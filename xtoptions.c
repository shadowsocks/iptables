/*
 *	Argument parser
 *	Copyright © Jan Engelhardt, 2011
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "xtables.h"
#include "xshared.h"

#define XTOPT_MKPTR(cb) \
	((void *)((char *)(cb)->data + (cb)->entry->ptroff))

/**
 * Creates getopt options from the x6-style option map, and assigns each a
 * getopt id.
 */
struct option *
xtables_options_xfrm(struct option *orig_opts, struct option *oldopts,
		     const struct xt_option_entry *entry, unsigned int *offset)
{
	unsigned int num_orig, num_old = 0, num_new, i;
	struct option *merge, *mp;

	if (entry == NULL)
		return oldopts;
	for (num_orig = 0; orig_opts[num_orig].name != NULL; ++num_orig)
		;
	if (oldopts != NULL)
		for (num_old = 0; oldopts[num_old].name != NULL; ++num_old)
			;
	for (num_new = 0; entry[num_new].name != NULL; ++num_new)
		;

	/*
	 * Since @oldopts also has @orig_opts already (and does so at the
	 * start), skip these entries.
	 */
	oldopts += num_orig;
	num_old -= num_orig;

	merge = malloc(sizeof(*mp) * (num_orig + num_old + num_new + 1));
	if (merge == NULL)
		return NULL;

	/* Let the base options -[ADI...] have precedence over everything */
	memcpy(merge, orig_opts, sizeof(*mp) * num_orig);
	mp = merge + num_orig;

	/* Second, the new options */
	xt_params->option_offset += XT_OPTION_OFFSET_SCALE;
	*offset = xt_params->option_offset;

	for (i = 0; i < num_new; ++i, ++mp, ++entry) {
		mp->name         = entry->name;
		mp->has_arg      = entry->type != XTTYPE_NONE;
		mp->flag         = NULL;
		mp->val          = entry->id + *offset;
	}

	/* Third, the old options */
	memcpy(mp, oldopts, sizeof(*mp) * num_old);
	mp += num_old;
	xtables_free_opts(0);

	/* Clear trailing entry */
	memset(mp, 0, sizeof(*mp));
	return merge;
}

static void (*const xtopt_subparse[])(struct xt_option_call *) = {
	[XTTYPE_NONE]        = NULL,
};

static const size_t xtopt_psize[] = {
	[XTTYPE_NONE]        = 0,
};

/**
 * The master option parsing routine. May be used for the ".x6_parse"
 * function pointer in extensions if fully automatic parsing is desired.
 * It may be also called manually from a custom x6_parse function.
 */
void xtables_option_parse(struct xt_option_call *cb)
{
	const struct xt_option_entry *entry = cb->entry;
	unsigned int eflag = 1 << cb->entry->id;

	/*
	 * With {.id = P_FOO, .excl = P_FOO} we can have simple double-use
	 * prevention. Though it turned out that this is too much typing (most
	 * of the options are one-time use only), so now we also have
	 * %XTOPT_MULTI.
	 */
	if ((!(entry->flags & XTOPT_MULTI) || (entry->excl & eflag)) &&
	    cb->xflags & eflag)
		xt_params->exit_err(PARAMETER_PROBLEM,
			"%s: option \"--%s\" can only be used once.\n",
			cb->ext_name, cb->entry->name);
	if (cb->invert && !(entry->flags & XTOPT_INVERT))
		xt_params->exit_err(PARAMETER_PROBLEM,
			"%s: option \"--%s\" cannot be inverted.\n",
			cb->ext_name, entry->name);
	if (entry->type != XTTYPE_NONE && optarg == NULL)
		xt_params->exit_err(PARAMETER_PROBLEM,
			"%s: option \"--%s\" requires an argument.\n",
			cb->ext_name, entry->name);
	if (entry->type <= ARRAY_SIZE(xtopt_subparse) &&
	    xtopt_subparse[entry->type] != NULL)
		xtopt_subparse[entry->type](cb);
	/* Exclusion with other flags tested later in finalize. */
	cb->xflags |= 1 << entry->id;
}

/**
 * Verifies that an extension's option map descriptor is valid, and ought to
 * be called right after the extension has been loaded, and before option
 * merging/xfrm.
 */
void xtables_option_metavalidate(const char *name,
				 const struct xt_option_entry *entry)
{
	for (; entry->name != NULL; ++entry) {
		if (entry->id >= CHAR_BIT * sizeof(unsigned int) ||
		    entry->id >= XT_OPTION_OFFSET_SCALE)
			xt_params->exit_err(OTHER_PROBLEM,
				"Extension %s uses invalid ID %u\n",
				name, entry->id);
		if (!(entry->flags & XTOPT_PUT))
			continue;
		if (entry->type >= ARRAY_SIZE(xtopt_psize))
			xt_params->exit_err(OTHER_PROBLEM,
				"%s: entry type of option \"--%s\" cannot be "
				"combined with XTOPT_PUT\n",
				name, entry->name);
		if (xtopt_psize[entry->type] != entry->size)
			xt_params->exit_err(OTHER_PROBLEM,
				"%s: option \"--%s\" points to a memory block "
				"of wrong size (expected %zu, got %zu)\n",
				name, entry->name,
				xtopt_psize[entry->type], entry->size);
	}
}

/**
 * Find an option entry by its id.
 */
static const struct xt_option_entry *
xtables_option_lookup(const struct xt_option_entry *entry, unsigned int id)
{
	for (; entry->name != NULL; ++entry)
		if (entry->id == id)
			return entry;
	return NULL;
}

/**
 * @c:		getopt id (i.e. with offset)
 * @fw:		struct ipt_entry or ip6t_entry
 *
 * Dispatch arguments to the appropriate parse function, based upon the
 * extension's choice of API.
 */
void xtables_option_tpcall(unsigned int c, char **argv, bool invert,
			   struct xtables_target *t, void *fw)
{
	struct xt_option_call cb;

	if (t->x6_parse == NULL) {
		if (t->parse != NULL)
			t->parse(c - t->option_offset, argv, invert,
				 &t->tflags, fw, &t->t);
		return;
	}

	c -= t->option_offset;
	cb.entry = xtables_option_lookup(t->x6_options, c);
	if (cb.entry == NULL)
		xtables_error(OTHER_PROBLEM,
			"Extension does not know id %u\n", c);
	cb.arg      = optarg;
	cb.invert   = invert;
	cb.ext_name = t->name;
	cb.data     = t->t->data;
	cb.xflags   = t->tflags;
	t->x6_parse(&cb);
	t->tflags = cb.xflags;
}

/**
 * @c:		getopt id (i.e. with offset)
 * @fw:		struct ipt_entry or ip6t_entry
 *
 * Dispatch arguments to the appropriate parse function, based upon the
 * extension's choice of API.
 */
void xtables_option_mpcall(unsigned int c, char **argv, bool invert,
			   struct xtables_match *m, void *fw)
{
	struct xt_option_call cb;

	if (m->x6_parse == NULL) {
		if (m->parse != NULL)
			m->parse(c - m->option_offset, argv, invert,
				 &m->mflags, fw, &m->m);
		return;
	}

	c -= m->option_offset;
	cb.entry = xtables_option_lookup(m->x6_options, c);
	if (cb.entry == NULL)
		xtables_error(OTHER_PROBLEM,
			"Extension does not know id %u\n", c);
	cb.arg      = optarg;
	cb.invert   = invert;
	cb.ext_name = m->name;
	cb.data     = m->m->data;
	cb.xflags   = m->mflags;
	m->x6_parse(&cb);
	m->mflags = cb.xflags;
}

/**
 * @name:	name of extension
 * @entry:	current option (from all ext's entries) being validated
 * @xflags:	flags the extension has collected
 * @i:		conflicting option (id) to test for
 */
static void
xtables_option_fcheck2(const char *name, const struct xt_option_entry *entry,
		       const struct xt_option_entry *other,
		       unsigned int xflags)
{
	unsigned int ef = 1 << entry->id, of = 1 << other->id;

	if (entry->also & of && !(xflags & of))
		xt_params->exit_err(PARAMETER_PROBLEM,
			"%s: option \"--%s\" also requires \"--%s\".\n",
			name, entry->name, other->name);

	if (!(entry->excl & of))
		/* Use of entry does not collide with other option, good. */
		return;
	if ((xflags & (ef | of)) != (ef | of))
		/* Conflicting options were not used. */
		return;

	xt_params->exit_err(PARAMETER_PROBLEM,
		"%s: option \"--%s\" cannot be used together with \"--%s\".\n",
		name, entry->name, other->name);
}

/**
 * @name:	name of extension
 * @xflags:	accumulated flags
 * @entry:	extension's option table
 *
 * Check that all option constraints have been met. This effectively replaces
 * ->final_check of the older API.
 */
void xtables_options_fcheck(const char *name, unsigned int xflags,
			    const struct xt_option_entry *table)
{
	const struct xt_option_entry *entry, *other;
	unsigned int i;

	for (entry = table; entry->name != NULL; ++entry) {
		if (entry->flags & XTOPT_MAND &&
		    !(xflags & (1 << entry->id)))
			xt_params->exit_err(PARAMETER_PROBLEM,
				"%s: option \"--%s\" must be specified\n",
				name, entry->name);

		for (i = 0; i < CHAR_BIT * sizeof(entry->id); ++i) {
			if (entry->id == i)
				/*
				 * Avoid conflict with self. Multi-use check
				 * was done earlier in xtables_option_parse.
				 */
				continue;
			other = xtables_option_lookup(table, i);
			if (other == NULL)
				continue;
			xtables_option_fcheck2(name, entry, other, xflags);
		}
	}
}
