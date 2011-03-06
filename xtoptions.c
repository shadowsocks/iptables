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

/**
 * Require a simple integer.
 */
static void xtopt_parse_int(struct xt_option_call *cb)
{
	const struct xt_option_entry *entry = cb->entry;
	unsigned long long lmin = 0, lmax = UINT32_MAX;
	unsigned int value;

	if (entry->type == XTTYPE_UINT8)
		lmax = UINT8_MAX;
	else if (entry->type == XTTYPE_UINT64)
		lmax = UINT64_MAX;
	if (cb->entry->min != 0)
		lmin = cb->entry->min;
	if (cb->entry->max != 0)
		lmax = cb->entry->max;

	if (!xtables_strtoui(cb->arg, NULL, &value, lmin, lmax))
		xt_params->exit_err(PARAMETER_PROBLEM,
			"%s: bad value for option \"--%s\", "
			"or out of range (%llu-%llu).\n",
			cb->ext_name, entry->name, lmin, lmax);

	if (entry->type == XTTYPE_UINT8) {
		cb->val.u8 = value;
		if (entry->flags & XTOPT_PUT)
			*(uint8_t *)XTOPT_MKPTR(cb) = cb->val.u8;
	} else if (entry->type == XTTYPE_UINT32) {
		cb->val.u32 = value;
		if (entry->flags & XTOPT_PUT)
			*(uint32_t *)XTOPT_MKPTR(cb) = cb->val.u32;
	} else if (entry->type == XTTYPE_UINT64) {
		cb->val.u64 = value;
		if (entry->flags & XTOPT_PUT)
			*(uint64_t *)XTOPT_MKPTR(cb) = cb->val.u64;
	}
}

/**
 * Multiple integer parse routine.
 *
 * This function is capable of parsing any number of fields. Only the first
 * two values from the string will be put into @cb however (and as such,
 * @cb->val.uXX_range is just that large) to cater for the few extensions that
 * do not have a range[2] field, but {min, max}, and which cannot use
 * XTOPT_POINTER.
 */
static void xtopt_parse_mint(struct xt_option_call *cb)
{
	const struct xt_option_entry *entry = cb->entry;
	const char *arg = cb->arg;
	uint32_t *put = XTOPT_MKPTR(cb);
	unsigned int maxiter, value;
	char *end = "";
	char sep = ':';

	maxiter = entry->size / sizeof(uint32_t);
	if (maxiter == 0)
		maxiter = 2; /* ARRAY_SIZE(cb->val.uXX_range) */
	if (entry->size % sizeof(uint32_t) != 0)
		xt_params->exit_err(OTHER_PROBLEM, "%s: memory block does "
			"not have proper size\n", __func__);

	cb->nvals = 0;
	for (arg = cb->arg; ; arg = end + 1) {
		if (cb->nvals == maxiter)
			xt_params->exit_err(PARAMETER_PROBLEM, "%s: Too many "
				"components for option \"--%s\" (max: %u)\n",
				cb->ext_name, entry->name, maxiter);
		if (!xtables_strtoui(arg, &end, &value, 0, UINT32_MAX))
			xt_params->exit_err(PARAMETER_PROBLEM,
				"%s: bad value for option \"--%s\", "
				"or out of range (0-%u).\n",
				cb->ext_name, entry->name, UINT32_MAX);
		if (*end != '\0' && *end != sep)
			xt_params->exit_err(PARAMETER_PROBLEM,
				"%s: Argument to \"--%s\" has unexpected "
				"characters.\n", cb->ext_name, entry->name);
		++cb->nvals;
		if (cb->nvals < ARRAY_SIZE(cb->val.u32_range))
			cb->val.u32_range[cb->nvals] = value;
		if (entry->flags & XTOPT_PUT)
			*put++ = value;
		if (*end == '\0')
			break;
	}
}

static void xtopt_parse_string(struct xt_option_call *cb)
{
	const struct xt_option_entry *entry = cb->entry;
	size_t z = strlen(cb->arg);
	char *p;

	if (entry->min != 0 && z < entry->min)
		xt_params->exit_err(PARAMETER_PROBLEM,
			"Argument must have a minimum length of "
			"%u characters\n", entry->min);
	if (entry->max != 0 && z > entry->max)
		xt_params->exit_err(PARAMETER_PROBLEM,
			"Argument must have a maximum length of "
			"%u characters\n", entry->max);
	if (!(entry->flags & XTOPT_PUT))
		return;
	if (z >= entry->size)
		z = entry->size - 1;
	p = XTOPT_MKPTR(cb);
	strncpy(p, cb->arg, z);
	p[z] = '\0';
}

/**
 * Validate the input for being conformant to "mark[/mask]".
 */
static void xtopt_parse_markmask(struct xt_option_call *cb)
{
	unsigned int mark = 0, mask = ~0U;
	char *end;

	if (!xtables_strtoui(cb->arg, &end, &mark, 0, UINT32_MAX))
		xt_params->exit_err(PARAMETER_PROBLEM,
			"%s: bad mark value for option \"--%s\", "
			"or out of range.\n",
			cb->ext_name, cb->entry->name);
	if (*end == '/' &&
	    !xtables_strtoui(end + 1, &end, &mask, 0, UINT32_MAX))
		xt_params->exit_err(PARAMETER_PROBLEM,
			"%s: bad mask value for option \"--%s\", "
			"or out of range.\n",
			cb->ext_name, cb->entry->name);
	if (*end != '\0')
		xt_params->exit_err(PARAMETER_PROBLEM,
			"%s: trailing garbage after value "
			"for option \"--%s\".\n",
			cb->ext_name, cb->entry->name);
	cb->val.mark = mark;
	cb->val.mask = mask;
}

static void (*const xtopt_subparse[])(struct xt_option_call *) = {
	[XTTYPE_UINT8]       = xtopt_parse_int,
	[XTTYPE_UINT32]      = xtopt_parse_int,
	[XTTYPE_UINT64]      = xtopt_parse_int,
	[XTTYPE_UINT32RC]    = xtopt_parse_mint,
	[XTTYPE_STRING]      = xtopt_parse_string,
	[XTTYPE_MARKMASK32]  = xtopt_parse_markmask,
};

static const size_t xtopt_psize[] = {
	[XTTYPE_UINT8]       = sizeof(uint8_t),
	[XTTYPE_UINT32]      = sizeof(uint32_t),
	[XTTYPE_UINT64]      = sizeof(uint64_t),
	[XTTYPE_UINT32RC]    = sizeof(uint32_t[2]),
	[XTTYPE_STRING]      = -1,
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
		if (xtopt_psize[entry->type] != -1 &&
		    xtopt_psize[entry->type] != entry->size)
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

/**
 * Dispatch arguments to the appropriate final_check function, based upon the
 * extension's choice of API.
 */
void xtables_option_tfcall(struct xtables_target *t)
{
	if (t->x6_fcheck != NULL) {
		struct xt_fcheck_call cb;

		cb.ext_name = t->name;
		cb.data     = t->t->data;
		cb.xflags   = t->tflags;
		t->x6_fcheck(&cb);
	} else if (t->final_check != NULL) {
		t->final_check(t->tflags);
	}
	if (t->x6_options != NULL)
		xtables_options_fcheck(t->name, t->tflags, t->x6_options);
}

/**
 * Dispatch arguments to the appropriate final_check function, based upon the
 * extension's choice of API.
 */
void xtables_option_mfcall(struct xtables_match *m)
{
	if (m->x6_fcheck != NULL) {
		struct xt_fcheck_call cb;

		cb.ext_name = m->name;
		cb.data     = m->m->data;
		cb.xflags   = m->mflags;
		m->x6_fcheck(&cb);
	} else if (m->final_check != NULL) {
		m->final_check(m->mflags);
	}
	if (m->x6_options != NULL)
		xtables_options_fcheck(m->name, m->mflags, m->x6_options);
}
