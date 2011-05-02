/*
 *	Argument parser
 *	Copyright © Jan Engelhardt, 2011
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include "xtables.h"
#include "xshared.h"
#ifndef IPTOS_NORMALSVC
#	define IPTOS_NORMALSVC 0
#endif

#define XTOPT_MKPTR(cb) \
	((void *)((char *)(cb)->data + (cb)->entry->ptroff))

/**
 * Simple key-value pairs for syslog levels
 */
struct syslog_level {
	char name[8];
	uint8_t level;
};

struct tos_value_mask {
	uint8_t value, mask;
};

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
	else if (entry->type == XTTYPE_UINT16)
		lmax = UINT16_MAX;
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
	} else if (entry->type == XTTYPE_UINT16) {
		cb->val.u16 = value;
		if (entry->flags & XTOPT_PUT)
			*(uint16_t *)XTOPT_MKPTR(cb) = cb->val.u16;
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
	size_t esize = sizeof(uint32_t);
	char *put = XTOPT_MKPTR(cb);
	unsigned int maxiter, value;
	char *end = "";
	char sep = ':';

	if (entry->type == XTTYPE_UINT8RC)
		esize = sizeof(uint8_t);
	else if (entry->type == XTTYPE_UINT16RC)
		esize = sizeof(uint16_t);
	else if (entry->type == XTTYPE_UINT64RC)
		esize = sizeof(uint64_t);
	maxiter = entry->size / esize;
	if (maxiter == 0)
		maxiter = 2; /* ARRAY_SIZE(cb->val.uXX_range) */
	if (entry->size % esize != 0)
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
		if (cb->nvals < ARRAY_SIZE(cb->val.u32_range)) {
			if (entry->type == XTTYPE_UINT8RC)
				cb->val.u8_range[cb->nvals] = value;
			else if (entry->type == XTTYPE_UINT16RC)
				cb->val.u16_range[cb->nvals] = value;
			else if (entry->type == XTTYPE_UINT32RC)
				cb->val.u32_range[cb->nvals] = value;
			else if (entry->type == XTTYPE_UINT64RC)
				cb->val.u64_range[cb->nvals] = value;
		}
		++cb->nvals;
		if (entry->flags & XTOPT_PUT) {
			if (entry->type == XTTYPE_UINT8RC)
				*(uint8_t *)put = value;
			else if (entry->type == XTTYPE_UINT16RC)
				*(uint16_t *)put = value;
			else if (entry->type == XTTYPE_UINT32RC)
				*(uint32_t *)put = value;
			else if (entry->type == XTTYPE_UINT64RC)
				*(uint64_t *)put = value;
			put += esize;
		}
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

static const struct tos_symbol_info {
	unsigned char value;
	const char *name;
} tos_symbol_names[] = {
	{IPTOS_LOWDELAY,    "Minimize-Delay"},
	{IPTOS_THROUGHPUT,  "Maximize-Throughput"},
	{IPTOS_RELIABILITY, "Maximize-Reliability"},
	{IPTOS_MINCOST,     "Minimize-Cost"},
	{IPTOS_NORMALSVC,   "Normal-Service"},
	{},
};

/*
 * tos_parse_numeric - parse a string like "15/255"
 *
 * @str:	input string
 * @tvm:	(value/mask) tuple
 * @max:	maximum allowed value (must be pow(2,some_int)-1)
 */
static bool tos_parse_numeric(const char *str, struct xt_option_call *cb,
                              unsigned int max)
{
	unsigned int value;
	char *end;

	xtables_strtoui(str, &end, &value, 0, max);
	cb->val.tos_value = value;
	cb->val.tos_mask  = max;

	if (*end == '/') {
		const char *p = end + 1;

		if (!xtables_strtoui(p, &end, &value, 0, max))
			xtables_error(PARAMETER_PROBLEM, "Illegal value: \"%s\"",
			           str);
		cb->val.tos_mask = value;
	}

	if (*end != '\0')
		xtables_error(PARAMETER_PROBLEM, "Illegal value: \"%s\"", str);
	return true;
}

/**
 * @str:	input string
 * @tvm:	(value/mask) tuple
 * @def_mask:	mask to force when a symbolic name is used
 */
static void xtopt_parse_tosmask(struct xt_option_call *cb)
{
	const struct tos_symbol_info *symbol;
	char *tmp;

	if (xtables_strtoui(cb->arg, &tmp, NULL, 0, UINT8_MAX)) {
		tos_parse_numeric(cb->arg, cb, UINT8_MAX);
		return;
	}
	/*
	 * This is our way we deal with different defaults
	 * for different revisions.
	 */
	cb->val.tos_mask = cb->entry->max;
	for (symbol = tos_symbol_names; symbol->name != NULL; ++symbol)
		if (strcasecmp(cb->arg, symbol->name) == 0) {
			cb->val.tos_value = symbol->value;
			return;
		}

	xtables_error(PARAMETER_PROBLEM, "Symbolic name \"%s\" is unknown",
		      cb->arg);
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

static int xtopt_sysloglvl_compare(const void *a, const void *b)
{
	const char *name = a;
	const struct syslog_level *entry = b;

	return strcmp(name, entry->name);
}

static void xtopt_parse_sysloglevel(struct xt_option_call *cb)
{
	static const struct syslog_level log_names[] = { /* must be sorted */
		{"alert",   LOG_ALERT},
		{"crit",    LOG_CRIT},
		{"debug",   LOG_DEBUG},
		{"emerg",   LOG_EMERG},
		{"error",   LOG_ERR}, /* deprecated */
		{"info",    LOG_INFO},
		{"notice",  LOG_NOTICE},
		{"panic",   LOG_EMERG}, /* deprecated */
		{"warning", LOG_WARNING},
	};
	const struct syslog_level *e;
	unsigned int num = 0;

	if (!xtables_strtoui(cb->arg, NULL, &num, 0, 7)) {
		e = bsearch(cb->arg, log_names, ARRAY_SIZE(log_names),
			    sizeof(*log_names), xtopt_sysloglvl_compare);
		if (e == NULL)
			xt_params->exit_err(PARAMETER_PROBLEM,
				"log level \"%s\" unknown\n", cb->arg);
		num = e->level;
	}
	cb->val.syslog_level = num;
	if (cb->entry->flags & XTOPT_PUT)
		*(uint8_t *)XTOPT_MKPTR(cb) = num;
}

static void *xtables_sa_host(const void *sa, unsigned int afproto)
{
	if (afproto == AF_INET6)
		return &((struct sockaddr_in6 *)sa)->sin6_addr;
	else if (afproto == AF_INET)
		return &((struct sockaddr_in *)sa)->sin_addr;
	return (void *)sa;
}

static socklen_t xtables_sa_hostlen(unsigned int afproto)
{
	if (afproto == AF_INET6)
		return sizeof(struct in6_addr);
	else if (afproto == AF_INET)
		return sizeof(struct in_addr);
	return 0;
}

/**
 * Accepts: a hostname (DNS), or a single inetaddr.
 */
static void xtopt_parse_onehost(struct xt_option_call *cb)
{
	struct addrinfo hints = {.ai_family = afinfo->family};
	unsigned int adcount = 0;
	struct addrinfo *res, *p;
	int ret;

	ret = getaddrinfo(cb->arg, NULL, &hints, &res);
	if (ret < 0)
		xt_params->exit_err(PARAMETER_PROBLEM,
			"getaddrinfo: %s\n", gai_strerror(ret));

	for (p = res; p != NULL; p = p->ai_next) {
		if (adcount == 0) {
			memset(&cb->val.inetaddr, 0, sizeof(cb->val.inetaddr));
			memcpy(&cb->val.inetaddr,
			       xtables_sa_host(p->ai_addr, p->ai_family),
			       xtables_sa_hostlen(p->ai_family));
			++adcount;
			continue;
		}
		if (memcmp(&cb->val.inetaddr,
		    xtables_sa_host(p->ai_addr, p->ai_family),
		    xtables_sa_hostlen(p->ai_family)) != 0)
			xt_params->exit_err(PARAMETER_PROBLEM,
				"%s resolves to more than one address\n",
				cb->arg);
	}

	freeaddrinfo(res);
	if (cb->entry->flags & XTOPT_PUT)
		/* Validation in xtables_option_metavalidate */
		memcpy(XTOPT_MKPTR(cb), &cb->val.inetaddr,
		       sizeof(cb->val.inetaddr));
}

/**
 * @name:	port name, or number as a string (e.g. "http" or "80")
 *
 * Resolve a port name to a number. Returns the port number in integral
 * form on success, or <0 on error. (errno will not be set.)
 */
static int xtables_getportbyname(const char *name)
{
	struct addrinfo *res = NULL, *p;
	int ret;

	ret = getaddrinfo(NULL, name, NULL, &res);
	if (ret < 0)
		return -1;
	ret = -1;
	for (p = res; p != NULL; p = p->ai_next) {
		if (p->ai_family == AF_INET6) {
			ret = ((struct sockaddr_in6 *)p->ai_addr)->sin6_port;
			break;
		} else if (p->ai_family == AF_INET) {
			ret = ((struct sockaddr_in *)p->ai_addr)->sin_port;
			break;
		}
	}
	freeaddrinfo(res);
	if (ret < 0)
		return ret;
	return ntohs(ret);
}

/**
 * Validate and parse a port specification and put the result into @cb.
 */
static void xtopt_parse_port(struct xt_option_call *cb)
{
	int ret;

	ret = xtables_getportbyname(cb->arg);
	if (ret < 0)
		xt_params->exit_err(PARAMETER_PROBLEM,
			"Port \"%s\" does not resolve to anything.\n",
			cb->arg);
	cb->val.port = ret;
	if (cb->entry->type == XTTYPE_PORT_NE)
		cb->val.port = htons(cb->val.port);
	if (cb->entry->flags & XTOPT_PUT)
		*(uint16_t *)XTOPT_MKPTR(cb) = cb->val.port;
}

static void xtopt_parse_mport(struct xt_option_call *cb)
{
	static const size_t esize = sizeof(uint16_t);
	const struct xt_option_entry *entry = cb->entry;
	char *lo_arg, *wp_arg, *arg;
	unsigned int maxiter;
	int value;

	wp_arg = lo_arg = strdup(cb->arg);
	if (lo_arg == NULL)
		xt_params->exit_err(RESOURCE_PROBLEM, "strdup");

	maxiter = entry->size / esize;
	if (maxiter == 0)
		maxiter = 2; /* ARRAY_SIZE(cb->val.port_range) */
	if (entry->size % esize != 0)
		xt_params->exit_err(OTHER_PROBLEM, "%s: memory block does "
			"not have proper size\n", __func__);

	cb->val.port_range[0] = 0;
	cb->val.port_range[1] = UINT16_MAX;
	cb->nvals = 0;

	while ((arg = strsep(&wp_arg, ":")) != NULL) {
		if (cb->nvals == maxiter)
			xt_params->exit_err(PARAMETER_PROBLEM, "%s: Too many "
				"components for option \"--%s\" (max: %u)\n",
				cb->ext_name, entry->name, maxiter);
		if (*arg == '\0') {
			++cb->nvals;
			continue;
		}

		value = xtables_getportbyname(arg);
		if (value < 0)
			xt_params->exit_err(PARAMETER_PROBLEM,
				"Port \"%s\" does not resolve to "
				"anything.\n", arg);
		if (entry->type == XTTYPE_PORTRC_NE)
			value = htons(value);
		if (cb->nvals < ARRAY_SIZE(cb->val.port_range))
			cb->val.port_range[cb->nvals] = value;
		++cb->nvals;
	}

	if (cb->nvals == 1) {
		cb->val.port_range[1] = cb->val.port_range[0];
		++cb->nvals;
	}
	if (entry->flags & XTOPT_PUT)
		memcpy(XTOPT_MKPTR(cb), cb->val.port_range, sizeof(uint16_t) *
		       (cb->nvals <= maxiter ? cb->nvals : maxiter));
	free(lo_arg);
}

static void (*const xtopt_subparse[])(struct xt_option_call *) = {
	[XTTYPE_UINT8]       = xtopt_parse_int,
	[XTTYPE_UINT16]      = xtopt_parse_int,
	[XTTYPE_UINT32]      = xtopt_parse_int,
	[XTTYPE_UINT64]      = xtopt_parse_int,
	[XTTYPE_UINT8RC]     = xtopt_parse_mint,
	[XTTYPE_UINT16RC]    = xtopt_parse_mint,
	[XTTYPE_UINT32RC]    = xtopt_parse_mint,
	[XTTYPE_UINT64RC]    = xtopt_parse_mint,
	[XTTYPE_STRING]      = xtopt_parse_string,
	[XTTYPE_TOSMASK]     = xtopt_parse_tosmask,
	[XTTYPE_MARKMASK32]  = xtopt_parse_markmask,
	[XTTYPE_SYSLOGLEVEL] = xtopt_parse_sysloglevel,
	[XTTYPE_ONEHOST]     = xtopt_parse_onehost,
	[XTTYPE_PORT]        = xtopt_parse_port,
	[XTTYPE_PORT_NE]     = xtopt_parse_port,
	[XTTYPE_PORTRC]      = xtopt_parse_mport,
	[XTTYPE_PORTRC_NE]   = xtopt_parse_mport,
};

static const size_t xtopt_psize[] = {
	[XTTYPE_UINT8]       = sizeof(uint8_t),
	[XTTYPE_UINT16]      = sizeof(uint16_t),
	[XTTYPE_UINT32]      = sizeof(uint32_t),
	[XTTYPE_UINT64]      = sizeof(uint64_t),
	[XTTYPE_UINT8RC]     = sizeof(uint8_t[2]),
	[XTTYPE_UINT16RC]    = sizeof(uint16_t[2]),
	[XTTYPE_UINT32RC]    = sizeof(uint32_t[2]),
	[XTTYPE_UINT64RC]    = sizeof(uint64_t[2]),
	[XTTYPE_STRING]      = -1,
	[XTTYPE_SYSLOGLEVEL] = sizeof(uint8_t),
	[XTTYPE_ONEHOST]     = sizeof(union nf_inet_addr),
	[XTTYPE_PORT]        = sizeof(uint16_t),
	[XTTYPE_PORT_NE]     = sizeof(uint16_t),
	[XTTYPE_PORTRC]      = sizeof(uint16_t[2]),
	[XTTYPE_PORTRC_NE]   = sizeof(uint16_t[2]),
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
	cb.target   = &t->t;
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
	cb.match    = &m->m;
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

struct xtables_lmap *xtables_lmap_init(const char *file)
{
	struct xtables_lmap *lmap_head = NULL, *lmap_prev = NULL, *lmap_this;
	char buf[512];
	FILE *fp;
	char *cur, *nxt;
	int id;

	fp = fopen(file, "re");
	if (fp == NULL)
		return NULL;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		cur = buf;
		while (isspace(*cur))
			++cur;
		if (*cur == '#' || *cur == '\n' || *cur == '\0')
			continue;

		/* iproute2 allows hex and dec format */
		errno = 0;
		id = strtoul(cur, &nxt, strncmp(cur, "0x", 2) == 0 ? 16 : 10);
		if (nxt == cur || errno != 0)
			continue;

		/* same boundaries as in iproute2 */
		if (id < 0 || id > 255)
			continue;
		cur = nxt;

		if (!isspace(*cur))
			continue;
		while (isspace(*cur))
			++cur;
		if (*cur == '#' || *cur == '\n' || *cur == '\0')
			continue;
		nxt = cur;
		while (*nxt != '\0' && !isspace(*nxt))
			++nxt;
		if (nxt == cur)
			continue;
		*nxt = '\0';

		/* found valid data */
		lmap_this = malloc(sizeof(*lmap_this));
		if (lmap_this == NULL) {
			perror("malloc");
			goto out;
		}
		lmap_this->id   = id;
		lmap_this->name = strdup(cur);
		if (lmap_this->name == NULL) {
			free(lmap_this);
			goto out;
		}
		lmap_this->next = NULL;

		if (lmap_prev != NULL)
			lmap_prev->next = lmap_this;
		else
			lmap_head = lmap_this;
		lmap_prev = lmap_this;
	}

	fclose(fp);
	return lmap_head;
 out:
	xtables_lmap_free(lmap_head);
	return NULL;
}

void xtables_lmap_free(struct xtables_lmap *head)
{
	struct xtables_lmap *next;

	for (; head != NULL; head = next) {
		next = head->next;
		free(head->name);
		free(head);
	}
}

int xtables_lmap_name2id(const struct xtables_lmap *head, const char *name)
{
	for (; head != NULL; head = head->next)
		if (strcmp(head->name, name) == 0)
			return head->id;
	return -1;
}

const char *xtables_lmap_id2name(const struct xtables_lmap *head, int id)
{
	for (; head != NULL; head = head->next)
		if (head->id == id)
			return head->name;
	return NULL;
}
