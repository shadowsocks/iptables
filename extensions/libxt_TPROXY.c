/*
 * Shared library add-on to iptables to add TPROXY target support.
 *
 * Copyright (C) 2002-2008 BalaBit IT Ltd.
 */
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include <xtables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_TPROXY.h>

static const struct option tproxy_tg_opts[] = {
	{.name = "on-port",     .has_arg = true, .val = '1'},
	{.name = "on-ip",       .has_arg = true, .val = '2'},
	{.name = "tproxy-mark", .has_arg = true, .val = '3'},
	XT_GETOPT_TABLEEND,
};

enum {
	PARAM_ONPORT = 1 << 0,
	PARAM_ONIP = 1 << 1,
	PARAM_MARK = 1 << 2,
};

static void tproxy_tg_help(void)
{
	printf(
"TPROXY target options:\n"
"  --on-port port		    Redirect connection to port, or the original port if 0\n"
"  --on-ip ip			    Optionally redirect to the given IP\n"
"  --tproxy-mark value[/mask]	    Mark packets with the given value/mask\n\n");
}

static void parse_tproxy_lport(const char *s, uint16_t *portp)
{
	unsigned int lport;

	if (xtables_strtoui(s, NULL, &lport, 0, UINT16_MAX))
		*portp = htons(lport);
	else
		xtables_param_act(XTF_BAD_VALUE, "TPROXY", "--on-port", s);
}

static void parse_tproxy_laddr(const char *s, union nf_inet_addr *addrp,
			       unsigned int nfproto)
{
	struct in6_addr *laddr6 = NULL;
	struct in_addr *laddr4 = NULL;

	if (nfproto == NFPROTO_IPV6) {
		laddr6 = xtables_numeric_to_ip6addr(s);
		if (laddr6 == NULL)
			goto out;
		addrp->in6 = *laddr6;
	} else if (nfproto == NFPROTO_IPV4) {
		laddr4 = xtables_numeric_to_ipaddr(s);
		if (laddr4 == NULL)
			goto out;
		addrp->in = *laddr4;
	}
	return;
 out:
	xtables_param_act(XTF_BAD_VALUE, "TPROXY", "--on-ip", s);
}

static void parse_tproxy_mark(char *s, uint32_t *markp, uint32_t *maskp)
{
	unsigned int value, mask = UINT32_MAX;
	char *end;

	if (!xtables_strtoui(s, &end, &value, 0, UINT32_MAX))
		xtables_param_act(XTF_BAD_VALUE, "TPROXY", "--tproxy-mark", s);
	if (*end == '/')
		if (!xtables_strtoui(end + 1, &end, &mask, 0, UINT32_MAX))
			xtables_param_act(XTF_BAD_VALUE, "TPROXY", "--tproxy-mark", s);
	if (*end != '\0')
		xtables_param_act(XTF_BAD_VALUE, "TPROXY", "--tproxy-mark", s);

	*markp = value;
	*maskp = mask;
}

static int tproxy_tg_parse(int c, char **argv, int invert, unsigned int *flags,
			const void *entry, struct xt_entry_target **target)
{
	struct xt_tproxy_target_info *info = (void *)(*target)->data;

	switch (c) {
	case '1':
		xtables_param_act(XTF_ONLY_ONCE, "TPROXY", "--on-port", *flags & PARAM_ONPORT);
		xtables_param_act(XTF_NO_INVERT, "TPROXY", "--on-port", invert);
		parse_tproxy_lport(optarg, &info->lport);
		*flags |= PARAM_ONPORT;
		return 1;
	case '2':
		xtables_param_act(XTF_ONLY_ONCE, "TPROXY", "--on-ip", *flags & PARAM_ONIP);
		xtables_param_act(XTF_NO_INVERT, "TPROXY", "--on-ip", invert);
		parse_tproxy_laddr(optarg, (void *)&info->laddr, NFPROTO_IPV4);
		*flags |= PARAM_ONIP;
		return 1;
	case '3':
		xtables_param_act(XTF_ONLY_ONCE, "TPROXY", "--tproxy-mark", *flags & PARAM_MARK);
		xtables_param_act(XTF_NO_INVERT, "TPROXY", "--tproxy-mark", invert);
		parse_tproxy_mark(optarg, &info->mark_value, &info->mark_mask);
		*flags |= PARAM_MARK;
		return 1;
	}

	return 0;
}

static int
tproxy_tg_parse1(int c, char **argv, int invert, unsigned int *flags,
		 struct xt_tproxy_target_info_v1 *info, unsigned int nfproto)
{
	switch (c) {
	case '1':
		xtables_param_act(XTF_ONLY_ONCE, "TPROXY", "--on-port", *flags & PARAM_ONPORT);
		xtables_param_act(XTF_NO_INVERT, "TPROXY", "--on-port", invert);
		parse_tproxy_lport(optarg, &info->lport);
		*flags |= PARAM_ONPORT;
		return true;
	case '2':
		xtables_param_act(XTF_ONLY_ONCE, "TPROXY", "--on-ip", *flags & PARAM_ONIP);
		xtables_param_act(XTF_NO_INVERT, "TPROXY", "--on-ip", invert);
		parse_tproxy_laddr(optarg, (void *)&info->laddr, nfproto);
		*flags |= PARAM_ONIP;
		return true;
	case '3':
		xtables_param_act(XTF_ONLY_ONCE, "TPROXY", "--tproxy-mark", *flags & PARAM_MARK);
		xtables_param_act(XTF_NO_INVERT, "TPROXY", "--tproxy-mark", invert);
		parse_tproxy_mark(optarg, &info->mark_value, &info->mark_mask);
		*flags |= PARAM_MARK;
		return true;
	}
	return false;
}

static int
tproxy_tg_parse4(int c, char **argv, int invert, unsigned int *flags,
		 const void *entry, struct xt_entry_target **target)
{
	struct xt_tproxy_target_info_v1 *info = (void *)(*target)->data;
	return tproxy_tg_parse1(c, argv, invert, flags, info, NFPROTO_IPV4);
}

static int
tproxy_tg_parse6(int c, char **argv, int invert, unsigned int *flags,
		 const void *entry, struct xt_entry_target **target)
{
	struct xt_tproxy_target_info_v1 *info = (void *)(*target)->data;
	return tproxy_tg_parse1(c, argv, invert, flags, info, NFPROTO_IPV6);
}

static void tproxy_tg_check(unsigned int flags)
{
	if (!(flags & PARAM_ONPORT))
		xtables_error(PARAMETER_PROBLEM,
			   "TPROXY target: Parameter --on-port is required");
}

static void tproxy_tg_print(const void *ip, const struct xt_entry_target *target,
			 int numeric)
{
	const struct xt_tproxy_target_info *info = (const void *)target->data;
	printf(" TPROXY redirect %s:%u mark 0x%x/0x%x",
	       xtables_ipaddr_to_numeric((const struct in_addr *)&info->laddr),
	       ntohs(info->lport), (unsigned int)info->mark_value,
	       (unsigned int)info->mark_mask);
}

static void
tproxy_tg_print4(const void *ip, const struct xt_entry_target *target,
		 int numeric)
{
	const struct xt_tproxy_target_info_v1 *info =
		(const void *)target->data;

	printf(" TPROXY redirect %s:%u mark 0x%x/0x%x",
	       xtables_ipaddr_to_numeric(&info->laddr.in),
	       ntohs(info->lport), (unsigned int)info->mark_value,
	       (unsigned int)info->mark_mask);
}

static void
tproxy_tg_print6(const void *ip, const struct xt_entry_target *target,
		 int numeric)
{
	const struct xt_tproxy_target_info_v1 *info =
		(const void *)target->data;

	printf(" TPROXY redirect %s:%u mark 0x%x/0x%x",
	       xtables_ip6addr_to_numeric(&info->laddr.in6),
	       ntohs(info->lport), (unsigned int)info->mark_value,
	       (unsigned int)info->mark_mask);
}

static void tproxy_tg_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_tproxy_target_info *info = (const void *)target->data;

	printf(" --on-port %u", ntohs(info->lport));
	printf(" --on-ip %s",
	       xtables_ipaddr_to_numeric((const struct in_addr *)&info->laddr));
	printf(" --tproxy-mark 0x%x/0x%x",
	       (unsigned int)info->mark_value, (unsigned int)info->mark_mask);
}

static void
tproxy_tg_save4(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_tproxy_target_info_v1 *info;

	info = (const void *)target->data;
	printf(" --on-port %u", ntohs(info->lport));
	printf(" --on-ip %s", xtables_ipaddr_to_numeric(&info->laddr.in));
	printf(" --tproxy-mark 0x%x/0x%x",
	       (unsigned int)info->mark_value, (unsigned int)info->mark_mask);
}

static void
tproxy_tg_save6(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_tproxy_target_info_v1 *info;

	info = (const void *)target->data;
	printf(" --on-port %u", ntohs(info->lport));
	printf(" --on-ip %s", xtables_ip6addr_to_numeric(&info->laddr.in6));
	printf(" --tproxy-mark 0x%x/0x%x",
	       (unsigned int)info->mark_value, (unsigned int)info->mark_mask);
}

static struct xtables_target tproxy_tg_reg[] = {
	{
		.name          = "TPROXY",
		.revision      = 0,
		.family        = NFPROTO_IPV4,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(sizeof(struct xt_tproxy_target_info)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_tproxy_target_info)),
		.help          = tproxy_tg_help,
		.parse         = tproxy_tg_parse,
		.final_check   = tproxy_tg_check,
		.print         = tproxy_tg_print,
		.save          = tproxy_tg_save,
		.extra_opts    = tproxy_tg_opts,
	},
	{
		.name          = "TPROXY",
		.revision      = 1,
		.family        = NFPROTO_IPV4,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(sizeof(struct xt_tproxy_target_info_v1)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_tproxy_target_info_v1)),
		.help          = tproxy_tg_help,
		.parse         = tproxy_tg_parse4,
		.final_check   = tproxy_tg_check,
		.print         = tproxy_tg_print4,
		.save          = tproxy_tg_save4,
		.extra_opts    = tproxy_tg_opts,
	},
	{
		.name          = "TPROXY",
		.revision      = 1,
		.family        = NFPROTO_IPV6,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(sizeof(struct xt_tproxy_target_info_v1)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_tproxy_target_info_v1)),
		.help          = tproxy_tg_help,
		.parse         = tproxy_tg_parse6,
		.final_check   = tproxy_tg_check,
		.print         = tproxy_tg_print6,
		.save          = tproxy_tg_save6,
		.extra_opts    = tproxy_tg_opts,
	},
};

void _init(void)
{
	xtables_register_targets(tproxy_tg_reg, ARRAY_SIZE(tproxy_tg_reg));
}
