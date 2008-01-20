/* Shared library add-on to iptables to add IP range matching support. */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <xtables.h>
#include <linux/netfilter.h>
#include <linux/netfilter/xt_iprange.h>
#include <linux/netfilter_ipv4/ipt_iprange.h>

enum {
	F_SRCIP = 1 << 0,
	F_DSTIP = 1 << 1,
};

static void iprange_mt_help(void)
{
	printf(
"iprange match options:\n"
"[!] --src-range ip-ip        Match source IP in the specified range\n"
"[!] --dst-range ip-ip        Match destination IP in the specified range\n"
"\n");
}

static const struct option iprange_mt_opts[] = {
	{.name = "src-range", .has_arg = true, .val = '1'},
	{.name = "dst-range", .has_arg = true, .val = '2'},
	{},
};

static void
parse_iprange(char *arg, struct ipt_iprange *range)
{
	char *dash;
	const struct in_addr *ip;

	dash = strchr(arg, '-');
	if (dash != NULL)
		*dash = '\0';

	ip = numeric_to_ipaddr(arg);
	if (ip != NULL)
		exit_error(PARAMETER_PROBLEM, "iprange match: Bad IP address `%s'\n",
			   arg);
	range->min_ip = ip->s_addr;

	if (dash != NULL) {
		ip = numeric_to_ipaddr(dash+1);
		if (ip != NULL)
			exit_error(PARAMETER_PROBLEM, "iprange match: Bad IP address `%s'\n",
				   dash+1);
		range->max_ip = ip->s_addr;
	} else {
		range->max_ip = range->min_ip;
	}
}

static int iprange_parse(int c, char **argv, int invert, unsigned int *flags,
                         const void *entry, struct xt_entry_match **match)
{
	struct ipt_iprange_info *info = (struct ipt_iprange_info *)(*match)->data;

	switch (c) {
	case '1':
		if (*flags & IPRANGE_SRC)
			exit_error(PARAMETER_PROBLEM,
				   "iprange match: Only use --src-range ONCE!");
		*flags |= IPRANGE_SRC;

		info->flags |= IPRANGE_SRC;
		check_inverse(optarg, &invert, &optind, 0);
		if (invert)
			info->flags |= IPRANGE_SRC_INV;
		parse_iprange(optarg, &info->src);

		break;

	case '2':
		if (*flags & IPRANGE_DST)
			exit_error(PARAMETER_PROBLEM,
				   "iprange match: Only use --dst-range ONCE!");
		*flags |= IPRANGE_DST;

		info->flags |= IPRANGE_DST;
		check_inverse(optarg, &invert, &optind, 0);
		if (invert)
			info->flags |= IPRANGE_DST_INV;

		parse_iprange(optarg, &info->dst);

		break;

	default:
		return 0;
	}
	return 1;
}

static int
iprange_mt4_parse(int c, char **argv, int invert, unsigned int *flags,
                  const void *entry, struct xt_entry_match **match)
{
	struct xt_iprange_mtinfo *info = (void *)(*match)->data;
	const struct in_addr *ia;
	char *end;

	switch (c) {
	case '1': /* --src-ip */
		end = strchr(optarg, '-');
		if (end == NULL)
			param_act(P_BAD_VALUE, "iprange", "--src-ip", optarg);
		*end = '\0';
		ia = numeric_to_ipaddr(optarg);
		if (ia == NULL)
			param_act(P_BAD_VALUE, "iprange", "--src-ip", optarg);
		memcpy(&info->src_min.in, ia, sizeof(*ia));
		ia = numeric_to_ipaddr(end+1);
		if (ia == NULL)
			param_act(P_BAD_VALUE, "iprange", "--src-ip", end + 1);
		memcpy(&info->src_max.in, ia, sizeof(*ia));
		*flags |= F_SRCIP;
		return true;

	case '2': /* --dst-ip */
		end = strchr(optarg, '-');
		if (end == NULL)
			param_act(P_BAD_VALUE, "iprange", "--dst-ip", optarg);
		*end = '\0';
		ia = numeric_to_ipaddr(optarg);
		if (ia == NULL)
			param_act(P_BAD_VALUE, "iprange", "--dst-ip", optarg);
		memcpy(&info->dst_min.in, ia, sizeof(*ia));
		ia = numeric_to_ipaddr(end + 1);
		if (ia == NULL)
			param_act(P_BAD_VALUE, "iprange", "--dst-ip", end + 1);
		memcpy(&info->dst_max.in, ia, sizeof(*ia));
		*flags |= F_DSTIP;
		return true;
	}
	return false;
}

static int
iprange_mt6_parse(int c, char **argv, int invert, unsigned int *flags,
                  const void *entry, struct xt_entry_match **match)
{
	struct xt_iprange_mtinfo *info = (void *)(*match)->data;
	const struct in6_addr *ia;
	char *end;

	switch (c) {
	case '1': /* --src-ip */
		end = strchr(optarg, '-');
		if (end == NULL)
			param_act(P_BAD_VALUE, "iprange", "--src-ip", optarg);
		*end = '\0';
		ia = numeric_to_ip6addr(optarg);
		if (ia == NULL)
			param_act(P_BAD_VALUE, "iprange", "--src-ip", optarg);
		memcpy(&info->src_min.in, ia, sizeof(*ia));
		ia = numeric_to_ip6addr(end+1);
		if (ia == NULL)
			param_act(P_BAD_VALUE, "iprange", "--src-ip", end + 1);
		memcpy(&info->src_max.in, ia, sizeof(*ia));
		info->flags |= IPRANGE_SRC;
		if (invert)
			info->flags |= IPRANGE_SRC_INV;
		*flags |= F_SRCIP;
		return true;

	case '2': /* --dst-ip */
		end = strchr(optarg, '-');
		if (end == NULL)
			param_act(P_BAD_VALUE, "iprange", "--dst-ip", optarg);
		*end = '\0';
		ia = numeric_to_ip6addr(optarg);
		if (ia == NULL)
			param_act(P_BAD_VALUE, "iprange", "--dst-ip", optarg);
		memcpy(&info->dst_min.in, ia, sizeof(*ia));
		ia = numeric_to_ip6addr(end + 1);
		if (ia == NULL)
			param_act(P_BAD_VALUE, "iprange", "--dst-ip", end + 1);
		memcpy(&info->dst_max.in, ia, sizeof(*ia));
		info->flags |= IPRANGE_DST;
		if (invert)
			info->flags |= IPRANGE_DST_INV;
		*flags |= F_DSTIP;
		return true;
	}
	return false;
}

static void iprange_mt_check(unsigned int flags)
{
	if (flags == 0)
		exit_error(PARAMETER_PROBLEM,
			   "iprange match: You must specify `--src-range' or `--dst-range'");
}

static void
print_iprange(const struct ipt_iprange *range)
{
	const unsigned char *byte_min, *byte_max;

	byte_min = (const unsigned char *)&range->min_ip;
	byte_max = (const unsigned char *)&range->max_ip;
	printf("%u.%u.%u.%u-%u.%u.%u.%u ",
		byte_min[0], byte_min[1], byte_min[2], byte_min[3],
		byte_max[0], byte_max[1], byte_max[2], byte_max[3]);
}

static void iprange_print(const void *ip, const struct xt_entry_match *match,
                          int numeric)
{
	const struct ipt_iprange_info *info = (const void *)match->data;

	if (info->flags & IPRANGE_SRC) {
		printf("source IP range ");
		if (info->flags & IPRANGE_SRC_INV)
			printf("! ");
		print_iprange(&info->src);
	}
	if (info->flags & IPRANGE_DST) {
		printf("destination IP range ");
		if (info->flags & IPRANGE_DST_INV)
			printf("! ");
		print_iprange(&info->dst);
	}
}

static void
iprange_mt4_print(const void *ip, const struct xt_entry_match *match,
                  int numeric)
{
	const struct xt_iprange_mtinfo *info = (const void *)match->data;

	if (info->flags & IPRANGE_SRC) {
		printf("source IP range ");
		if (info->flags & IPRANGE_SRC_INV)
			printf("! ");
		/*
		 * ipaddr_to_numeric() uses a static buffer, so cannot
		 * combine the printf() calls.
		 */
		printf("%s", ipaddr_to_numeric(&info->src_min.in));
		printf("-%s ", ipaddr_to_numeric(&info->src_max.in));
	}
	if (info->flags & IPRANGE_DST) {
		printf("destination IP range ");
		if (info->flags & IPRANGE_DST_INV)
			printf("! ");
		printf("%s", ipaddr_to_numeric(&info->dst_min.in));
		printf("-%s ", ipaddr_to_numeric(&info->dst_max.in));
	}
}

static void
iprange_mt6_print(const void *ip, const struct xt_entry_match *match,
                  int numeric)
{
	const struct xt_iprange_mtinfo *info = (const void *)match->data;

	if (info->flags & IPRANGE_SRC) {
		printf("source IP range ");
		if (info->flags & IPRANGE_SRC_INV)
			printf("! ");
		/*
		 * ipaddr_to_numeric() uses a static buffer, so cannot
		 * combine the printf() calls.
		 */
		printf("%s", ip6addr_to_numeric(&info->src_min.in6));
		printf("-%s ", ip6addr_to_numeric(&info->src_max.in6));
	}
	if (info->flags & IPRANGE_DST) {
		printf("destination IP range ");
		if (info->flags & IPRANGE_DST_INV)
			printf("! ");
		printf("%s", ip6addr_to_numeric(&info->dst_min.in6));
		printf("-%s ", ip6addr_to_numeric(&info->dst_max.in6));
	}
}

static void iprange_save(const void *ip, const struct xt_entry_match *match)
{
	const struct ipt_iprange_info *info = (const void *)match->data;

	if (info->flags & IPRANGE_SRC) {
		if (info->flags & IPRANGE_SRC_INV)
			printf("! ");
		printf("--src-range ");
		print_iprange(&info->src);
		if (info->flags & IPRANGE_DST)
			fputc(' ', stdout);
	}
	if (info->flags & IPRANGE_DST) {
		if (info->flags & IPRANGE_DST_INV)
			printf("! ");
		printf("--dst-range ");
		print_iprange(&info->dst);
	}
}

static void iprange_mt4_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_iprange_mtinfo *info = (const void *)match->data;

	if (info->flags & IPRANGE_SRC) {
		if (info->flags & IPRANGE_SRC_INV)
			printf("! ");
		printf("--src-range %s", ipaddr_to_numeric(&info->src_min.in));
		printf("-%s ", ipaddr_to_numeric(&info->src_max.in));
	}
	if (info->flags & IPRANGE_DST) {
		if (info->flags & IPRANGE_DST_INV)
			printf("! ");
		printf("--dst-range %s", ipaddr_to_numeric(&info->dst_min.in));
		printf("-%s ", ipaddr_to_numeric(&info->dst_max.in));
	}
}

static void iprange_mt6_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_iprange_mtinfo *info = (const void *)match->data;

	if (info->flags & IPRANGE_SRC) {
		if (info->flags & IPRANGE_SRC_INV)
			printf("! ");
		printf("--src-range %s", ip6addr_to_numeric(&info->src_min.in6));
		printf("-%s ", ip6addr_to_numeric(&info->src_max.in6));
	}
	if (info->flags & IPRANGE_DST) {
		if (info->flags & IPRANGE_DST_INV)
			printf("! ");
		printf("--dst-range %s", ip6addr_to_numeric(&info->dst_min.in6));
		printf("-%s ", ip6addr_to_numeric(&info->dst_max.in6));
	}
}

static struct xtables_match iprange_match = {
	.version       = IPTABLES_VERSION,
	.name          = "iprange",
	.revision      = 0,
	.family        = AF_INET,
	.size          = XT_ALIGN(sizeof(struct ipt_iprange_info)),
	.userspacesize = XT_ALIGN(sizeof(struct ipt_iprange_info)),
	.help          = iprange_mt_help,
	.parse         = iprange_parse,
	.final_check   = iprange_mt_check,
	.print         = iprange_print,
	.save          = iprange_save,
	.extra_opts    = iprange_mt_opts,
};

static struct xtables_match iprange_mt_reg = {
	.version        = IPTABLES_VERSION,
	.name           = "iprange",
	.revision       = 1,
	.family         = AF_INET,
	.size           = XT_ALIGN(sizeof(struct xt_iprange_mtinfo)),
	.userspacesize  = XT_ALIGN(sizeof(struct xt_iprange_mtinfo)),
	.help           = iprange_mt_help,
	.parse          = iprange_mt4_parse,
	.final_check    = iprange_mt_check,
	.print          = iprange_mt4_print,
	.save           = iprange_mt4_save,
	.extra_opts     = iprange_mt_opts,
};

static struct xtables_match iprange_mt6_reg = {
	.version        = IPTABLES_VERSION,
	.name           = "iprange",
	.revision       = 1,
	.family         = AF_INET6,
	.size           = XT_ALIGN(sizeof(struct xt_iprange_mtinfo)),
	.userspacesize  = XT_ALIGN(sizeof(struct xt_iprange_mtinfo)),
	.help           = iprange_mt_help,
	.parse          = iprange_mt6_parse,
	.final_check    = iprange_mt_check,
	.print          = iprange_mt6_print,
	.save           = iprange_mt6_save,
	.extra_opts     = iprange_mt_opts,
};

void _init(void)
{
	xtables_register_match(&iprange_match);
	xtables_register_match(&iprange_mt_reg);
	xtables_register_match(&iprange_mt6_reg);
}
