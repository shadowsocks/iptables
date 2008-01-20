/* Shared library add-on to iptables to add IP range matching support. */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <iptables.h>
#include <linux/netfilter_ipv4/ipt_iprange.h>

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

void _init(void)
{
	xtables_register_match(&iprange_match);
}
