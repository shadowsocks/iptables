/*
 * IPv6 Hop Limit matching module
 * Maciej Soltysiak <solt@dns.toxicfilms.tv>
 * Based on HW's ttl match
 * This program is released under the terms of GNU GPL
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <ip6tables.h>

#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter_ipv6/ip6t_hl.h>

static void help(void) 
{
	printf(
"HL match v%s options:\n"
"  --hl-eq value	Match hop limit value\n"
"  --hl-lt value	Match HL < value\n"
"  --hl-gt value	Match HL > value\n"
, IPTABLES_VERSION);
}

static void init(struct ip6t_entry_match *m, unsigned int *nfcache)
{
	/* caching not yet implemented */
	*nfcache |= NFC_UNKNOWN;
}

static int parse(int c, char **argv, int invert, unsigned int *flags,
		const struct ip6t_entry *entry, unsigned int *nfcache,
		struct ip6t_entry_match **match)
{
	struct ip6t_hl_info *info = (struct ip6t_hl_info *) (*match)->data;
	u_int8_t value;

	check_inverse(optarg, &invert, &optind, 0);
	value = atoi(argv[optind-1]);

	if (*flags) 
		exit_error(PARAMETER_PROBLEM, 
				"Can't specify HL option twice");

	if (!optarg)
		exit_error(PARAMETER_PROBLEM,
				"hl: You must specify a value");
	switch (c) {
		case '2':
			if (invert)
				info->mode = IP6T_HL_NE;
			else
				info->mode = IP6T_HL_EQ;

			/* is 0 allowed? */
			info->hop_limit = value;
			*flags = 1;

			break;
		case '3':
			if (invert) 
				exit_error(PARAMETER_PROBLEM,
						"hl: unexpected `!'");

			info->mode = IP6T_HL_LT;
			info->hop_limit = value;
			*flags = 1;

			break;
		case '4':
			if (invert)
				exit_error(PARAMETER_PROBLEM,
						"hl: unexpected `!'");

			info->mode = IP6T_HL_GT;
			info->hop_limit = value;
			*flags = 1;

			break;
		default:
			return 0;

	}

	return 1;
}

static void final_check(unsigned int flags)
{
	if (!flags) 
		exit_error(PARAMETER_PROBLEM,
			"HL match: You must specify one of "
			"`--hl-eq', `--hl-lt', `--hl-gt");
}

static void print(const struct ip6t_ip6 *ip, 
		const struct ip6t_entry_match *match,
		int numeric)
{
	const struct ip6t_hl_info *info = 
		(struct ip6t_hl_info *) match->data;

	printf("HL match ");
	switch (info->mode) {
		case IP6T_HL_EQ:
			printf("HL == ");
			break;
		case IP6T_HL_NE:
			printf("HL != ");
			break;
		case IP6T_HL_LT:
			printf("HL < ");
			break;
		case IP6T_HL_GT:
			printf("HL > ");
			break;
	}
	printf("%u ", info->hop_limit);
}

static void save(const struct ip6t_ip6 *ip, 
		const struct ip6t_entry_match *match)
{
	const struct ip6t_hl_info *info =
		(struct ip6t_hl_info *) match->data;

	switch (info->mode) {
		case IP6T_HL_EQ:
			printf("--hl-eq ");
			break;
		case IP6T_HL_NE:
			printf("! --hl-eq ");
			break;
		case IP6T_HL_LT:
			printf("--hl-lt ");
			break;
		case IP6T_HL_GT:
			printf("--hl-gt ");
			break;
		default:
			/* error */
			break;
	}
	printf("%u ", info->hop_limit);
}

static struct option opts[] = {
	{ "hl", 1, 0, '2' },
	{ "hl-eq", 1, 0, '2'},
	{ "hl-lt", 1, 0, '3'},
	{ "hl-gt", 1, 0, '4'},
	{ 0 }
};

static
struct ip6tables_match hl = {
	NULL,
	"hl",
	IPTABLES_VERSION,
	IP6T_ALIGN(sizeof(struct ip6t_hl_info)),
	IP6T_ALIGN(sizeof(struct ip6t_hl_info)),
	&help,
	&init,
	&parse,
	&final_check,
	&print,
	&save,
	opts
};


void _init(void) 
{
	register_match6(&hl);
}
