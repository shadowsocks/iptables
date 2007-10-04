/* Shared library add-on to iptables to add TTL matching support 
 * (C) 2000 by Harald Welte <laforge@gnumonks.org>
 *
 * $Id$
 *
 * This program is released under the terms of GNU GPL */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <iptables.h>

#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_ttl.h>

static void ttl_help(void)
{
	printf(
"TTL match v%s options:\n"
"  --ttl-eq value	Match time to live value\n"
"  --ttl-lt value	Match TTL < value\n"
"  --ttl-gt value	Match TTL > value\n"
, IPTABLES_VERSION);
}

static int ttl_parse(int c, char **argv, int invert, unsigned int *flags,
                     const void *entry, struct xt_entry_match **match)
{
	struct ipt_ttl_info *info = (struct ipt_ttl_info *) (*match)->data;
	unsigned int value;

	check_inverse(optarg, &invert, &optind, 0);

	switch (c) {
		case '2':
			if (string_to_number(optarg, 0, 255, &value) == -1)
				exit_error(PARAMETER_PROBLEM,
				           "ttl: Expected value between 0 and 255");

			if (invert)
				info->mode = IPT_TTL_NE;
			else
				info->mode = IPT_TTL_EQ;

			/* is 0 allowed? */
			info->ttl = value;
			break;
		case '3':
			if (string_to_number(optarg, 0, 255, &value) == -1)
				exit_error(PARAMETER_PROBLEM,
				           "ttl: Expected value between 0 and 255");

			if (invert) 
				exit_error(PARAMETER_PROBLEM,
						"ttl: unexpected `!'");

			info->mode = IPT_TTL_LT;
			info->ttl = value;
			break;
		case '4':
			if (string_to_number(optarg, 0, 255, &value) == -1)
				exit_error(PARAMETER_PROBLEM,
				           "ttl: Expected value between 0 and 255");

			if (invert)
				exit_error(PARAMETER_PROBLEM,
						"ttl: unexpected `!'");

			info->mode = IPT_TTL_GT;
			info->ttl = value;
			break;
		default:
			return 0;

	}

	if (*flags) 
		exit_error(PARAMETER_PROBLEM, 
				"Can't specify TTL option twice");
	*flags = 1;

	return 1;
}

static void ttl_check(unsigned int flags)
{
	if (!flags) 
		exit_error(PARAMETER_PROBLEM,
			"TTL match: You must specify one of "
			"`--ttl-eq', `--ttl-lt', `--ttl-gt");
}

static void ttl_print(const void *ip, const struct xt_entry_match *match,
                      int numeric)
{
	const struct ipt_ttl_info *info = 
		(struct ipt_ttl_info *) match->data;

	printf("TTL match ");
	switch (info->mode) {
		case IPT_TTL_EQ:
			printf("TTL == ");
			break;
		case IPT_TTL_NE:
			printf("TTL != ");
			break;
		case IPT_TTL_LT:
			printf("TTL < ");
			break;
		case IPT_TTL_GT:
			printf("TTL > ");
			break;
	}
	printf("%u ", info->ttl);
}

static void ttl_save(const void *ip, const struct xt_entry_match *match)
{
	const struct ipt_ttl_info *info =
		(struct ipt_ttl_info *) match->data;

	switch (info->mode) {
		case IPT_TTL_EQ:
			printf("--ttl-eq ");
			break;
		case IPT_TTL_NE:
			printf("! --ttl-eq ");
			break;
		case IPT_TTL_LT:
			printf("--ttl-lt ");
			break;
		case IPT_TTL_GT:
			printf("--ttl-gt ");
			break;
		default:
			/* error */
			break;
	}
	printf("%u ", info->ttl);
}

static const struct option ttl_opts[] = {
	{ "ttl", 1, NULL, '2' },
	{ "ttl-eq", 1, NULL, '2'},
	{ "ttl-lt", 1, NULL, '3'},
	{ "ttl-gt", 1, NULL, '4'},
	{ }
};

static struct iptables_match ttl_match = {
	.name		= "ttl",
	.version	= IPTABLES_VERSION,
	.size		= IPT_ALIGN(sizeof(struct ipt_ttl_info)),
	.userspacesize	= IPT_ALIGN(sizeof(struct ipt_ttl_info)),
	.help		= ttl_help,
	.parse		= ttl_parse,
	.final_check	= ttl_check,
	.print		= ttl_print,
	.save		= ttl_save,
	.extra_opts	= ttl_opts,
};


void _init(void) 
{
	register_match(&ttl_match);
}
