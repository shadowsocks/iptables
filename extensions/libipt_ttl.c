/* Shared library add-on to iptables to add TTL matching support 
 * (C) 2000 by Harald Welte <laforge@gnumonks.org>
 *
 * Version: 1.3
 *
 * This program is released under the terms of GNU GPL */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <iptables.h>

#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_ttl.h>

static void help(void) 
{
	printf(
"TTL match v%s options:\n"
"  --ttl value		Match time to live value\n", NETFILTER_VERSION);
}

static void init(struct ipt_entry_match *m, unsigned int *nfcache)
{
	/* caching not yet implemented */
}

static int parse(int c, char **argv, int invert, unsigned int *flags,
		const struct ipt_entry *entry, unsigned int *nfcache,
		struct ipt_entry_match **match)
{
	struct ipt_ttl_info *info = (struct ipt_ttl_info *) (*match)->data;
	u_int8_t value;

	switch (c) {
		case '1':
			if (check_inverse(optarg, &invert))
				optind++;
			value = atoi(argv[optind-1]);

			/* is 0 allowed? */
			info->ttl = value;
			if (invert)
				info->invert = 1;
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
			"TTL match: You must specify `--ttl'");
}

static void print(const struct ipt_ip *ip, 
		const struct ipt_entry_match *match,
		int numeric)
{
	const struct ipt_ttl_info *info = 
		(struct ipt_ttl_info *) match->data;

	printf("TTL match ");
	if (info->invert)
		printf("!");
	printf("%u ", info->ttl);
}

static void save(const struct ipt_ip *ip, 
		const struct ipt_entry_match *match)
{
	const struct ipt_ttl_info *info =
		(struct ipt_ttl_info *) match->data;

	printf("--ttl ");
	if (info->invert)
		printf("!");
	printf("%u ", info->ttl);
}

static struct option opts[] = {
	{ "ttl", 0, '1' },
	{ 0 }
};

struct iptables_match ttl = {
	NULL,
	"ttl",
	NETFILTER_VERSION,
	IPT_ALIGN(sizeof(struct ipt_ttl_info)),
	IPT_ALIGN(sizeof(struct ipt_ttl_info)),
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
	register_match(&ttl);
}
