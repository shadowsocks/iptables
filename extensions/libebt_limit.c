/* ebt_limit
 *
 * Authors:
 * Tom Marshall <tommy@home.tig-grr.com>
 *
 * Mostly copied from iptables' limit match.
 *
 * September, 2003
 *
 * Translated to use libxtables for ebtables-compat in 2015 by
 * Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <xtables.h>
#include <linux/netfilter_bridge/ebt_limit.h>
#include "iptables/nft.h"
#include "iptables/nft-bridge.h"

#define EBT_LIMIT_AVG	"3/hour"
#define EBT_LIMIT_BURST	5

#define FLAG_LIMIT		0x01
#define FLAG_LIMIT_BURST	0x02
#define ARG_LIMIT		'1'
#define ARG_LIMIT_BURST		'2'

static struct option brlimit_opts[] =
{
	{ .name = "limit",	.has_arg = true,	.val = ARG_LIMIT },
	{ .name = "limit-burst",.has_arg = true,	.val = ARG_LIMIT_BURST },
	XT_GETOPT_TABLEEND,
};

static void brlimit_print_help(void)
{
	printf(
"limit options:\n"
"--limit avg                   : max average match rate: default "EBT_LIMIT_AVG"\n"
"                                [Packets per second unless followed by \n"
"                                /sec /minute /hour /day postfixes]\n"
"--limit-burst number          : number to match in a burst, -1 < number < 10001,\n"
"                                default %u\n", EBT_LIMIT_BURST);
}

static int parse_rate(const char *rate, uint32_t *val)
{
	const char *delim;
	uint32_t r;
	uint32_t mult = 1;  /* Seconds by default. */

	delim = strchr(rate, '/');
	if (delim) {
		if (strlen(delim+1) == 0)
			return 0;

		if (strncasecmp(delim+1, "second", strlen(delim+1)) == 0)
			mult = 1;
		else if (strncasecmp(delim+1, "minute", strlen(delim+1)) == 0)
			mult = 60;
		else if (strncasecmp(delim+1, "hour", strlen(delim+1)) == 0)
			mult = 60*60;
		else if (strncasecmp(delim+1, "day", strlen(delim+1)) == 0)
			mult = 24*60*60;
		else
			return 0;
	}
	r = atoi(rate);
	if (!r)
		return 0;

	/* This would get mapped to infinite (1/day is minimum they
	   can specify, so we're ok at that end). */
	if (r / mult > EBT_LIMIT_SCALE)
		return 0;

	*val = EBT_LIMIT_SCALE * mult / r;
	return 1;
}

static void brlimit_init(struct xt_entry_match *match)
{
	struct ebt_limit_info *r = (struct ebt_limit_info *)match->data;

	parse_rate(EBT_LIMIT_AVG, &r->avg);
	r->burst = EBT_LIMIT_BURST;
}

static int brlimit_parse(int c, char **argv, int invert, unsigned int *flags,
			 const void *entry, struct xt_entry_match **match)
{
	struct ebt_limit_info *r = (struct ebt_limit_info *)(*match)->data;
	uintmax_t num;

	switch (c) {
	case ARG_LIMIT:
		EBT_CHECK_OPTION(flags, FLAG_LIMIT);
		if (invert)
			xtables_error(PARAMETER_PROBLEM,
				      "Unexpected `!' after --limit");
		if (!parse_rate(optarg, &r->avg))
			xtables_error(PARAMETER_PROBLEM,
				      "bad rate `%s'", optarg);
		break;
	case ARG_LIMIT_BURST:
		EBT_CHECK_OPTION(flags, FLAG_LIMIT_BURST);
		if (invert)
			xtables_error(PARAMETER_PROBLEM,
				      "Unexpected `!' after --limit-burst");
		if (!xtables_strtoul(optarg, NULL, &num, 0, 10000))
			xtables_error(PARAMETER_PROBLEM,
				      "bad --limit-burst `%s'", optarg);
		r->burst = num;
		break;
	default:
		return 0;
	}

	return 1;
}

struct rates
{
	const char	*name;
	uint32_t	mult;
};

static struct rates g_rates[] =
{
	{ "day",	EBT_LIMIT_SCALE*24*60*60 },
	{ "hour",	EBT_LIMIT_SCALE*60*60 },
	{ "min",	EBT_LIMIT_SCALE*60 },
	{ "sec",	EBT_LIMIT_SCALE }
};

static void print_rate(uint32_t period)
{
	unsigned int i;

	for (i = 1; i < sizeof(g_rates)/sizeof(struct rates); i++)
		if (period > g_rates[i].mult ||
		    g_rates[i].mult/period < g_rates[i].mult%period)
			break;

	printf("%u/%s ", g_rates[i-1].mult / period, g_rates[i-1].name);
}

static void brlimit_print(const void *ip, const struct xt_entry_match *match,
			  int numeric)
{
	struct ebt_limit_info *r = (struct ebt_limit_info *)match->data;

	printf("--limit ");
	print_rate(r->avg);
	printf("--limit-burst %u ", r->burst);
}

static struct xtables_match brlimit_match = {
	.name		= "limit",
	.revision	= 0,
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_BRIDGE,
	.size		= XT_ALIGN(sizeof(struct ebt_limit_info)),
	.userspacesize	= offsetof(struct ebt_limit_info, prev),
	.init		= brlimit_init,
	.help		= brlimit_print_help,
	.parse		= brlimit_parse,
	.print		= brlimit_print,
	.extra_opts	= brlimit_opts,
};

void _init(void)
{
	xtables_register_match(&brlimit_match);
}
