/* Shared library add-on to iptables to add connection limit support. */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <getopt.h>
#include <iptables.h>
#include "../include/linux/netfilter/xt_connlimit.h"

/* Function which prints out usage message. */
static void connlimit_help(void)
{
	printf(
"connlimit v%s options:\n"
"[!] --connlimit-above n        match if the number of existing "
"                               connections is (not) above n\n"
"    --connlimit-mask n         group hosts using mask\n"
"\n", IPTABLES_VERSION);
}

static const struct option connlimit_opts[] = {
	{"connlimit-above", 1, NULL, 1},
	{"connlimit-mask",  1, NULL, 2},
	{NULL},
};

static void connlimit_init(struct ipt_entry_match *match, unsigned int *nfc)
{
	struct xt_connlimit_info *info = (void *)match->data;
	info->v4_mask = 0xFFFFFFFF;
}

static int connlimit_parse(int c, char **argv, int invert, unsigned int *flags,
                           const struct ipt_entry *entry,
                           unsigned int *nfcache,
                           struct ipt_entry_match **match)
{
	struct xt_connlimit_info *info = (void *)(*match)->data;
	char *err;
	int i;

	if (*flags & c)
		exit_error(PARAMETER_PROBLEM,
		           "--connlimit-above and/or --connlimit-mask may "
			   "only be given once");

	switch (c) {
	case 1:
		check_inverse(optarg, &invert, &optind, 0);
		info->limit   = strtoul(argv[optind-1], NULL, 0);
		info->inverse = invert;
		break;
	case 2:
		i = strtoul(argv[optind-1], &err, 0);
		if (i > 32 || *err != '\0')
			exit_error(PARAMETER_PROBLEM,
				"--connlimit-mask must be between 0 and 32");
		if (i == 0)
			info->v4_mask = 0;
		else
			info->v4_mask = htonl(0xFFFFFFFF << (32 - i));
		break;
	default:
		return 0;
	}

	*flags |= c;
	return 1;
}

/* Final check */
static void connlimit_check(unsigned int flags)
{
	if (!(flags & 1))
		exit_error(PARAMETER_PROBLEM,
		           "You must specify \"--connlimit-above\"");
}

static unsigned int count_bits(u_int32_t mask)
{
	unsigned int bits = 0;

	for (mask = ~ntohl(mask); mask != 0; mask >>= 1)
		++bits;

	return 32 - bits;
}

/* Prints out the matchinfo. */
static void connlimit_print(const struct ipt_ip *ip,
                            const struct ipt_entry_match *match, int numeric)
{
	const struct xt_connlimit_info *info = (const void *)match->data;

	printf("#conn/%u %s %u ", count_bits(info->v4_mask),
	       info->inverse ? "<" : ">", info->limit);
}

/* Saves the matchinfo in parsable form to stdout. */
static void connlimit_save(const struct ipt_ip *ip,
                           const struct ipt_entry_match *match)
{
	const struct xt_connlimit_info *info = (const void *)match->data;

	printf("%s--connlimit-above %u --connlimit-mask %u ",
	       info->inverse ? "! " : "", info->limit,
	       count_bits(info->v4_mask));
}

static struct iptables_match connlimit_reg = {
	.name          = "connlimit",
	.version       = IPTABLES_VERSION,
	.size          = IPT_ALIGN(sizeof(struct xt_connlimit_info)),
	.userspacesize = offsetof(struct xt_connlimit_info, data),
	.help          = connlimit_help,
	.init          = connlimit_init,
	.parse         = connlimit_parse,
	.final_check   = connlimit_check,
	.print         = connlimit_print,
	.save          = connlimit_save,
	.extra_opts    = connlimit_opts,
};

static __attribute__((constructor)) void libipt_connlimit_init(void)
{
	register_match(&connlimit_reg);
}
