/* Shared library add-on to iptables for ECN, $Version$
 *
 * (C) 2002 by Harald Welte <laforge@gnumonks.org>
 *
 * This program is distributed under the terms of GNU GPL v2, 1991
 *
 * libipt_ECN.c borrowed heavily from libipt_DSCP.c
 *
 * $Id: libipt_ECN.c,v 1.2 2002/02/18 21:32:56 laforge Exp $
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <iptables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_ECN.h>

static void init(struct ipt_entry_target *t, unsigned int *nfcache) 
{
}

static void help(void) 
{
	printf(
"ECN target options\n"
"  --ecn-remove			Remove all ECN bits which may be present\n"
"  		                in the IPv4 header\n"
);
}

static struct option opts[] = {
	{ "ecn-remove", 1, 0, 'F' },
	{ 0 }
};

static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      struct ipt_entry_target **target)
{
	struct ipt_ECN_info *einfo
		= (struct ipt_ECN_info *)(*target)->data;

	switch (c) {
	case 'F':
		if (*flags)
			exit_error(PARAMETER_PROBLEM,
			           "ECN target: Only use --ecn-remove ONCE!");
		einfo->operation = IPT_ECN_OP_REMOVE;
		*flags = 1;
		break;

	default:
		return 0;
	}

	return 1;
}

static void
final_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM,
		           "ECN target: Parameter --ecn-remove is required");
}

/* Prints out the targinfo. */
static void
print(const struct ipt_ip *ip,
      const struct ipt_entry_target *target,
      int numeric)
{
	const struct ipt_ECN_info *einfo =
		(const struct ipt_ECN_info *)target->data;

	printf("ECN ");

	switch (einfo->operation) {
		case IPT_ECN_OP_REMOVE:
			printf("remove ");
			break;
		default:
			printf("unsupported_ecn_operation ");
			break;
	}
}

/* Saves the union ipt_targinfo in parsable form to stdout. */
static void
save(const struct ipt_ip *ip, const struct ipt_entry_target *target)
{
	const struct ipt_ECN_info *einfo =
		(const struct ipt_ECN_info *)target->data;

	switch (einfo->operation) {
		case IPT_ECN_OP_REMOVE:
			printf("--ecn-remove ");
			break;
	}
}

static
struct iptables_target ecn
= { NULL,
    "ECN",
    NETFILTER_VERSION,
    IPT_ALIGN(sizeof(struct ipt_ECN_info)),
    IPT_ALIGN(sizeof(struct ipt_ECN_info)),
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
	register_target(&ecn);
}
