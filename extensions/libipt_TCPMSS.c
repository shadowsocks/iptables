/* Shared library add-on to iptables to add TCPMSS target support.
 *
 * Copyright (c) 2000 Marc Boucher
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <iptables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_TCPMSS.h>

struct mssinfo {
	struct ipt_entry_target t;
	struct ipt_tcpmss_info mss;
};

/* Function which prints out usage message. */
static void
help(void)
{
	printf(
"TCPMSS target v%s options:\n"
"  --set-mss value                   Value to set MSS option to\n",
NETFILTER_VERSION);
}

static struct option opts[] = {
	{ "set-mss", 1, 0, '1' },
	{ 0 }
};

/* Initialize the target. */
static void
init(struct ipt_entry_target *t, unsigned int *nfcache)
{
}

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      struct ipt_entry_target **target)
{
	struct ipt_tcpmss_info *mssinfo
		= (struct ipt_tcpmss_info *)(*target)->data;

	switch (c) {
		int mssval;

	case '1':
		if (*flags)
			exit_error(PARAMETER_PROBLEM,
			           "TCPMSS target: Can't specify --set-mss twice");
		if ((mssval = string_to_number(optarg, 0, 65535)) == -1)
			exit_error(PARAMETER_PROBLEM, "Bad TCPMSS value `%s'", optarg);
		
		mssinfo->mss = mssval;
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
		           "TCPMSS target: Parameter --set-mss is required");
}

/* Prints out the targinfo. */
static void
print(const struct ipt_ip *ip,
      const struct ipt_entry_target *target,
      int numeric)
{
	const struct ipt_tcpmss_info *mssinfo =
		(const struct ipt_tcpmss_info *)target->data;
	printf("TCPMSS set %u ", mssinfo->mss);
}

/* Saves the union ipt_targinfo in parsable form to stdout. */
static void
save(const struct ipt_ip *ip, const struct ipt_entry_target *target)
{
	const struct ipt_tcpmss_info *mssinfo =
		(const struct ipt_tcpmss_info *)target->data;

	printf("--set-mss %u ", mssinfo->mss);
}

struct iptables_target mss
= { NULL,
    "TCPMSS",
    NETFILTER_VERSION,
    IPT_ALIGN(sizeof(struct ipt_tcpmss_info)),
    IPT_ALIGN(sizeof(struct ipt_tcpmss_info)),
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
	register_target(&mss);
}
