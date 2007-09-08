/* Shared library add-on to iptables to add TCPMSS target support.
 *
 * Copyright (c) 2000 Marc Boucher
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <xtables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_TCPMSS.h>

struct mssinfo {
	struct xt_entry_target t;
	struct xt_tcpmss_info mss;
};

/* Function which prints out usage message. */
static void __help(int hdrsize)
{
	printf(
"TCPMSS target v%s mutually-exclusive options:\n"
"  --set-mss value               explicitly set MSS option to specified value\n"
"  --clamp-mss-to-pmtu           automatically clamp MSS value to (path_MTU - %d)\n",
IPTABLES_VERSION, hdrsize);
}

static void help(void)
{
	__help(40);
}

static void help6(void)
{
	__help(60);
}

static const struct option opts[] = {
	{ "set-mss", 1, NULL, '1' },
	{ "clamp-mss-to-pmtu", 0, NULL, '2' },
	{ }
};

/* Initialize the target. */
static void
init(struct xt_entry_target *t)
{
}

/* Function which parses command options; returns true if it
   ate an option */
static int
__parse(int c, char **argv, int invert, unsigned int *flags,
      const void *entry,
      struct xt_entry_target **target,
      int hdrsize)
{
	struct xt_tcpmss_info *mssinfo
		= (struct xt_tcpmss_info *)(*target)->data;

	switch (c) {
		unsigned int mssval;

	case '1':
		if (*flags)
			exit_error(PARAMETER_PROBLEM,
			           "TCPMSS target: Only one option may be specified");
		if (string_to_number(optarg, 0, 65535 - hdrsize, &mssval) == -1)
			exit_error(PARAMETER_PROBLEM, "Bad TCPMSS value `%s'", optarg);
		
		mssinfo->mss = mssval;
		*flags = 1;
		break;

	case '2':
		if (*flags)
			exit_error(PARAMETER_PROBLEM,
			           "TCPMSS target: Only one option may be specified");
		mssinfo->mss = XT_TCPMSS_CLAMP_PMTU;
		*flags = 1;
		break;

	default:
		return 0;
	}

	return 1;
}

static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const void *entry,
      struct xt_entry_target **target)
{
	return __parse(c, argv, invert, flags, entry, target, 40);
}

static int
parse6(int c, char **argv, int invert, unsigned int *flags,
      const void *entry,
      struct xt_entry_target **target)
{
	return __parse(c, argv, invert, flags, entry, target, 60);
}

static void
final_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM,
		           "TCPMSS target: At least one parameter is required");
}

/* Prints out the targinfo. */
static void
print(const void *ip,
      const struct xt_entry_target *target,
      int numeric)
{
	const struct xt_tcpmss_info *mssinfo =
		(const struct xt_tcpmss_info *)target->data;
	if(mssinfo->mss == XT_TCPMSS_CLAMP_PMTU)
		printf("TCPMSS clamp to PMTU ");
	else
		printf("TCPMSS set %u ", mssinfo->mss);
}

/* Saves the union ipt_targinfo in parsable form to stdout. */
static void
save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_tcpmss_info *mssinfo =
		(const struct xt_tcpmss_info *)target->data;

	if(mssinfo->mss == XT_TCPMSS_CLAMP_PMTU)
		printf("--clamp-mss-to-pmtu ");
	else
		printf("--set-mss %u ", mssinfo->mss);
}

static struct xtables_target mss = {
	.family		= AF_INET,
	.name		= "TCPMSS",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_tcpmss_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_tcpmss_info)),
	.help		= &help,
	.init		= &init,
	.parse		= &parse,
	.final_check	= &final_check,
	.print		= &print,
	.save		= &save,
	.extra_opts	= opts
};

static struct xtables_target mss6 = {
	.family		= AF_INET6,
	.name		= "TCPMSS",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_tcpmss_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_tcpmss_info)),
	.help		= &help6,
	.init		= &init,
	.parse		= &parse6,
	.final_check	= &final_check,
	.print		= &print,
	.save		= &save,
	.extra_opts	= opts
};

void _init(void)
{
	xtables_register_target(&mss);
	xtables_register_target(&mss6);
}
