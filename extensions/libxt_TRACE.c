/* Shared library add-on to iptables to add TRACE target support. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <xtables.h>
#include <linux/netfilter/x_tables.h>

/* Function which prints out usage message. */
static void
help(void)
{
	printf(
"TRACE target v%s takes no options\n",
IPTABLES_VERSION);
}

/* Initialize the target. */
static void
init(struct xt_entry_target *t, unsigned int *nfcache)
{
}

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const void *entry,
      struct xt_entry_target **target)
{
	return 0;
}

static void
final_check(unsigned int flags)
{
}

static struct xtables_target trace = {
	.family		= AF_INET,
	.name		= "TRACE",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(0),
	.userspacesize	= XT_ALIGN(0),
	.help		= &help,
	.init		= &init,
	.parse		= &parse,
	.final_check	= &final_check,
	.print		= NULL, /* print */
	.save		= NULL, /* save */
};

static struct xtables_target trace6 = {
	.family		= AF_INET6,
	.name		= "TRACE",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(0),
	.userspacesize	= XT_ALIGN(0),
	.help		= &help,
	.init		= &init,
	.parse		= &parse,
	.final_check	= &final_check,
	.print		= NULL, /* print */
	.save		= NULL, /* save */
};

void _init(void)
{
	xtables_register_target(&trace);
	xtables_register_target(&trace6);
}
