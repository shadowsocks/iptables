/* Shared library add-on to iptables to add NOTRACK target support. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <xtables.h>
#include <linux/netfilter/x_tables.h>

/* Function which prints out usage message. */
static void NOTRACK_help(void)
{
	printf("NOTRACK target takes no options\n");
}

/* Function which parses command options; returns true if it
   ate an option */
static int
NOTRACK_parse(int c, char **argv, int invert, unsigned int *flags,
              const void *entry, struct xt_entry_target **target)
{
	return 0;
}

static struct xtables_target notrack_target = {
	.family		= AF_INET,
	.name		= "NOTRACK",
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(0),
	.userspacesize	= XT_ALIGN(0),
	.help		= NOTRACK_help,
	.parse		= NOTRACK_parse,
};

static struct xtables_target notrack_target6 = {
	.family		= AF_INET6,
	.name		= "NOTRACK",
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(0),
	.userspacesize	= XT_ALIGN(0),
	.help		= NOTRACK_help,
	.parse		= NOTRACK_parse,
};

void _init(void)
{
	xtables_register_target(&notrack_target);
	xtables_register_target(&notrack_target6);
}
