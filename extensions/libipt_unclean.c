/* Shared library add-on to iptables for unclean. */
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <iptables.h>

/* Function which prints out usage message. */
static void unclean_help(void)
{
	printf("unclean match takes no options\n");
}

/* Function which parses command options; returns true if it
   ate an option */
static int unclean_parse(int c, char **argv, int invert, unsigned int *flags,
                         const void *entry, struct xt_entry_match **match)
{
	return 0;
}

static struct xtables_match unclean_mt_reg = {
	.name		= "unclean",
	.version	= XTABLES_VERSION,
	.family		= PF_INET,
	.size		= XT_ALIGN(0),
	.userspacesize	= XT_ALIGN(0),
	.help		= unclean_help,
	.parse		= unclean_parse,
};

void _init(void)
{
	xtables_register_match(&unclean_mt_reg);
}
