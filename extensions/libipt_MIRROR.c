/* Shared library add-on to iptables to add MIRROR target support. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <iptables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

/* Function which prints out usage message. */
static void MIRROR_help(void)
{
	printf("MIRROR target takes no options\n");
}

/* Function which parses command options; returns true if it
   ate an option */
static int MIRROR_parse(int c, char **argv, int invert, unsigned int *flags,
                        const void *entry, struct xt_entry_target **target)
{
	return 0;
}

static struct xtables_target mirror_tg_reg = {
	.name		= "MIRROR",
	.version	= XTABLES_VERSION,
	.family		= PF_INET,
	.size		= XT_ALIGN(0),
	.userspacesize	= XT_ALIGN(0),
 	.help		= MIRROR_help,
 	.parse		= MIRROR_parse,
	.print		= NULL,
	.save		= NULL,
};

void _init(void)
{
	xtables_register_target(&mirror_tg_reg);
}
