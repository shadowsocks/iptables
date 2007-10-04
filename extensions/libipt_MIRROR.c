/* Shared library add-on to iptables to add MIRROR target support. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <iptables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

/* Function which prints out usage message. */
static void
help(void)
{
	printf(
"MIRROR target v%s takes no options\n",
IPTABLES_VERSION);
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

static struct iptables_target mirror = {
	.name		= "MIRROR",
	.version	= IPTABLES_VERSION,
	.size		= IPT_ALIGN(0),
	.userspacesize	= IPT_ALIGN(0),
 	.help		= &help,
 	.parse		= &parse,
	.print		= NULL,
	.save		= NULL,
};

void _init(void)
{
	register_target(&mirror);
}
