/* Shared library add-on to iptables for unclean. */
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <iptables.h>

/* Function which prints out usage message. */
static void
help(void)
{
	printf(
"unclean v%s takes no options\n"
"\n", IPTABLES_VERSION);
}

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const void *entry,
      struct xt_entry_match **match)
{
	return 0;
}

static
struct iptables_match unclean = { 
	.name		= "unclean",
	.version	= IPTABLES_VERSION,
	.size		= IPT_ALIGN(0),
	.userspacesize	= IPT_ALIGN(0),
	.help		= &help,
	.parse		= &parse,
};

void _init(void)
{
	register_match(&unclean);
}
