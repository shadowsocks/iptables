/* Shared library add-on to iptables for standard target support. */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <getopt.h>
#include <xtables.h>

/* Function which prints out usage message. */
static void standard_help(void)
{
	printf(
"Standard v%s options:\n"
"(If target is DROP, ACCEPT, RETURN or nothing)\n", IPTABLES_VERSION);
}

/* Function which parses command options; returns true if it
   ate an option */
static int standard_parse(int c, char **argv, int invert, unsigned int *flags,
                          const void *entry, struct xt_entry_target **target)
{
	return 0;
}

static struct xtables_target standard_target = {
	.family		= AF_UNSPEC,
	.name		= "standard",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(int)),
	.userspacesize	= XT_ALIGN(sizeof(int)),
	.help		= standard_help,
	.parse		= standard_parse,
};

void _init(void)
{
	xtables_register_target(&standard_target);
}
