/* Shared library add-on to iptables to add NOTRACK target support. */
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
"NOTRACK target v%s takes no options\n",
IPTABLES_VERSION);
}

/* Initialize the target. */
static void
init(struct xt_entry_target *t)
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

static
struct xtables_target notrack =
{
	.family		= AF_INET,
	.name		= "NOTRACK",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(0),
	.userspacesize	= XT_ALIGN(0),
	.help		= &help,
	.init		= &init,
	.parse		= &parse,
	.final_check	= &final_check,
};

static
struct xtables_target notrack6 =
{
	.family		= AF_INET6,
	.name		= "NOTRACK",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(0),
	.userspacesize	= XT_ALIGN(0),
	.help		= &help,
	.init		= &init,
	.parse		= &parse,
	.final_check	= &final_check,
};

void _init(void)
{
	xtables_register_target(&notrack);
	xtables_register_target(&notrack6);
}
