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

static struct option opts[] = {
	{0}
};

/* Initialize the match. */
static void
init(struct ipt_entry_match *m, unsigned int *nfcache)
{
	/* Can't cache this. */
	*nfcache |= NFC_UNKNOWN;
}

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      unsigned int *nfcache,
      struct ipt_entry_match **match)
{
	return 0;
}

/* Final check; must have specified --mac. */
static void final_check(unsigned int flags)
{
}

static
struct iptables_match unclean = { 
	.next		= NULL,
	.name		= "unclean",
	.version	= IPTABLES_VERSION,
	.size		= IPT_ALIGN(0),
	.userspacesize	= IPT_ALIGN(0),
	.help		= &help,
	.init		= &init,
	.parse		= &parse,
	.final_check	= &final_check,
	.print		= NULL,
	.save		= NULL,
	.extra_opts	= opts
};

void _init(void)
{
	register_match(&unclean);
}
