/* Shared library add-on to ip6tables to add EUI64 address checking support. */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#if defined(__GLIBC__) && __GLIBC__ == 2
#include <net/ethernet.h>
#else
#include <linux/if_ether.h>
#endif
#include <ip6tables.h>

/* Function which prints out usage message. */
static void
help(void)
{
	printf(
"eui64 v%s options:\n"
" This module hasn't got any option\n"
" This module checks for EUI64 IPv6 addresses\n"
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

/* Prints out the matchinfo. */
static void
print(const void *ip,
      const struct xt_entry_match *match,
      int numeric)
{
	printf("eui64 ");
}

/* Saves the union ip6t_matchinfo in parsable form to stdout. */
static void save(const void *ip, const struct xt_entry_match *match)
{

}

static struct ip6tables_match eui64 = {
	.name 		= "eui64",
	.version	= IPTABLES_VERSION,
	.size		= IP6T_ALIGN(sizeof(int)),
	.userspacesize	= IP6T_ALIGN(sizeof(int)),
	.help		= &help,
	.parse		= &parse,
	.print		= &print,
	.save		= &save,
};

void _init(void)
{
	register_match6(&eui64);
}
