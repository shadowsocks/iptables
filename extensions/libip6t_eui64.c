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
static void eui64_help(void)
{
	printf(
"eui64 v%s options:\n"
" This module hasn't got any option\n"
" This module checks for EUI64 IPv6 addresses\n"
"\n", IPTABLES_VERSION);
}

/* Function which parses command options; returns true if it
   ate an option */
static int eui64_parse(int c, char **argv, int invert, unsigned int *flags,
                       const void *entry, struct xt_entry_match **match)
{
	return 0;
}

static struct ip6tables_match eui64_target6 = {
	.name 		= "eui64",
	.version	= IPTABLES_VERSION,
	.size		= IP6T_ALIGN(sizeof(int)),
	.userspacesize	= IP6T_ALIGN(sizeof(int)),
	.help		= eui64_help,
	.parse		= eui64_parse,
};

void _init(void)
{
	register_match6(&eui64_target6);
}
