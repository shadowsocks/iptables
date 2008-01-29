/* Shared library add-on to iptables to add customized REJECT support.
 *
 * (C) 2000 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 * 
 * ported to IPv6 by Harald Welte <laforge@gnumonks.org>
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <ip6tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter_ipv6/ip6t_REJECT.h>

struct reject_names {
	const char *name;
	const char *alias;
	enum ip6t_reject_with with;
	const char *desc;
};

static const struct reject_names reject_table[] = {
	{"icmp6-no-route", "no-route",
		IP6T_ICMP6_NO_ROUTE, "ICMPv6 no route"},
	{"icmp6-adm-prohibited", "adm-prohibited",
		IP6T_ICMP6_ADM_PROHIBITED, "ICMPv6 administratively prohibited"},
#if 0
	{"icmp6-not-neighbor", "not-neighbor"},
		IP6T_ICMP6_NOT_NEIGHBOR, "ICMPv6 not a neighbor"},
#endif
	{"icmp6-addr-unreachable", "addr-unreach",
		IP6T_ICMP6_ADDR_UNREACH, "ICMPv6 address unreachable"},
	{"icmp6-port-unreachable", "port-unreach",
		IP6T_ICMP6_PORT_UNREACH, "ICMPv6 port unreachable"},
	{"tcp-reset", "tcp-reset",
		IP6T_TCP_RESET, "TCP RST packet"}
};

static void
print_reject_types(void)
{
	unsigned int i;

	printf("Valid reject types:\n");

	for (i = 0; i < sizeof(reject_table)/sizeof(struct reject_names); i++) {
		printf("    %-25s\t%s\n", reject_table[i].name, reject_table[i].desc);
		printf("    %-25s\talias\n", reject_table[i].alias);
	}
	printf("\n");
}

/* Saves the union ipt_targinfo in parsable form to stdout. */

/* Function which prints out usage message. */
static void REJECT_help(void)
{
	printf(
"REJECT options:\n"
"--reject-with type              drop input packet and send back\n"
"                                a reply packet according to type:\n");

	print_reject_types();
}

static const struct option REJECT_opts[] = {
	{ "reject-with", 1, NULL, '1' },
	{ .name = NULL }
};

/* Allocate and initialize the target. */
static void REJECT_init(struct xt_entry_target *t)
{
	struct ip6t_reject_info *reject = (struct ip6t_reject_info *)t->data;

	/* default */
	reject->with = IP6T_ICMP6_PORT_UNREACH;

}

/* Function which parses command options; returns true if it
   ate an option */
static int REJECT_parse(int c, char **argv, int invert, unsigned int *flags,
                        const void *entry, struct xt_entry_target **target)
{
	struct ip6t_reject_info *reject = 
		(struct ip6t_reject_info *)(*target)->data;
	unsigned int limit = sizeof(reject_table)/sizeof(struct reject_names);
	unsigned int i;

	switch(c) {
	case '1':
		if (check_inverse(optarg, &invert, NULL, 0))
			exit_error(PARAMETER_PROBLEM,
				   "Unexpected `!' after --reject-with");
		for (i = 0; i < limit; i++) {
			if ((strncasecmp(reject_table[i].name, optarg, strlen(optarg)) == 0)
			    || (strncasecmp(reject_table[i].alias, optarg, strlen(optarg)) == 0)) {
				reject->with = reject_table[i].with;
				return 1;
			}
		}
		exit_error(PARAMETER_PROBLEM, "unknown reject type `%s'",optarg);
	default:
		/* Fall through */
		break;
	}
	return 0;
}

/* Prints out ipt_reject_info. */
static void REJECT_print(const void *ip, const struct xt_entry_target *target,
                         int numeric)
{
	const struct ip6t_reject_info *reject
		= (const struct ip6t_reject_info *)target->data;
	unsigned int i;

	for (i = 0; i < sizeof(reject_table)/sizeof(struct reject_names); i++) {
		if (reject_table[i].with == reject->with)
			break;
	}
	printf("reject-with %s ", reject_table[i].name);
}

/* Saves ipt_reject in parsable form to stdout. */
static void REJECT_save(const void *ip, const struct xt_entry_target *target)
{
	const struct ip6t_reject_info *reject
		= (const struct ip6t_reject_info *)target->data;
	unsigned int i;

	for (i = 0; i < sizeof(reject_table)/sizeof(struct reject_names); i++)
		if (reject_table[i].with == reject->with)
			break;

	printf("--reject-with %s ", reject_table[i].name);
}

static struct ip6tables_target reject_target6 = {
	.name = "REJECT",
	.version	= IPTABLES_VERSION,
	.size 		= IP6T_ALIGN(sizeof(struct ip6t_reject_info)),
	.userspacesize 	= IP6T_ALIGN(sizeof(struct ip6t_reject_info)),
	.help		= REJECT_help,
	.init		= REJECT_init,
	.parse		= REJECT_parse,
	.print		= REJECT_print,
	.save		= REJECT_save,
	.extra_opts	= REJECT_opts,
};

void _init(void)
{
	register_target6(&reject_target6);
}
