/* Shared library add-on to iptables to add ROUTE v6 target support.
 * Author : Cedric de Launois, <delaunois@info.ucl.ac.be>
 * v 1.0 2003/06/24
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <ip6tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter_ipv6/ip6t_ROUTE.h>

/* Function which prints out usage message. */
static void
help(void)
{
	printf(
"ROUTE target v%s options:\n"
"    --oif   \tifname \t\tRoute the packet through `ifname' network interface\n"
"    --gw    \tip     \t\tRoute the packet via this gateway\n"
"    --continue\t     \t\tRoute the packet and continue traversing the rules.\n"
"\n",
"1.0");
}

static struct option opts[] = {
	{ "oif", 1, 0, '1' },
	{ "iif", 1, 0, '2' },
	{ "gw", 1, 0, '3' },
	{ "continue", 0, 0, '4' },
	{ 0 }
};

/* Initialize the target. */
static void
init(struct ip6t_entry_target *t, unsigned int *nfcache)
{
	struct ip6t_route_target_info *route_info = 
		(struct ip6t_route_target_info*)t->data;

	route_info->oif[0] = '\0';
	route_info->iif[0] = '\0';
	route_info->gw[0] = 0;
	route_info->gw[1] = 0;
	route_info->gw[2] = 0;
	route_info->gw[3] = 0;
	route_info->flags = 0;
}


#define IP6T_ROUTE_OPT_OIF      0x01
#define IP6T_ROUTE_OPT_IIF      0x02
#define IP6T_ROUTE_OPT_GW       0x04
#define IP6T_ROUTE_OPT_CONTINUE 0x08

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ip6t_entry *entry,
      struct ip6t_entry_target **target)
{
	struct ip6t_route_target_info *route_info = 
		(struct ip6t_route_target_info*)(*target)->data;

	switch (c) {
	case '1':
		if (*flags & IP6T_ROUTE_OPT_OIF)
			exit_error(PARAMETER_PROBLEM,
				   "Can't specify --oif twice");

		if (check_inverse(optarg, &invert, NULL, 0))
			exit_error(PARAMETER_PROBLEM,
				   "Unexpected `!' after --oif");

		if (strlen(optarg) > sizeof(route_info->oif) - 1)
			exit_error(PARAMETER_PROBLEM,
				   "Maximum interface name length %u",
				   sizeof(route_info->oif) - 1);

		strcpy(route_info->oif, optarg);
		*flags |= IP6T_ROUTE_OPT_OIF;
		break;

	case '2':
		exit_error(PARAMETER_PROBLEM,
			   "--iif option not implemented");
		break;

	case '3':
		if (*flags & IP6T_ROUTE_OPT_GW)
			exit_error(PARAMETER_PROBLEM,
				   "Can't specify --gw twice");

		if (check_inverse(optarg, &invert, NULL, 0))
			exit_error(PARAMETER_PROBLEM,
				   "Unexpected `!' after --gw");

		if (!inet_pton(AF_INET6, optarg, (struct in6_addr*)&route_info->gw)) {
			exit_error(PARAMETER_PROBLEM,
				   "Invalid IPv6 address %s",
				   optarg);
		}

		*flags |= IP6T_ROUTE_OPT_GW;
		break;

	case '4':
		if (*flags & IP6T_ROUTE_OPT_CONTINUE)
			exit_error(PARAMETER_PROBLEM,
				   "Can't specify --continue twice");

		route_info->flags |= IP6T_ROUTE_CONTINUE;
		*flags |= IP6T_ROUTE_OPT_CONTINUE;

		break;

	default:
		return 0;
	}

	return 1;
}


static void
final_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM,
		           "ROUTE target: oif or gw option required");
}


/* Prints out the targinfo. */
static void
print(const struct ip6t_ip6 *ip,
      const struct ip6t_entry_target *target,
      int numeric)
{
	const struct ip6t_route_target_info *route_info
		= (const struct ip6t_route_target_info *)target->data;

	printf("ROUTE ");

	if (route_info->oif[0])
		printf("oif:%s ", route_info->oif);

	if (route_info->gw[0] 
	    || route_info->gw[1] 
	    || route_info->gw[2] 
	    || route_info->gw[3]) {
		char address[INET6_ADDRSTRLEN];
		printf("gw:%s ", inet_ntop(AF_INET6, route_info->gw, address, INET6_ADDRSTRLEN));
	}

	if (route_info->flags & IP6T_ROUTE_CONTINUE)
		printf("continue");

}


static void save(const struct ip6t_ip6 *ip, 
		 const struct ip6t_entry_target *target)
{
	const struct ip6t_route_target_info *route_info
		= (const struct ip6t_route_target_info *)target->data;

	if (route_info->oif[0])
		printf("--oif %s ", route_info->oif);

	if (route_info->gw[0] 
	    || route_info->gw[1] 
	    || route_info->gw[2] 
	    || route_info->gw[3]) {
		char address[INET6_ADDRSTRLEN];
		printf("--gw %s ", inet_ntop(AF_INET6, route_info->gw, address, INET6_ADDRSTRLEN));
	}

	if (route_info->flags & IP6T_ROUTE_CONTINUE)
		printf("--continue ");
}


static
struct ip6tables_target route
= { NULL,
    "ROUTE",
    IPTABLES_VERSION,
    IP6T_ALIGN(sizeof(struct ip6t_route_target_info)),
    IP6T_ALIGN(sizeof(struct ip6t_route_target_info)),
    &help,
    &init,
    &parse,
    &final_check,
    &print,
    &save,
    opts
};

void _init(void)
{
	register_target6(&route);
}
