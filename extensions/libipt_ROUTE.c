/* Shared library add-on to iptables to add ROUTE target support.
 * Author : Cedric de Launois, <delaunois@info.ucl.ac.be>
 * v 1.8 2003/06/24
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <iptables.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_ROUTE.h>

/* Function which prints out usage message. */
static void
help(void)
{
	printf(
"ROUTE target v%s options:\n"
"    --oif   \tifname \t\tRoute the packet through `ifname' network interface\n"
"    --iif   \tifname \t\tChange the packet's incoming interface to `ifname'\n"
"    --gw    \tip     \t\tRoute the packet via this gateway\n"
"    --continue\t     \t\tRoute the packet and continue traversing the\n"
"            \t       \t\trules. Not valid with --iif.\n"
"\n",
"1.8");
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
init(struct ipt_entry_target *t, unsigned int *nfcache)
{
	struct ipt_route_target_info *route_info = 
		(struct ipt_route_target_info*)t->data;

	route_info->oif[0] = '\0';
	route_info->iif[0] = '\0';
	route_info->gw = 0;
	route_info->flags = 0;
}


#define IPT_ROUTE_OPT_OIF      0x01
#define IPT_ROUTE_OPT_IIF      0x02
#define IPT_ROUTE_OPT_GW       0x04
#define IPT_ROUTE_OPT_CONTINUE 0x08

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      struct ipt_entry_target **target)
{
	struct ipt_route_target_info *route_info = 
		(struct ipt_route_target_info*)(*target)->data;

	switch (c) {
	case '1':
		if (*flags & IPT_ROUTE_OPT_OIF)
			exit_error(PARAMETER_PROBLEM,
				   "Can't specify --oif twice");

		if (*flags & IPT_ROUTE_OPT_IIF)
			exit_error(PARAMETER_PROBLEM,
				   "Can't use --oif and --iif together");

		if (check_inverse(optarg, &invert, NULL, 0))
			exit_error(PARAMETER_PROBLEM,
				   "Unexpected `!' after --oif");

		if (strlen(optarg) > sizeof(route_info->oif) - 1)
			exit_error(PARAMETER_PROBLEM,
				   "Maximum interface name length %u",
				   sizeof(route_info->oif) - 1);

		strcpy(route_info->oif, optarg);
		*flags |= IPT_ROUTE_OPT_OIF;
		break;

	case '2':
		if (*flags & IPT_ROUTE_OPT_IIF)
			exit_error(PARAMETER_PROBLEM,
				   "Can't specify --iif twice");

		if (*flags & IPT_ROUTE_OPT_OIF)
			exit_error(PARAMETER_PROBLEM,
				   "Can't use --iif and --oif together");

		if (check_inverse(optarg, &invert, NULL, 0))
			exit_error(PARAMETER_PROBLEM,
				   "Unexpected `!' after --iif");

		if (strlen(optarg) > sizeof(route_info->iif) - 1)
			exit_error(PARAMETER_PROBLEM,
				   "Maximum interface name length %u",
				   sizeof(route_info->iif) - 1);

		strcpy(route_info->iif, optarg);
		*flags |= IPT_ROUTE_OPT_IIF;
		break;

	case '3':
		if (*flags & IPT_ROUTE_OPT_GW)
			exit_error(PARAMETER_PROBLEM,
				   "Can't specify --gw twice");

		if (check_inverse(optarg, &invert, NULL, 0))
			exit_error(PARAMETER_PROBLEM,
				   "Unexpected `!' after --gw");

		if (!inet_aton(optarg, (struct in_addr*)&route_info->gw)) {
			exit_error(PARAMETER_PROBLEM,
				   "Invalid IP address %s",
				   optarg);
		}

		*flags |= IPT_ROUTE_OPT_GW;
		break;

	case '4':
		if (*flags & IPT_ROUTE_OPT_CONTINUE)
			exit_error(PARAMETER_PROBLEM,
				   "Can't specify --continue twice");

		route_info->flags |= IPT_ROUTE_CONTINUE;
		*flags |= IPT_ROUTE_OPT_CONTINUE;

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
		           "ROUTE target: oif, iif or gw option required");

	if ((flags & IPT_ROUTE_OPT_CONTINUE) && (flags & IPT_ROUTE_OPT_IIF))
		exit_error(PARAMETER_PROBLEM,
			   "ROUTE target: can't continue traversing the rules with iif option");
}


/* Prints out the targinfo. */
static void
print(const struct ipt_ip *ip,
      const struct ipt_entry_target *target,
      int numeric)
{
	const struct ipt_route_target_info *route_info
		= (const struct ipt_route_target_info *)target->data;

	printf("ROUTE ");

	if (route_info->oif[0])
		printf("oif:%s ", route_info->oif);

	if (route_info->iif[0])
		printf("iif:%s ", route_info->iif);

	if (route_info->gw) {
		struct in_addr ip = { route_info->gw };
		printf("gw:%s ", inet_ntoa(ip));
	}

	if (route_info->flags & IPT_ROUTE_CONTINUE)
		printf("continue");

}


static void save(const struct ipt_ip *ip, 
		 const struct ipt_entry_target *target)
{
	const struct ipt_route_target_info *route_info
		= (const struct ipt_route_target_info *)target->data;

	if (route_info->oif[0])
		printf("--oif %s ", route_info->oif);

	if (route_info->iif[0])
		printf("--iif %s ", route_info->iif);

	if (route_info->gw) {
		struct in_addr ip = { route_info->gw };
		printf("--gw %s ", inet_ntoa(ip));
	}

	if (route_info->flags & IPT_ROUTE_CONTINUE)
		printf("--continue ");
}


static
struct iptables_target route
= { NULL,
    "ROUTE",
    IPTABLES_VERSION,
    IPT_ALIGN(sizeof(struct ipt_route_target_info)),
    IPT_ALIGN(sizeof(struct ipt_route_target_info)),
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
	register_target(&route);
}
