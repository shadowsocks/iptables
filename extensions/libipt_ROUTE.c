/* Shared library add-on to iptables to add ROUTE target support.
 * Author : Cédric de Launois, <delaunois@info.ucl.ac.be>
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
"  --iface   name    Send the packet directly through this interface.\n"
"  --to      ip      Route the packet as if its destination address was ip.\n"
"\n",
IPTABLES_VERSION);
}

static struct option opts[] = {
	{ "iface", 1, 0, '1' },
	{ "to", 1, 0, '2' },
	{ 0 }
};

/* Initialize the target. */
static void
init(struct ipt_entry_target *t, unsigned int *nfcache)
{
	struct ipt_route_target_info *route_info = 
		(struct ipt_route_target_info*)t->data;

	route_info->ifname[0] = '\0';
	route_info->ipto = 0;
}

#define IPT_ROUTE_OPT_IF    0x01
#define IPT_ROUTE_OPT_TO    0x02

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
		if (*flags & IPT_ROUTE_OPT_IF)
			exit_error(PARAMETER_PROBLEM,
				   "Can't specify --iface twice");

		if (check_inverse(optarg, &invert, NULL, 0))
			exit_error(PARAMETER_PROBLEM,
				   "Unexpected `!' after --iface");

		if (strlen(optarg) > sizeof(route_info->ifname) - 1)
			exit_error(PARAMETER_PROBLEM,
				   "Maximum interface name length %u",
				   sizeof(route_info->ifname) - 1);

		strcpy(route_info->ifname, optarg);
		*flags |= IPT_ROUTE_OPT_IF;
		break;

	case '2':
		if (*flags & IPT_ROUTE_OPT_TO)
			exit_error(PARAMETER_PROBLEM,
				   "Can't specify --to twice");

		if (!inet_aton(optarg, (struct in_addr*)&route_info->ipto)) {
			exit_error(PARAMETER_PROBLEM,
				   "Invalid IP address %s",
				   optarg);
		}

		*flags |= IPT_ROUTE_OPT_TO;
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
		           "ROUTE target: minimum 1 parameter is required");
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

	if (route_info->ifname[0])
		printf("iface %s ", route_info->ifname);

	if (route_info->ipto) {
		struct in_addr ip = { route_info->ipto };
		printf("to %s ", inet_ntoa(ip));
	}
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
    NULL, /* save */
    opts
};

void _init(void)
{
	register_target(&route);
}
