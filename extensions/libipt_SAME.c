/* Shared library add-on to iptables to add simple non load-balancing SNAT support. */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <iptables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ip_nat_rule.h>
#include <linux/netfilter_ipv4/ipt_SAME.h>

#define BREAKUP_IP(x) (x) & 0xFF, ((x)>>8) & 0xFF, ((x)>>16) & 0xFF, (x)>>24

/* Function which prints out usage message. */
static void
help(void)
{
	printf(
"SAME v%s options:\n"
" --to <ipaddr>-<ipaddr>\n"
"				Addresses to map source to.\n"
" --nodst\n"
"				Don't use destination-ip in\n"
"				           source selection\n",
NETFILTER_VERSION);
}

static struct option opts[] = {
	{ "to", 1, 0, '1' },
	{ "nodst", 0, 0, '2'},
	{ 0 }
};

/* Initialize the target. */
static void
init(struct ipt_entry_target *t, unsigned int *nfcache)
{
	struct ipt_same_info *mr = (struct ipt_same_info *)t->data;

	/* Actually, it's 0, but it's ignored at the moment. */
	mr->rangesize = 1;

	/* Set default info to 0 */
	mr->info = 0;
	
	/* Can't cache this */
	*nfcache |= NFC_UNKNOWN;
}

/* Parses range of IPs */
static void
parse_to(char *arg, struct ip_nat_range *range)
{
	char *dash;
	struct in_addr *ip;

	range->flags |= IP_NAT_RANGE_MAP_IPS;
	dash = strchr(arg, '-');
	if (dash)
		*dash = '\0';
	else
		exit_error(PARAMETER_PROBLEM, "Bad IP range `%s'\n", arg);

	ip = dotted_to_addr(arg);
	if (!ip)
		exit_error(PARAMETER_PROBLEM, "Bad IP address `%s'\n",
			   arg);
	range->min_ip = ip->s_addr;
	ip = dotted_to_addr(dash+1);
	if (!ip)
		exit_error(PARAMETER_PROBLEM, "Bad IP address `%s'\n",
			   dash+1);
	range->max_ip = ip->s_addr;
	if (range->min_ip >= range->max_ip)
		exit_error(PARAMETER_PROBLEM, "Bad IP range `%u.%u.%u.%u-%u.%u.%u.%u'\n", BREAKUP_IP(range->min_ip), BREAKUP_IP(range->max_ip));
}

#define IPT_SAME_OPT_TO			0x01
#define IPT_SAME_OPT_NODST		0x02

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      struct ipt_entry_target **target)
{
	struct ipt_same_info *mr
		= (struct ipt_same_info *)(*target)->data;

	switch (c) {
	case '1':
		if (*flags & IPT_SAME_OPT_TO)
			exit_error(PARAMETER_PROBLEM,
				   "Can't specify --to twice");
		
		if (check_inverse(optarg, &invert))
			exit_error(PARAMETER_PROBLEM,
				   "Unexpected `!' after --to");

		parse_to(optarg, &mr->range[0]);
		*flags |= IPT_SAME_OPT_TO;
		break;
		
	case '2':
		if (*flags & IPT_SAME_OPT_NODST)
			exit_error(PARAMETER_PROBLEM,
				   "Can't specify --nodst twice");
		
		mr->info |= IPT_SAME_NODST;
		*flags |= IPT_SAME_OPT_NODST;
		break;
		
	default:
		return 0;
	}
	
	return 1;
}

/* Final check; need --to. */
static void final_check(unsigned int flags)
{
	if (!(flags & IPT_SAME_OPT_TO))
		exit_error(PARAMETER_PROBLEM,
			   "SAME needs --to");
}

/* Prints out the targinfo. */
static void
print(const struct ipt_ip *ip,
      const struct ipt_entry_target *target,
      int numeric)
{
	struct ipt_same_info *mr
		= (struct ipt_same_info *)target->data;
	struct ip_nat_range *r = &mr->range[0];
	struct in_addr a;

	a.s_addr = r->min_ip;

	printf("same %s", addr_to_dotted(&a));
	a.s_addr = r->max_ip;
	printf("-%s ", addr_to_dotted(&a));
	
	if (mr->info & IPT_SAME_NODST)
		printf("nodst ");
}

/* Saves the union ipt_targinfo in parsable form to stdout. */
static void
save(const struct ipt_ip *ip, const struct ipt_entry_target *target)
{
	struct ipt_same_info *mr
		= (struct ipt_same_info *)target->data;
	struct ip_nat_range *r = &mr->range[0];
	struct in_addr a;

	a.s_addr = r->min_ip;
	printf("--to %s", addr_to_dotted(&a));
	a.s_addr = r->max_ip;
	printf("-%s ", addr_to_dotted(&a));
	
	if (mr->info & IPT_SAME_NODST)
		printf("--nodst ");
}

static
struct iptables_target same
= { NULL,
    "SAME",
    NETFILTER_VERSION,
    IPT_ALIGN(sizeof(struct ipt_same_info)),
    IPT_ALIGN(sizeof(struct ipt_same_info)),
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
	register_target(&same);
}
