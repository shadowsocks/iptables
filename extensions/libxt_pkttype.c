/* 
 * Shared library add-on to iptables to match 
 * packets by their type (BROADCAST, UNICAST, MULTICAST). 
 *
 * Michal Ludvig <michal@logix.cz>
 */
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
#include <xtables.h>
#include <linux/if_packet.h>
#include <linux/netfilter/xt_pkttype.h>

#define	PKTTYPE_VERSION	"0.1"

struct pkttypes {
	const char *name;
	unsigned char pkttype;
	unsigned char printhelp;
	const char *help;
};

static const struct pkttypes supported_types[] = {
	{"unicast", PACKET_HOST, 1, "to us"},
	{"broadcast", PACKET_BROADCAST, 1, "to all"},
	{"multicast", PACKET_MULTICAST, 1, "to group"},
/*
	{"otherhost", PACKET_OTHERHOST, 1, "to someone else"},
	{"outgoing", PACKET_OUTGOING, 1, "outgoing of any type"},
*/
	/* aliases */
	{"bcast", PACKET_BROADCAST, 0, NULL},
	{"mcast", PACKET_MULTICAST, 0, NULL},
	{"host", PACKET_HOST, 0, NULL}
};

static void print_types()
{
	unsigned int	i;
	
	printf("Valid packet types:\n");
	for (i = 0; i < sizeof(supported_types)/sizeof(struct pkttypes); i++)
	{
		if(supported_types[i].printhelp == 1)
			printf("\t%-14s\t\t%s\n", supported_types[i].name, supported_types[i].help);
	}
	printf("\n");
}

/* Function which prints out usage message. */
static void help(void)
{
	printf(
"pkt_type v%s options:\n"
"  --pkt-type [!] packettype\tmatch packet type\n"
"\n", PKTTYPE_VERSION);
	print_types();
}

static struct option opts[] = {
	{"pkt-type", 1, 0, '1'},
	{0}
};

static void parse_pkttype(const char *pkttype, struct xt_pkttype_info *info)
{
	unsigned int	i;
	
	for (i = 0; i < sizeof(supported_types)/sizeof(struct pkttypes); i++)
	{
		if(strcasecmp(pkttype, supported_types[i].name)==0)
		{
			info->pkttype=supported_types[i].pkttype;
			return;
		}
	}
	
	exit_error(PARAMETER_PROBLEM, "Bad packet type '%s'", pkttype);
}

static int parse(int c, char **argv, int invert, unsigned int *flags,
      const void *entry,
      unsigned int *nfcache,
      struct xt_entry_match **match)
{
	struct xt_pkttype_info *info = (struct xt_pkttype_info *)(*match)->data;
	
	switch(c)
	{
		case '1':
			check_inverse(optarg, &invert, &optind, 0);
			parse_pkttype(argv[optind-1], info);
			if(invert)
				info->invert=1;
			*flags=1;
			break;

		default: 
			return 0;
	}

	return 1;
}

static void final_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM, "You must specify `--pkt-type'");
}

static void print_pkttype(struct xt_pkttype_info *info)
{
	unsigned int	i;
	
	for (i = 0; i < sizeof(supported_types)/sizeof(struct pkttypes); i++)
	{
		if(supported_types[i].pkttype==info->pkttype)
		{
			printf("%s ", supported_types[i].name);
			return;
		}
	}

	printf("%d ", info->pkttype);	/* in case we didn't find an entry in named-packtes */
}

static void print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	struct xt_pkttype_info *info = (struct xt_pkttype_info *)match->data;
	
	printf("PKTTYPE %s= ", info->invert?"!":"");
	print_pkttype(info);
}

static void save(const void *ip, const struct xt_entry_match *match)
{
	struct xt_pkttype_info *info = (struct xt_pkttype_info *)match->data;
	
	printf("--pkt-type %s", info->invert?"! ":"");
	print_pkttype(info);
}

static struct xtables_match pkttype = {
	.family		= AF_INET,
	.name		= "pkttype",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_pkttype_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_pkttype_info)),
	.help		= &help,
	.parse		= &parse, 
	.final_check	= &final_check, 
	.print		= &print,
	.save		= &save, 
	.extra_opts	= opts
};

static struct xtables_match pkttype6 = {
	.family		= AF_INET6,
	.name		= "pkttype",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_pkttype_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_pkttype_info)),
	.help		= &help,
	.parse		= &parse, 
	.final_check	= &final_check, 
	.print		= &print,
	.save		= &save, 
	.extra_opts	= opts
};

void _init(void)
{
	xtables_register_match(&pkttype);
	xtables_register_match(&pkttype6);
}
