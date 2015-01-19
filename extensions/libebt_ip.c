/* ebt_ip
 *
 * Authors:
 * Bart De Schuymer <bdschuym@pandora.be>
 *
 * Changes:
 *    added ip-sport and ip-dport; parsing of port arguments is
 *    based on code from iptables-1.2.7a
 *    Innominate Security Technologies AG <mhopf@innominate.com>
 *    September, 2002
 *
 * Adapted by Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>
 * to use libxtables for ebtables-compat in 2015.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <netdb.h>
#include <xtables.h>
#include <linux/netfilter_bridge/ebt_ip.h>

#define IP_SOURCE	'1'
#define IP_DEST		'2'
#define IP_EBT_TOS	'3' /* include/bits/in.h seems to already define IP_TOS */
#define IP_PROTO	'4'
#define IP_SPORT	'5'
#define IP_DPORT	'6'

static const struct option brip_opts[] = {
	{ .name = "ip-source",		.has_arg = true, .val = IP_SOURCE },
	{ .name = "ip-src",		.has_arg = true, .val = IP_SOURCE },
	{ .name = "ip-destination",	.has_arg = true, .val = IP_DEST },
	{ .name = "ip-dst",		.has_arg = true, .val = IP_DEST },
	{ .name = "ip-tos",		.has_arg = true, .val = IP_EBT_TOS },
	{ .name = "ip-protocol",	.has_arg = true, .val = IP_PROTO },
	{ .name = "ip-proto",		.has_arg = true, .val = IP_PROTO },
	{ .name = "ip-source-port",	.has_arg = true, .val = IP_SPORT },
	{ .name = "ip-sport",		.has_arg = true, .val = IP_SPORT },
	{ .name = "ip-destination-port",.has_arg = true, .val = IP_DPORT },
	{ .name = "ip-dport",		.has_arg = true, .val = IP_DPORT },
	XT_GETOPT_TABLEEND,
};

static void brip_print_help(void)
{
	printf(
"ip options:\n"
"--ip-src    [!] address[/mask]: ip source specification\n"
"--ip-dst    [!] address[/mask]: ip destination specification\n"
"--ip-tos    [!] tos           : ip tos specification\n"
"--ip-proto  [!] protocol      : ip protocol specification\n"
"--ip-sport  [!] port[:port]   : tcp/udp source port or port range\n"
"--ip-dport  [!] port[:port]   : tcp/udp destination port or port range\n");
}

static void brip_init(struct xt_entry_match *match)
{
	struct ebt_ip_info *info = (struct ebt_ip_info *)match->data;

	info->invflags = 0;
	info->bitmask = 0;
}

static void
parse_port_range(const char *protocol, const char *portstring, uint16_t *ports)
{
	char *buffer;
	char *cp;

	buffer = strdup(portstring);
	if ((cp = strchr(buffer, ':')) == NULL)
		ports[0] = ports[1] = xtables_parse_port(buffer, NULL);
	else {
		*cp = '\0';
		cp++;

		ports[0] = buffer[0] ? xtables_parse_port(buffer, NULL) : 0;
		ports[1] = cp[0] ? xtables_parse_port(cp, NULL) : 0xFFFF;

		if (ports[0] > ports[1])
			xtables_error(PARAMETER_PROBLEM,
				      "invalid portrange (min > max)");
	}
	free(buffer);
}

/* original code from ebtables: useful_functions.c */
static int undot_ip(char *ip, unsigned char *ip2)
{
	char *p, *q, *end;
	long int onebyte;
	int i;
	char buf[20];

	strncpy(buf, ip, sizeof(buf) - 1);

	p = buf;
	for (i = 0; i < 3; i++) {
		if ((q = strchr(p, '.')) == NULL)
			return -1;
		*q = '\0';
		onebyte = strtol(p, &end, 10);
		if (*end != '\0' || onebyte > 255 || onebyte < 0)
			return -1;
		ip2[i] = (unsigned char)onebyte;
		p = q + 1;
	}

	onebyte = strtol(p, &end, 10);
	if (*end != '\0' || onebyte > 255 || onebyte < 0)
		return -1;
	ip2[3] = (unsigned char)onebyte;

	return 0;
}

static int ip_mask(char *mask, unsigned char *mask2)
{
	char *end;
	long int bits;
	uint32_t mask22;

	if (undot_ip(mask, mask2)) {
		/* not the /a.b.c.e format, maybe the /x format */
		bits = strtol(mask, &end, 10);
		if (*end != '\0' || bits > 32 || bits < 0)
			return -1;
		if (bits != 0) {
			mask22 = htonl(0xFFFFFFFF << (32 - bits));
			memcpy(mask2, &mask22, 4);
		} else {
			mask22 = 0xFFFFFFFF;
			memcpy(mask2, &mask22, 4);
		}
	}
	return 0;
}

static void ebt_parse_ip_address(char *address, uint32_t *addr, uint32_t *msk)
{
	char *p;

	/* first the mask */
	if ((p = strrchr(address, '/')) != NULL) {
		*p = '\0';
		if (ip_mask(p + 1, (unsigned char *)msk)) {
			xtables_error(PARAMETER_PROBLEM,
				      "Problem with the IP mask '%s'", p + 1);
			return;
		}
	} else
		*msk = 0xFFFFFFFF;

	if (undot_ip(address, (unsigned char *)addr)) {
		xtables_error(PARAMETER_PROBLEM,
			      "Problem with the IP address '%s'", address);
		return;
	}
	*addr = *addr & *msk;
}

static int
brip_parse(int c, char **argv, int invert, unsigned int *flags,
	   const void *entry, struct xt_entry_match **match)
{
	struct ebt_ip_info *info = (struct ebt_ip_info *)(*match)->data;

	switch (c) {
	case IP_SOURCE:
		if (invert)
			info->invflags |= EBT_IP_SOURCE;
		ebt_parse_ip_address(optarg, &info->saddr, &info->smsk);
		info->bitmask |= EBT_IP_SOURCE;
		break;
	case IP_DEST:
		if (invert)
			info->invflags |= EBT_IP_DEST;
		ebt_parse_ip_address(optarg, &info->daddr, &info->dmsk);
		info->bitmask |= EBT_IP_DEST;
		break;
	case IP_SPORT:
		if (invert)
			info->invflags |= EBT_IP_SPORT;
		parse_port_range(NULL, optarg, info->sport);
		info->bitmask |= EBT_IP_SPORT;
		break;
	case IP_DPORT:
		if (invert)
			info->invflags |= EBT_IP_DPORT;
		parse_port_range(NULL, optarg, info->dport);
		info->bitmask |= EBT_IP_DPORT;
		break;
	case IP_EBT_TOS:
		if (invert)
			info->invflags |= EBT_IP_TOS;
		if (!xtables_strtoul(optarg, NULL, (uintmax_t *)&info->tos,
				     0, 255))
			xtables_error(PARAMETER_PROBLEM,
				      "Problem with specified IP tos");
		info->bitmask |= EBT_IP_TOS;
		break;
	case IP_PROTO:
		if (invert)
			info->invflags |= EBT_IP_PROTO;
		info->protocol = xtables_parse_protocol(optarg);
		if (info->protocol == -1)
			xtables_error(PARAMETER_PROBLEM,
				      "Unknown specified IP protocol - %s",
				      optarg);
		info->bitmask |= EBT_IP_PROTO;
		break;
	default:
		return 0;
	}
	return 1;
}

static void brip_final_check(unsigned int flags)
{
/*	struct ebt_ip_info *ipinfo = (struct ebt_ip_info *)match->data;

	if (entry->ethproto != ETH_P_IP || entry->invflags & EBT_IPROTO) {
		ebt_print_error("For IP filtering the protocol must be "
		            "specified as IPv4");
	} else if (info->bitmask & (EBT_IP_SPORT|EBT_IP_DPORT) &&
		(!(info->bitmask & EBT_IP_PROTO) ||
		info->invflags & EBT_IP_PROTO ||
		(info->protocol!=IPPROTO_TCP &&
		 info->protocol!=IPPROTO_UDP &&
		 info->protocol!=IPPROTO_SCTP &&
		 info->protocol!=IPPROTO_DCCP)))
		ebt_print_error("For port filtering the IP protocol must be "
				"either 6 (tcp), 17 (udp), 33 (dccp) or "
				"132 (sctp)");
*/
	if (!flags)
		xtables_error(PARAMETER_PROBLEM,
			      "You must specify proper arguments");
}

static void print_port_range(uint16_t *ports)
{
	if (ports[0] == ports[1])
		printf("%d ", ports[0]);
	else
		printf("%d:%d ", ports[0], ports[1]);
}

static void brip_print(const void *ip, const struct xt_entry_match *match,
		       int numeric)
{
	struct ebt_ip_info *info = (struct ebt_ip_info *)match->data;
	struct in_addr *addrp, *maskp;

	if (info->bitmask & EBT_IP_SOURCE) {
		printf("--ip-src ");
		if (info->invflags & EBT_IP_SOURCE)
			printf("! ");
		addrp = (struct in_addr *)&info->saddr;
		maskp = (struct in_addr *)&info->smsk;
		printf("%s%s ", xtables_ipaddr_to_numeric(addrp),
		       xtables_ipmask_to_numeric(maskp));
	}
	if (info->bitmask & EBT_IP_DEST) {
		printf("--ip-dst ");
		if (info->invflags & EBT_IP_DEST)
			printf("! ");
		addrp = (struct in_addr *)&info->daddr;
		maskp = (struct in_addr *)&info->dmsk;
		printf("%s%s ", xtables_ipaddr_to_numeric(addrp),
		       xtables_ipmask_to_numeric(maskp));
	}
	if (info->bitmask & EBT_IP_TOS) {
		printf("--ip-tos ");
		if (info->invflags & EBT_IP_TOS)
			printf("! ");
		printf("0x%02X ", info->tos);
	}
	if (info->bitmask & EBT_IP_PROTO) {
		struct protoent *pe;

		printf("--ip-proto ");
		if (info->invflags & EBT_IP_PROTO)
			printf("! ");
		pe = getprotobynumber(info->protocol);
		if (pe == NULL) {
			printf("%d ", info->protocol);
		} else {
			printf("%s ", pe->p_name);
		}
	}
	if (info->bitmask & EBT_IP_SPORT) {
		printf("--ip-sport ");
		if (info->invflags & EBT_IP_SPORT)
			printf("! ");
		print_port_range(info->sport);
	}
	if (info->bitmask & EBT_IP_DPORT) {
		printf("--ip-dport ");
		if (info->invflags & EBT_IP_DPORT)
			printf("! ");
		print_port_range(info->dport);
	}
}

static struct xtables_match brip_match = {
	.name		= "ip",
	.revision	= 0,
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_BRIDGE,
	.size		= XT_ALIGN(sizeof(struct ebt_ip_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct ebt_ip_info)),
	.init		= brip_init,
	.help		= brip_print_help,
	.parse		= brip_parse,
	.final_check	= brip_final_check,
	.print		= brip_print,
	.extra_opts	= brip_opts,
};

void _init(void)
{
	xtables_register_match(&brip_match);
}
