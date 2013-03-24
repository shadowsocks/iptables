/*
 * (C) 2012-2013 by Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2013 by Tomasz Bursztyka <tomasz.bursztyka@linux.intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Sophos Astaro <http://www.sophos.com>
 */

#include <string.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>

#include <xtables.h>

#include "nft-shared.h"

static int nft_ipv6_add(struct nft_rule *r, struct iptables_command_state *cs)
{
	if (cs->fw6.ipv6.iniface[0] != '\0')
		add_iniface(r, cs->fw6.ipv6.iniface, cs->fw6.ipv6.invflags);

	if (cs->fw6.ipv6.outiface[0] != '\0')
		add_outiface(r, cs->fw6.ipv6.outiface, cs->fw6.ipv6.invflags);

	if (!IN6_IS_ADDR_UNSPECIFIED(&cs->fw6.ipv6.src))
		add_addr(r, offsetof(struct ip6_hdr, ip6_src),
			 &cs->fw6.ipv6.src, 16, cs->fw6.ipv6.invflags);

	if (!IN6_IS_ADDR_UNSPECIFIED(&cs->fw6.ipv6.dst))
		add_addr(r, offsetof(struct ip6_hdr, ip6_dst),
			 &cs->fw6.ipv6.dst, 16, cs->fw6.ipv6.invflags);

	if (cs->fw6.ipv6.proto != 0)
		add_proto(r, offsetof(struct ip6_hdr, ip6_nxt), 1,
			  cs->fw6.ipv6.proto, cs->fw6.ipv6.invflags);

	add_compat(r, cs->fw6.ipv6.proto, cs->fw6.ipv6.invflags);

	return cs->fw6.ipv6.flags;
}

static bool nft_ipv6_is_same(const struct iptables_command_state *a,
			     const struct iptables_command_state *b)
{
	if (memcmp(a->fw6.ipv6.src.s6_addr, b->fw6.ipv6.src.s6_addr,
		   sizeof(struct in6_addr)) != 0
	    || memcmp(a->fw6.ipv6.dst.s6_addr, b->fw6.ipv6.dst.s6_addr,
		    sizeof(struct in6_addr)) != 0
	    || a->fw6.ipv6.proto != b->fw6.ipv6.proto
	    || a->fw6.ipv6.flags != b->fw6.ipv6.flags
	    || a->fw6.ipv6.invflags != b->fw6.ipv6.invflags) {
		DEBUGP("different src/dst/proto/flags/invflags\n");
		return false;
	}

	return is_same_interfaces(a->fw6.ipv6.iniface, a->fw6.ipv6.outiface,
				  a->fw6.ipv6.iniface_mask,
				  a->fw6.ipv6.outiface_mask,
				  b->fw6.ipv6.iniface, b->fw6.ipv6.outiface,
				  b->fw6.ipv6.iniface_mask,
				  b->fw6.ipv6.outiface_mask);
}

static void nft_ipv6_print_payload(struct nft_rule_expr *e,
				   struct nft_rule_expr_iter *iter)
{
	uint32_t offset;
	bool inv;

	offset = nft_rule_expr_get_u32(e, NFT_EXPR_PAYLOAD_OFFSET);

	switch (offset) {
	char addr_str[INET6_ADDRSTRLEN];
	struct in6_addr addr;
	uint8_t proto;
	case offsetof(struct ip6_hdr, ip6_src):
		get_cmp_data(iter, &addr, sizeof(addr), &inv);
		inet_ntop(AF_INET6, &addr, addr_str, INET6_ADDRSTRLEN);

		if (inv)
			printf("! -s %s ", addr_str);
		else
			printf("-s %s ", addr_str);

		break;
	case offsetof(struct ip6_hdr, ip6_dst):
		get_cmp_data(iter, &addr, sizeof(addr), &inv);
		inet_ntop(AF_INET6, &addr, addr_str, INET6_ADDRSTRLEN);

		if (inv)
			printf("! -d %s ", addr_str);
		else
			printf("-d %s ", addr_str);

		break;
	case offsetof(struct ip6_hdr, ip6_nxt):
		get_cmp_data(iter, &proto, sizeof(proto), &inv);
		print_proto(proto, inv);
		break;
	default:
		DEBUGP("unknown payload offset %d\n", offset);
		break;
	}
}

static void nft_ipv6_parse_meta(struct nft_rule_expr *e, uint8_t key,
				struct iptables_command_state *cs)
{
	parse_meta(e, key, cs->fw6.ipv6.iniface,
		   cs->fw6.ipv6.iniface_mask, cs->fw6.ipv6.outiface,
		   cs->fw6.ipv6.outiface_mask, &cs->fw6.ipv6.invflags);
}

static void nft_ipv6_parse_payload(struct nft_rule_expr_iter *iter,
				   struct iptables_command_state *cs,
				   uint32_t offset)
{
	switch (offset) {
	struct in6_addr addr;
	uint8_t proto;
	bool inv;

	case offsetof(struct ip6_hdr, ip6_src):
		get_cmp_data(iter, &addr, sizeof(addr), &inv);
		memcpy(cs->fw6.ipv6.src.s6_addr, &addr, sizeof(addr));
		if (inv)
			cs->fw6.ipv6.invflags |= IPT_INV_SRCIP;
		break;
	case offsetof(struct ip6_hdr, ip6_dst):
		get_cmp_data(iter, &addr, sizeof(addr), &inv);
		memcpy(cs->fw6.ipv6.dst.s6_addr, &addr, sizeof(addr));
		if (inv)
			cs->fw6.ipv6.invflags |= IPT_INV_DSTIP;
		break;
	case offsetof(struct ip6_hdr, ip6_nxt):
		get_cmp_data(iter, &proto, sizeof(proto), &inv);
		cs->fw6.ipv6.flags |= IP6T_F_PROTO;
		cs->fw6.ipv6.proto = proto;
		if (inv)
			cs->fw6.ipv6.invflags |= IPT_INV_PROTO;
	default:
		DEBUGP("unknown payload offset %d\n", offset);
		break;
	}
}

static void nft_ipv6_parse_immediate(struct iptables_command_state *cs)
{
	cs->fw6.ipv6.flags |= IPT_F_GOTO;
}

static void print_ipv6_addr(const struct iptables_command_state *cs,
			    unsigned int format)
{
	char buf[BUFSIZ];

	fputc(cs->fw6.ipv6.invflags & IPT_INV_SRCIP ? '!' : ' ', stdout);
	if (IN6_IS_ADDR_UNSPECIFIED(&cs->fw6.ipv6.src)
	    && !(format & FMT_NUMERIC))
		printf(FMT("%-19s ","%s "), "anywhere");
	else {
		if (format & FMT_NUMERIC)
			strcpy(buf,
			       xtables_ip6addr_to_numeric(&cs->fw6.ipv6.src));
		else
			strcpy(buf,
			       xtables_ip6addr_to_anyname(&cs->fw6.ipv6.src));
		strcat(buf, xtables_ip6mask_to_numeric(&cs->fw6.ipv6.smsk));
		printf(FMT("%-19s ","%s "), buf);
	}


	fputc(cs->fw6.ipv6.invflags & IPT_INV_DSTIP ? '!' : ' ', stdout);
	if (IN6_IS_ADDR_UNSPECIFIED(&cs->fw6.ipv6.dst)
	    && !(format & FMT_NUMERIC))
		printf(FMT("%-19s ","-> %s"), "anywhere");
	else {
		if (format & FMT_NUMERIC)
			strcpy(buf,
			       xtables_ip6addr_to_numeric(&cs->fw6.ipv6.dst));
		else
			strcpy(buf,
			       xtables_ip6addr_to_anyname(&cs->fw6.ipv6.dst));
		strcat(buf, xtables_ip6mask_to_numeric(&cs->fw6.ipv6.dmsk));
		printf(FMT("%-19s ","-> %s"), buf);
	}
}

static uint8_t nft_ipv6_print_firewall(const struct iptables_command_state *cs,
				       const char *targname, unsigned int num,
				       unsigned int format)
{
	print_firewall_details(cs, targname, cs->fw6.ipv6.flags,
			       cs->fw6.ipv6.invflags, cs->fw6.ipv6.proto,
			       cs->fw6.ipv6.iniface, cs->fw6.ipv6.outiface,
			       num, format);

	print_ipv6_addr(cs, format);

	return cs->fw6.ipv6.flags;
}

struct nft_family_ops nft_family_ops_ipv6 = {
	.add			= nft_ipv6_add,
	.is_same		= nft_ipv6_is_same,
	.print_payload		= nft_ipv6_print_payload,
	.parse_meta		= nft_ipv6_parse_meta,
	.parse_payload		= nft_ipv6_parse_payload,
	.parse_immediate	= nft_ipv6_parse_immediate,
	.print_firewall		= nft_ipv6_print_firewall,
};
