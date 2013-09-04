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

static void nft_ipv6_parse_meta(struct nft_rule_expr *e, uint8_t key,
				void *data)
{
	struct iptables_command_state *cs = data;

	parse_meta(e, key, cs->fw6.ipv6.iniface,
		   cs->fw6.ipv6.iniface_mask, cs->fw6.ipv6.outiface,
		   cs->fw6.ipv6.outiface_mask, &cs->fw6.ipv6.invflags);
}

static void nft_ipv6_parse_payload(struct nft_rule_expr_iter *iter,
				   uint32_t offset, void *data)
{
	struct iptables_command_state *cs = data;
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

static void nft_ipv6_parse_immediate(const char *jumpto, bool nft_goto,
				     void *data)
{
	struct iptables_command_state *cs = data;

	cs->jumpto = jumpto;

	if (nft_goto)
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

static void nft_ipv6_print_firewall(struct nft_rule *r, unsigned int num,
				    unsigned int format)
{
	struct iptables_command_state cs = {};

	nft_rule_to_iptables_command_state(r, &cs);

	print_firewall_details(&cs, cs.jumpto, cs.fw6.ipv6.flags,
			       cs.fw6.ipv6.invflags, cs.fw6.ipv6.proto,
			       num, format);
	print_ifaces(cs.fw6.ipv6.iniface, cs.fw6.ipv6.outiface,
		     cs.fw6.ipv6.invflags, format);
	print_ipv6_addr(&cs, format);

	if (format & FMT_NOTABLE)
		fputs("  ", stdout);

#ifdef IPT_F_GOTO
	if (cs.fw6.ipv6.flags & IPT_F_GOTO)
		printf("[goto] ");
#endif

	print_matches_and_target(&cs, format);

	if (!(format & FMT_NONEWLINE))
		fputc('\n', stdout);
}

static void save_ipv6_addr(char letter, const struct in6_addr *addr,
			   int invert)
{
	char addr_str[INET6_ADDRSTRLEN];

	if (!invert && IN6_IS_ADDR_UNSPECIFIED(addr))
		return;

	inet_ntop(AF_INET6, addr, addr_str, INET6_ADDRSTRLEN);
	printf("%s-%c %s ", invert ? "! " : "", letter, addr_str);
}

static uint8_t nft_ipv6_save_firewall(const struct iptables_command_state *cs,
				      unsigned int format)
{
	save_firewall_details(cs, cs->fw6.ipv6.invflags, cs->fw6.ipv6.proto,
			      cs->fw6.ipv6.iniface, cs->fw6.ipv6.iniface_mask,
			      cs->fw6.ipv6.outiface, cs->fw6.ipv6.outiface_mask,
			      format);

	save_ipv6_addr('s', &cs->fw6.ipv6.src,
		       cs->fw6.ipv6.invflags & IPT_INV_SRCIP);
	save_ipv6_addr('d', &cs->fw6.ipv6.dst,
		       cs->fw6.ipv6.invflags & IPT_INV_DSTIP);

	return cs->fw6.ipv6.flags;
}

/* These are invalid numbers as upper layer protocol */
static int is_exthdr(uint16_t proto)
{
	return (proto == IPPROTO_ROUTING ||
		proto == IPPROTO_FRAGMENT ||
		proto == IPPROTO_AH ||
		proto == IPPROTO_DSTOPTS);
}

static void nft_ipv6_post_parse(int command, struct iptables_command_state *cs,
				struct xtables_args *args)
{
	if (args->proto != 0)
		args->flags |= IP6T_F_PROTO;

	cs->fw6.ipv6.proto = args->proto;
	cs->fw6.ipv6.invflags = args->invflags;
	cs->fw6.ipv6.flags = args->flags;

	if (is_exthdr(cs->fw6.ipv6.proto)
	    && (cs->fw6.ipv6.invflags & XT_INV_PROTO) == 0)
		fprintf(stderr,
			"Warning: never matched protocol: %s. "
			"use extension match instead.\n",
			cs->protocol);

	strncpy(cs->fw6.ipv6.iniface, args->iniface, IFNAMSIZ);
	memcpy(cs->fw6.ipv6.iniface_mask,
	       args->iniface_mask, IFNAMSIZ*sizeof(unsigned char));

	strncpy(cs->fw6.ipv6.outiface, args->outiface, IFNAMSIZ);
	memcpy(cs->fw6.ipv6.outiface_mask,
	       args->outiface_mask, IFNAMSIZ*sizeof(unsigned char));

	if (args->goto_set)
		cs->fw6.ipv6.flags |= IP6T_F_GOTO;

	cs->fw6.counters.pcnt = args->pcnt_cnt;
	cs->fw6.counters.bcnt = args->bcnt_cnt;

	if (command & (CMD_REPLACE | CMD_INSERT |
			CMD_DELETE | CMD_APPEND | CMD_CHECK)) {
		if (!(cs->options & OPT_DESTINATION))
			args->dhostnetworkmask = "::0/0";
		if (!(cs->options & OPT_SOURCE))
			args->shostnetworkmask = "::0/0";
	}

	if (args->shostnetworkmask)
		xtables_ip6parse_multiple(args->shostnetworkmask,
					  &args->s.addr.v6,
					  &args->s.mask.v6,
					  &args->s.naddrs);
	if (args->dhostnetworkmask)
		xtables_ip6parse_multiple(args->dhostnetworkmask,
					  &args->d.addr.v6,
					  &args->d.mask.v6,
					  &args->d.naddrs);

	if ((args->s.naddrs > 1 || args->d.naddrs > 1) &&
	    (cs->fw6.ipv6.invflags & (IP6T_INV_SRCIP | IP6T_INV_DSTIP)))
		xtables_error(PARAMETER_PROBLEM,
			      "! not allowed with multiple"
			      " source or destination IP addresses");
}

static void nft_ipv6_parse_target(struct xtables_target *t, void *data)
{
	struct iptables_command_state *cs = data;

	cs->target = t;
}

struct nft_family_ops nft_family_ops_ipv6 = {
	.add			= nft_ipv6_add,
	.is_same		= nft_ipv6_is_same,
	.parse_meta		= nft_ipv6_parse_meta,
	.parse_payload		= nft_ipv6_parse_payload,
	.parse_immediate	= nft_ipv6_parse_immediate,
	.print_firewall		= nft_ipv6_print_firewall,
	.save_firewall		= nft_ipv6_save_firewall,
	.post_parse		= nft_ipv6_post_parse,
	.parse_target		= nft_ipv6_parse_target,
};
