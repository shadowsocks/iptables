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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include <xtables.h>

#include <linux/netfilter/nf_tables.h>

#include "nft-shared.h"

static int nft_ipv4_add(struct nft_rule *r, void *data)
{
	struct iptables_command_state *cs = data;
	uint32_t op;

	if (cs->fw.ip.iniface[0] != '\0')
		add_iniface(r, cs->fw.ip.iniface, cs->fw.ip.invflags);

	if (cs->fw.ip.outiface[0] != '\0')
		add_outiface(r, cs->fw.ip.outiface, cs->fw.ip.invflags);

	if (cs->fw.ip.src.s_addr != 0)
		add_addr(r, offsetof(struct iphdr, saddr),
			 &cs->fw.ip.src.s_addr, 4, cs->fw.ip.invflags);

	if (cs->fw.ip.dst.s_addr != 0)
		add_addr(r, offsetof(struct iphdr, daddr),
			 &cs->fw.ip.dst.s_addr, 4, cs->fw.ip.invflags);

	if (cs->fw.ip.proto != 0)
		add_proto(r, offsetof(struct iphdr, protocol), 1,
			  cs->fw.ip.proto, cs->fw.ip.invflags);

	if (cs->fw.ip.flags & IPT_F_FRAG) {
		add_payload(r, offsetof(struct iphdr, frag_off), 2);
		/* get the 13 bits that contain the fragment offset */
		add_bitwise_u16(r, 0x1fff, !0x1fff);

		/* if offset is non-zero, this is a fragment */
		if (cs->fw.ip.invflags & IPT_INV_FRAG)
			op = NFT_CMP_EQ;
		else
			op = NFT_CMP_NEQ;

		add_cmp_u16(r, 0, op);
	}

	add_compat(r, cs->fw.ip.proto, cs->fw.ip.invflags);

	return cs->fw.ip.flags;
}

static bool nft_ipv4_is_same(const struct iptables_command_state *a,
			     const struct iptables_command_state *b)
{
	if (a->fw.ip.src.s_addr != b->fw.ip.src.s_addr
	    || a->fw.ip.dst.s_addr != b->fw.ip.dst.s_addr
	    || a->fw.ip.smsk.s_addr != b->fw.ip.smsk.s_addr
	    || a->fw.ip.dmsk.s_addr != b->fw.ip.dmsk.s_addr
	    || a->fw.ip.proto != b->fw.ip.proto
	    || a->fw.ip.flags != b->fw.ip.flags
	    || a->fw.ip.invflags != b->fw.ip.invflags) {
		DEBUGP("different src/dst/proto/flags/invflags\n");
		return false;
	}

	return is_same_interfaces(a->fw.ip.iniface, a->fw.ip.outiface,
				  a->fw.ip.iniface_mask, a->fw.ip.outiface_mask,
				  b->fw.ip.iniface, b->fw.ip.outiface,
				  b->fw.ip.iniface_mask, b->fw.ip.outiface_mask);
}

static void get_frag(struct nft_rule_expr_iter *iter, bool *inv)
{
	struct nft_rule_expr *e;
	const char *name;
	uint8_t op;

	e = nft_rule_expr_iter_next(iter);
	if (e == NULL)
		return;

	/* we assume correct mask and xor */
	name = nft_rule_expr_get_str(e, NFT_RULE_EXPR_ATTR_NAME);
	if (strcmp(name, "bitwise") != 0) {
		DEBUGP("skipping no bitwise after payload\n");
		return;
	}

	/* Now check for cmp */
	e = nft_rule_expr_iter_next(iter);
	if (e == NULL)
		return;

	/* we assume correct data */
	name = nft_rule_expr_get_str(e, NFT_RULE_EXPR_ATTR_NAME);
	if (strcmp(name, "cmp") != 0) {
		DEBUGP("skipping no cmp after payload\n");
		return;
	}

	op = nft_rule_expr_get_u8(e, NFT_EXPR_CMP_OP);
	if (op == NFT_CMP_EQ)
		*inv = true;
	else
		*inv = false;
}

static const char *mask_to_str(uint32_t mask)
{
	static char mask_str[sizeof("255.255.255.255")];
	uint32_t bits, hmask = ntohl(mask);
	struct in_addr mask_addr = {
		.s_addr = mask,
	};
	int i;

	if (mask == 0xFFFFFFFFU) {
		sprintf(mask_str, "32");
		return mask_str;
	}

	i    = 32;
	bits = 0xFFFFFFFEU;
	while (--i >= 0 && hmask != bits)
		bits <<= 1;
	if (i >= 0)
		sprintf(mask_str, "%u", i);
	else
		sprintf(mask_str, "%s", inet_ntoa(mask_addr));

	return mask_str;
}

static void nft_ipv4_parse_meta(struct nft_rule_expr *e, uint8_t key,
				void *data)
{
	struct iptables_command_state *cs = data;

	parse_meta(e, key, cs->fw.ip.iniface, cs->fw.ip.iniface_mask,
		   cs->fw.ip.outiface, cs->fw.ip.outiface_mask,
		   &cs->fw.ip.invflags);
}

static void nft_ipv4_parse_payload(struct nft_rule_expr_iter *iter,
				   uint32_t offset, void *data)
{
	struct iptables_command_state *cs = data;

	switch(offset) {
	struct in_addr addr;
	uint8_t proto;
	bool inv;

	case offsetof(struct iphdr, saddr):
		get_cmp_data(iter, &addr, sizeof(addr), &inv);
		cs->fw.ip.src.s_addr = addr.s_addr;
		cs->fw.ip.smsk.s_addr = 0xffffffff;
		if (inv)
			cs->fw.ip.invflags |= IPT_INV_SRCIP;
		break;
	case offsetof(struct iphdr, daddr):
		get_cmp_data(iter, &addr, sizeof(addr), &inv);
		cs->fw.ip.dst.s_addr = addr.s_addr;
		cs->fw.ip.dmsk.s_addr = 0xffffffff;
		if (inv)
			cs->fw.ip.invflags |= IPT_INV_DSTIP;
		break;
	case offsetof(struct iphdr, protocol):
		get_cmp_data(iter, &proto, sizeof(proto), &inv);
		cs->fw.ip.proto = proto;
		if (inv)
			cs->fw.ip.invflags |= IPT_INV_PROTO;
		break;
	case offsetof(struct iphdr, frag_off):
		cs->fw.ip.flags |= IPT_F_FRAG;
		get_frag(iter, &inv);
		if (inv)
			cs->fw.ip.invflags |= IPT_INV_FRAG;
		break;
	default:
		DEBUGP("unknown payload offset %d\n", offset);
		break;
	}
}

static void nft_ipv4_parse_immediate(const char *jumpto, bool nft_goto,
				     void *data)
{
	struct iptables_command_state *cs = data;

	cs->jumpto = jumpto;

	if (nft_goto)
		cs->fw.ip.flags |= IPT_F_GOTO;
}

static void print_ipv4_addr(const struct iptables_command_state *cs,
			    unsigned int format)
{
	char buf[BUFSIZ];

	fputc(cs->fw.ip.invflags & IPT_INV_SRCIP ? '!' : ' ', stdout);
	if (cs->fw.ip.smsk.s_addr == 0L && !(format & FMT_NUMERIC))
		printf(FMT("%-19s ","%s "), "anywhere");
	else {
		if (format & FMT_NUMERIC)
			strcpy(buf, xtables_ipaddr_to_numeric(&cs->fw.ip.src));
		else
			strcpy(buf, xtables_ipaddr_to_anyname(&cs->fw.ip.src));
		strcat(buf, xtables_ipmask_to_numeric(&cs->fw.ip.smsk));
		printf(FMT("%-19s ","%s "), buf);
	}

	fputc(cs->fw.ip.invflags & IPT_INV_DSTIP ? '!' : ' ', stdout);
	if (cs->fw.ip.dmsk.s_addr == 0L && !(format & FMT_NUMERIC))
		printf(FMT("%-19s ","-> %s"), "anywhere");
	else {
		if (format & FMT_NUMERIC)
			strcpy(buf, xtables_ipaddr_to_numeric(&cs->fw.ip.dst));
		else
			strcpy(buf, xtables_ipaddr_to_anyname(&cs->fw.ip.dst));
		strcat(buf, xtables_ipmask_to_numeric(&cs->fw.ip.dmsk));
		printf(FMT("%-19s ","-> %s"), buf);
	}
}

static void print_fragment(unsigned int flags, unsigned int invflags,
			   unsigned int format)
{
	if (!(format & FMT_OPTIONS))
		return;

	if (format & FMT_NOTABLE)
		fputs("opt ", stdout);
	fputc(invflags & IPT_INV_FRAG ? '!' : '-', stdout);
	fputc(flags & IPT_F_FRAG ? 'f' : '-', stdout);
	fputc(' ', stdout);
}

static void nft_ipv4_print_firewall(struct nft_rule *r, unsigned int num,
				    unsigned int format)
{
	struct iptables_command_state cs = {};

	nft_rule_to_iptables_command_state(r, &cs);

	print_firewall_details(&cs, cs.jumpto, cs.fw.ip.flags,
			       cs.fw.ip.invflags, cs.fw.ip.proto,
			       num, format);
	print_fragment(cs.fw.ip.flags, cs.fw.ip.invflags, format);
	print_ifaces(cs.fw.ip.iniface, cs.fw.ip.outiface, cs.fw.ip.invflags,
		     format);
	print_ipv4_addr(&cs, format);

	if (format & FMT_NOTABLE)
		fputs("  ", stdout);

#ifdef IPT_F_GOTO
	if (cs.fw.ip.flags & IPT_F_GOTO)
		printf("[goto] ");
#endif

	print_matches_and_target(&cs, format);

	if (!(format & FMT_NONEWLINE))
		fputc('\n', stdout);
}

static void save_ipv4_addr(char letter, const struct in_addr *addr,
			   uint32_t mask, int invert)
{
	if (!mask && !invert && !addr->s_addr)
		return;

	printf("%s-%c %s/%s ", invert ? "! " : "", letter, inet_ntoa(*addr),
	       mask_to_str(mask));
}

static uint8_t nft_ipv4_save_firewall(const struct iptables_command_state *cs,
				      unsigned int format)
{
	save_firewall_details(cs, cs->fw.ip.invflags, cs->fw.ip.proto,
			      cs->fw.ip.iniface, cs->fw.ip.iniface_mask,
			      cs->fw.ip.outiface, cs->fw.ip.outiface_mask,
			      format);

	if (cs->fw.ip.flags & IPT_F_FRAG) {
		if (cs->fw.ip.invflags & IPT_INV_FRAG)
			printf("! ");
		printf("-f ");
	}

	save_ipv4_addr('s', &cs->fw.ip.src, cs->fw.ip.smsk.s_addr,
		       cs->fw.ip.invflags & IPT_INV_SRCIP);
	save_ipv4_addr('d', &cs->fw.ip.dst, cs->fw.ip.dmsk.s_addr,
		       cs->fw.ip.invflags & IPT_INV_DSTIP);

	return cs->fw.ip.flags;
}

static void nft_ipv4_post_parse(int command,
				struct iptables_command_state *cs,
				struct xtables_args *args)
{
	cs->fw.ip.proto = args->proto;
	cs->fw.ip.invflags = args->invflags;
	cs->fw.ip.flags = args->flags;

	strncpy(cs->fw.ip.iniface, args->iniface, IFNAMSIZ);
	memcpy(cs->fw.ip.iniface_mask,
	       args->iniface_mask, IFNAMSIZ*sizeof(unsigned char));

	strncpy(cs->fw.ip.outiface, args->outiface, IFNAMSIZ);
	memcpy(cs->fw.ip.outiface_mask,
	       args->outiface_mask, IFNAMSIZ*sizeof(unsigned char));

	if (args->goto_set)
		cs->fw.ip.flags |= IPT_F_GOTO;

	cs->counters.pcnt = args->pcnt_cnt;
	cs->counters.bcnt = args->bcnt_cnt;

	if (command & (CMD_REPLACE | CMD_INSERT |
			CMD_DELETE | CMD_APPEND | CMD_CHECK)) {
		if (!(cs->options & OPT_DESTINATION))
			args->dhostnetworkmask = "0.0.0.0/0";
		if (!(cs->options & OPT_SOURCE))
			args->shostnetworkmask = "0.0.0.0/0";
	}

	if (args->shostnetworkmask)
		xtables_ipparse_multiple(args->shostnetworkmask,
					 &args->s.addr.v4, &args->s.mask.v4,
					 &args->s.naddrs);
	if (args->dhostnetworkmask)
		xtables_ipparse_multiple(args->dhostnetworkmask,
					 &args->d.addr.v4, &args->d.mask.v4,
					 &args->d.naddrs);

	if ((args->s.naddrs > 1 || args->d.naddrs > 1) &&
	    (cs->fw.ip.invflags & (IPT_INV_SRCIP | IPT_INV_DSTIP)))
		xtables_error(PARAMETER_PROBLEM,
			      "! not allowed with multiple"
			      " source or destination IP addresses");
}

static void nft_ipv4_parse_target(struct xtables_target *t, void *data)
{
	struct iptables_command_state *cs = data;

	cs->target = t;
}

struct nft_family_ops nft_family_ops_ipv4 = {
	.add			= nft_ipv4_add,
	.is_same		= nft_ipv4_is_same,
	.parse_meta		= nft_ipv4_parse_meta,
	.parse_payload		= nft_ipv4_parse_payload,
	.parse_immediate	= nft_ipv4_parse_immediate,
	.print_firewall		= nft_ipv4_print_firewall,
	.save_firewall		= nft_ipv4_save_firewall,
	.post_parse		= nft_ipv4_post_parse,
	.parse_target		= nft_ipv4_parse_target,
};
