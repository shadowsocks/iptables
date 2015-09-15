/*
 * (C) 2014 by Giuseppe Longo <giuseppelng@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h>
#include <inttypes.h>

#include <xtables.h>
#include <libiptc/libxtc.h>
#include <linux/netfilter/nf_tables.h>
#include <ebtables/ethernetdb.h>

#include "nft-shared.h"
#include "nft-bridge.h"
#include "nft.h"

void ebt_cs_clean(struct ebtables_command_state *cs)
{
	struct ebt_match *m, *nm;

	xtables_rule_matches_free(&cs->matches);

	for (m = cs->match_list; m;) {
		nm = m->next;
		if (!m->ismatch)
			free(m->u.watcher->t);
		free(m);
		m = nm;
	}
}

/* 0: default, print only 2 digits if necessary
 * 2: always print 2 digits, a printed mac address
 * then always has the same length
 */
int ebt_printstyle_mac;

static void ebt_print_mac(const unsigned char *mac)
{
	if (ebt_printstyle_mac == 2) {
		int j;
		for (j = 0; j < ETH_ALEN; j++)
			printf("%02x%s", mac[j],
				(j==ETH_ALEN-1) ? "" : ":");
	} else
		printf("%s", ether_ntoa((struct ether_addr *) mac));
}

/* Put the mac address into 6 (ETH_ALEN) bytes returns 0 on success. */
static void ebt_print_mac_and_mask(const unsigned char *mac, const unsigned char *mask)
{
	char hlpmsk[6] = {};

	if (!memcmp(mac, eb_mac_type_unicast, 6) &&
	    !memcmp(mask, eb_msk_type_unicast, 6))
		printf("Unicast");
	else if (!memcmp(mac, eb_mac_type_multicast, 6) &&
	         !memcmp(mask, eb_msk_type_multicast, 6))
		printf("Multicast");
	else if (!memcmp(mac, eb_mac_type_broadcast, 6) &&
	         !memcmp(mask, eb_msk_type_broadcast, 6))
		printf("Broadcast");
	else if (!memcmp(mac, eb_mac_type_bridge_group, 6) &&
	         !memcmp(mask, eb_msk_type_bridge_group, 6))
		printf("BGA");
	else {
		ebt_print_mac(mac);
		if (memcmp(mask, hlpmsk, 6)) {
			printf("/");
			ebt_print_mac(mask);
		}
	}
}

static uint16_t ipt_to_ebt_flags(uint8_t invflags)
{
	uint16_t result = 0;

	if (invflags & IPT_INV_VIA_IN)
		result |= EBT_IIN;

	if (invflags & IPT_INV_VIA_OUT)
		result |= EBT_IOUT;

	if (invflags & IPT_INV_PROTO)
		result |= EBT_IPROTO;

	return result;
}

static void add_logical_iniface(struct nftnl_rule *r, char *iface, uint32_t op)
{
	int iface_len;

	iface_len = strlen(iface);

	add_meta(r, NFT_META_BRI_IIFNAME);
	if (iface[iface_len - 1] == '+')
		add_cmp_ptr(r, op, iface, iface_len - 1);
	else
		add_cmp_ptr(r, op, iface, iface_len + 1);
}

static void add_logical_outiface(struct nftnl_rule *r, char *iface, uint32_t op)
{
	int iface_len;

	iface_len = strlen(iface);

	add_meta(r, NFT_META_BRI_OIFNAME);
	if (iface[iface_len - 1] == '+')
		add_cmp_ptr(r, op, iface, iface_len - 1);
	else
		add_cmp_ptr(r, op, iface, iface_len + 1);
}

/* TODO: Use generic add_action() once we convert this to use
 * iptables_command_state.
 */
static int _add_action(struct nftnl_rule *r, struct ebtables_command_state *cs)
{
	int ret = 0;

	if (cs->jumpto == NULL || strcmp(cs->jumpto, "CONTINUE") == 0)
		return 0;

	/* If no target at all, add nothing (default to continue) */
	if (cs->target != NULL) {
		/* Standard target? */
		if (strcmp(cs->jumpto, XTC_LABEL_ACCEPT) == 0)
			ret = add_verdict(r, NF_ACCEPT);
		else if (strcmp(cs->jumpto, XTC_LABEL_DROP) == 0)
			ret = add_verdict(r, NF_DROP);
		else if (strcmp(cs->jumpto, XTC_LABEL_RETURN) == 0)
			ret = add_verdict(r, NFT_RETURN);
		else
			ret = add_target(r, cs->target->t);
	} else if (strlen(cs->jumpto) > 0) {
		/* Not standard, then it's a jump to chain */
		ret = add_jumpto(r, cs->jumpto, NFT_JUMP);
	}

	return ret;
}

static int nft_bridge_add(struct nftnl_rule *r, void *data)
{
	struct ebtables_command_state *cs = data;
	struct ebt_match *iter;
	struct ebt_entry *fw = &cs->fw;
	uint32_t op;
	char *addr;

	if (fw->in[0] != '\0') {
		op = nft_invflags2cmp(fw->invflags, EBT_IIN);
		add_iniface(r, fw->in, op);
	}

	if (fw->out[0] != '\0') {
		op = nft_invflags2cmp(fw->invflags, EBT_IOUT);
		add_outiface(r, fw->out, op);
	}

	if (fw->logical_in[0] != '\0') {
		op = nft_invflags2cmp(fw->invflags, EBT_ILOGICALIN);
		add_logical_iniface(r, fw->logical_in, op);
	}

	if (fw->logical_out[0] != '\0') {
		op = nft_invflags2cmp(fw->invflags, EBT_ILOGICALOUT);
		add_logical_outiface(r, fw->logical_out, op);
	}

	addr = ether_ntoa((struct ether_addr *) fw->sourcemac);
	if (strcmp(addr, "0:0:0:0:0:0") != 0) {
		op = nft_invflags2cmp(fw->invflags, EBT_ISOURCE);
		add_payload(r, offsetof(struct ethhdr, h_source), 6,
			    NFT_PAYLOAD_LL_HEADER);
		add_cmp_ptr(r, op, fw->sourcemac, 6);
	}

	addr = ether_ntoa((struct ether_addr *) fw->destmac);
	if (strcmp(addr, "0:0:0:0:0:0") != 0) {
		op = nft_invflags2cmp(fw->invflags, EBT_IDEST);
		add_payload(r, offsetof(struct ethhdr, h_dest), 6,
			    NFT_PAYLOAD_LL_HEADER);
		add_cmp_ptr(r, op, fw->destmac, 6);
	}

	if (fw->ethproto != 0) {
		op = nft_invflags2cmp(fw->invflags, EBT_IPROTO);
		add_payload(r, offsetof(struct ethhdr, h_proto), 2,
			    NFT_PAYLOAD_LL_HEADER);
		add_cmp_u16(r, fw->ethproto, op);
	}

	add_compat(r, fw->ethproto, fw->invflags);

	for (iter = cs->match_list; iter; iter = iter->next) {
		if (iter->ismatch) {
			if (add_match(r, iter->u.match->m))
				break;
		} else {
			if (add_target(r, iter->u.watcher->t))
				break;
		}
	}

	if (add_counters(r, cs->counters.pcnt, cs->counters.bcnt) < 0)
		return -1;

	return _add_action(r, cs);
}

static void nft_bridge_parse_meta(struct nft_xt_ctx *ctx,
				  struct nftnl_expr *e, void *data)
{
	struct ebtables_command_state *cs = data;
	struct ebt_entry *fw = &cs->fw;
	uint8_t flags = 0;
	int iface = 0;
	const void *ifname;
	uint32_t len;

	iface = parse_meta(e, ctx->meta.key, fw->in, fw->in_mask,
			   fw->out, fw->out_mask, &flags);
	if (!iface)
		goto out;

	switch (ctx->meta.key) {
	case NFT_META_BRI_IIFNAME:
		ifname = nftnl_expr_get(e, NFTNL_EXPR_CMP_DATA, &len);
		if (nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_OP) == NFT_CMP_NEQ)
			flags |= IPT_INV_VIA_IN;

		memcpy(fw->logical_in, ifname, len);

		if (fw->logical_in[len] == '\0')
			memset(fw->in_mask, 0xff, len);
		else {
			fw->logical_in[len] = '+';
			fw->logical_in[len+1] = '\0';
			memset(fw->in_mask, 0xff, len + 1);
		}
		break;
	case NFT_META_BRI_OIFNAME:
		ifname = nftnl_expr_get(e, NFTNL_EXPR_CMP_DATA, &len);
		if (nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_OP) == NFT_CMP_NEQ)
			flags |= IPT_INV_VIA_OUT;

		memcpy(fw->logical_out, ifname, len);

		if (fw->logical_out[len] == '\0') 
			memset(fw->out_mask, 0xff, len);
		else {
			fw->logical_out[len] = '+';
			fw->logical_out[len+1] = '\0';
			memset(fw->out_mask, 0xff, len + 1);
		}
		break;
	default:
		break;
	}

out:
	fw->invflags |= ipt_to_ebt_flags(flags);
}

static void nft_bridge_parse_payload(struct nft_xt_ctx *ctx,
				     struct nftnl_expr *e, void *data)
{
	struct ebtables_command_state *cs = data;
	struct ebt_entry *fw = &cs->fw;
	unsigned char addr[ETH_ALEN];
	unsigned short int ethproto;
	bool inv;
	int i;

	switch (ctx->payload.offset) {
	case offsetof(struct ethhdr, h_dest):
		get_cmp_data(e, addr, sizeof(addr), &inv);
		for (i = 0; i < ETH_ALEN; i++)
			fw->destmac[i] = addr[i];
		if (inv)
			fw->invflags |= EBT_IDEST;
		break;
	case offsetof(struct ethhdr, h_source):
		get_cmp_data(e, addr, sizeof(addr), &inv);
		for (i = 0; i < ETH_ALEN; i++)
			fw->sourcemac[i] = addr[i];
		if (inv)
			fw->invflags |= EBT_ISOURCE;
		break;
	case offsetof(struct ethhdr, h_proto):
		get_cmp_data(e, &ethproto, sizeof(ethproto), &inv);
		fw->ethproto = ethproto;
		if (inv)
			fw->invflags |= EBT_IPROTO;
		break;
	}
}

static void nft_bridge_parse_immediate(const char *jumpto, bool nft_goto,
				       void *data)
{
	struct ebtables_command_state *cs = data;

	cs->jumpto = jumpto;
}

static void parse_watcher(void *object, struct ebt_match **match_list,
			  bool ismatch)
{
	struct ebt_match *m;

	m = calloc(1, sizeof(struct ebt_match));
	if (m == NULL)
		xtables_error(OTHER_PROBLEM, "Can't allocate memory");

	if (ismatch)
		m->u.match = object;
	else
		m->u.watcher = object;

	m->ismatch = ismatch;
	if (*match_list == NULL)
		*match_list = m;
	else
		(*match_list)->next = m;
}

static void nft_bridge_parse_match(struct xtables_match *m, void *data)
{
	struct ebtables_command_state *cs = data;

	parse_watcher(m, &cs->match_list, true);
}

static void nft_bridge_parse_target(struct xtables_target *t, void *data)
{
	struct ebtables_command_state *cs = data;

	/* harcoded names :-( */
	if (strcmp(t->name, "log") == 0 ||
	    strcmp(t->name, "nflog") == 0) {
		parse_watcher(t, &cs->match_list, false);
		return;
	}

	cs->target = t;
}

void nft_rule_to_ebtables_command_state(struct nftnl_rule *r,
					struct ebtables_command_state *cs)
{
	struct nftnl_expr_iter *iter;
	struct nftnl_expr *expr;
	int family = nftnl_rule_get_u32(r, NFTNL_RULE_FAMILY);
	struct nft_xt_ctx ctx = {
		.state.cs_eb = cs,
		.family = family,
	};

	iter = nftnl_expr_iter_create(r);
	if (iter == NULL)
		return;

	expr = nftnl_expr_iter_next(iter);
	while (expr != NULL) {
		const char *name =
			nftnl_expr_get_str(expr, NFTNL_EXPR_NAME);

		if (strcmp(name, "counter") == 0)
			nft_parse_counter(expr, &cs->counters);
		else if (strcmp(name, "payload") == 0)
			nft_parse_payload(&ctx, expr);
		else if (strcmp(name, "meta") == 0)
			nft_parse_meta(&ctx, expr);
                else if (strcmp(name, "bitwise") == 0)
                        nft_parse_bitwise(&ctx, expr);
		else if (strcmp(name, "cmp") == 0)
			nft_parse_cmp(&ctx, expr);
		else if (strcmp(name, "immediate") == 0)
			nft_parse_immediate(&ctx, expr);
		else if (strcmp(name, "match") == 0)
			nft_parse_match(&ctx, expr);
		else if (strcmp(name, "target") == 0)
			nft_parse_target(&ctx, expr);

		expr = nftnl_expr_iter_next(iter);
	}

	nftnl_expr_iter_destroy(iter);

	if (cs->jumpto != NULL)
		return;

	if (cs->target != NULL && cs->target->name != NULL)
		cs->target = xtables_find_target(cs->target->name, XTF_TRY_LOAD);
	else
		cs->jumpto = "CONTINUE";
}

static void print_iface(const char *iface)
{
	char *c;

	if ((c = strchr(iface, IF_WILDCARD)))
		*c = '+';
	printf("%s ", iface);
	if (c)
		*c = IF_WILDCARD;
}

static void nft_bridge_print_table_header(const char *tablename)
{
	printf("Bridge table: %s\n\n", tablename);
}

static void nft_bridge_print_header(unsigned int format, const char *chain,
				    const char *pol,
				    const struct xt_counters *counters,
				    bool basechain, uint32_t refs)
{
	printf("Bridge chain: %s, entries: %u, policy: %s\n",
	       chain, refs, basechain ? pol : "RETURN");
}

static void nft_bridge_print_firewall(struct nftnl_rule *r, unsigned int num,
				      unsigned int format)
{
	struct xtables_match *matchp;
	struct xtables_target *watcherp;
	struct ebt_match *m;
	struct ebtables_command_state cs = {};
	char *addr;

	nft_rule_to_ebtables_command_state(r, &cs);

	if (format & FMT_LINENUMBERS)
		printf("%d ", num);

	/* Dont print anything about the protocol if no protocol was
	 * specified, obviously this means any protocol will do. */
	if (cs.fw.ethproto != 0) {
		printf("-p ");
		if (cs.fw.invflags & EBT_IPROTO)
			printf("! ");
		if (cs.fw.bitmask & EBT_802_3)
			printf("Length ");
		else {
			struct ethertypeent *ent;

			ent = getethertypebynumber(ntohs(cs.fw.ethproto));
			if (!ent)
				printf("0x%x ", ntohs(cs.fw.ethproto));
			else
				printf("%s ", ent->e_name);
		}
	}

	addr = ether_ntoa((struct ether_addr *) cs.fw.sourcemac);
	if (strcmp(addr, "0:0:0:0:0:0") != 0) {
		printf("-s ");
		if (cs.fw.invflags & EBT_ISOURCE)
			printf("! ");
		ebt_print_mac_and_mask(cs.fw.sourcemac, cs.fw.sourcemsk);
		printf(" ");
	}

	addr = ether_ntoa((struct ether_addr *) cs.fw.destmac);
	if (strcmp(addr, "0:0:0:0:0:0") != 0) {
		printf("-d ");
		if (cs.fw.invflags & EBT_IDEST)
			printf("! ");
		ebt_print_mac_and_mask(cs.fw.destmac, cs.fw.destmsk);
		printf(" ");
	}

	if (cs.fw.in[0] != '\0') {
		printf("-i ");
		if (cs.fw.invflags & EBT_IIN)
			printf("! ");
		print_iface(cs.fw.in);
	}

	if (cs.fw.logical_in[0] != '\0') {
		printf("--logical-in ");
		if (cs.fw.invflags & EBT_ILOGICALIN)
			printf("! ");
		print_iface(cs.fw.logical_in);
	}

	if (cs.fw.logical_out[0] != '\0') {
		printf("--logical-out ");
		if (cs.fw.invflags & EBT_ILOGICALOUT)
			printf("! ");
		print_iface(cs.fw.logical_out);
	}

	if (cs.fw.out[0] != '\0') {
		printf("-o ");
		if (cs.fw.invflags & EBT_IOUT)
			printf("! ");
		print_iface(cs.fw.out);
	}

	for (m = cs.match_list; m; m = m->next) {
		if (m->ismatch) {
			matchp = m->u.match;
			if (matchp->print != NULL) {
				matchp->print(&cs.fw, matchp->m,
					      format & FMT_NUMERIC);
			}
		} else {
			watcherp = m->u.watcher;
			if (watcherp->print != NULL) {
				watcherp->print(&cs.fw, watcherp->t,
						format & FMT_NUMERIC);
			}
		}
	}

	printf("-j ");

	if (cs.jumpto != NULL)
		printf("%s", cs.jumpto);
	else if (cs.target != NULL && cs.target->print != NULL)
		cs.target->print(&cs.fw, cs.target->t, format & FMT_NUMERIC);

	if (!(format & FMT_NOCOUNTS))
		printf(" , pcnt = %"PRIu64" -- bcnt = %"PRIu64"",
		       (uint64_t)cs.counters.pcnt, (uint64_t)cs.counters.bcnt);

	if (!(format & FMT_NONEWLINE))
		fputc('\n', stdout);

	ebt_cs_clean(&cs);
}

static bool nft_bridge_is_same(const void *data_a, const void *data_b)
{
	const struct ebt_entry *a = data_a;
	const struct ebt_entry *b = data_b;
	int i;

	if (a->ethproto != b->ethproto ||
	    /* FIXME: a->flags != b->flags || */
	    a->invflags != b->invflags) {
		DEBUGP("different proto/flags/invflags\n");
		return false;
	}

	for (i = 0; i < ETH_ALEN; i++) {
		if (a->sourcemac[i] != b->sourcemac[i]) {
			DEBUGP("different source mac %x, %x (%d)\n",
			a->sourcemac[i] & 0xff, b->sourcemac[i] & 0xff, i);
			return false;
		}

		if (a->destmac[i] != b->destmac[i]) {
			DEBUGP("different destination mac %x, %x (%d)\n",
			a->destmac[i] & 0xff, b->destmac[i] & 0xff, i);
			return false;
		}
	}

	for (i = 0; i < IFNAMSIZ; i++) {
		if (a->logical_in[i] != b->logical_in[i]) {
			DEBUGP("different logical iniface %x, %x (%d)\n",
			a->logical_in[i] & 0xff, b->logical_in[i] & 0xff, i);
			return false;
		}

		if (a->logical_out[i] != b->logical_out[i]) {
			DEBUGP("different logical outiface %x, %x (%d)\n",
			a->logical_out[i] & 0xff, b->logical_out[i] & 0xff, i);
			return false;
		}
	}

	return is_same_interfaces((char *)a->in,
				  (char *)a->out,
				  a->in_mask,
				  a->out_mask,
				  (char *)b->in,
				  (char *)b->out,
				  b->in_mask,
				  b->out_mask);
}

static bool nft_bridge_rule_find(struct nft_family_ops *ops, struct nftnl_rule *r,
				 void *data)
{
	struct ebtables_command_state *cs = data;
	struct ebtables_command_state this = {};

	nft_rule_to_ebtables_command_state(r, &this);

	DEBUGP("comparing with... ");

	if (!nft_bridge_is_same(cs, &this))
		return false;

	if (!compare_matches(cs->matches, this.matches)) {
		DEBUGP("Different matches\n");
		return false;
	}

	if (!compare_targets(cs->target, this.target)) {
		DEBUGP("Different target\n");
		return false;
	}

	if (cs->jumpto != NULL && strcmp(cs->jumpto, this.jumpto) != 0) {
		DEBUGP("Different verdict\n");
		return false;
	}

	return true;
}

struct nft_family_ops nft_family_ops_bridge = {
	.add			= nft_bridge_add,
	.is_same		= nft_bridge_is_same,
	.print_payload		= NULL,
	.parse_meta		= nft_bridge_parse_meta,
	.parse_payload		= nft_bridge_parse_payload,
	.parse_immediate	= nft_bridge_parse_immediate,
	.parse_match		= nft_bridge_parse_match,
	.parse_target		= nft_bridge_parse_target,
	.print_table_header	= nft_bridge_print_table_header,
	.print_header		= nft_bridge_print_header,
	.print_firewall		= nft_bridge_print_firewall,
	.save_firewall		= NULL,
	.save_counters		= NULL,
	.post_parse		= NULL,
	.rule_find		= nft_bridge_rule_find,
};
