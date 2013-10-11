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
#include <stdlib.h>
#include <stdbool.h>
#include <netdb.h>
#include <errno.h>

#include <xtables.h>

#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftables/rule.h>
#include <libnftables/expr.h>

#include "nft-shared.h"
#include "xshared.h"
#include "nft.h"

extern struct nft_family_ops nft_family_ops_ipv4;
extern struct nft_family_ops nft_family_ops_ipv6;
extern struct nft_family_ops nft_family_ops_arp;

void add_meta(struct nft_rule *r, uint32_t key)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("meta");
	if (expr == NULL)
		return;

	nft_rule_expr_set_u32(expr, NFT_EXPR_META_KEY, key);
	nft_rule_expr_set_u32(expr, NFT_EXPR_META_DREG, NFT_REG_1);

	nft_rule_add_expr(r, expr);
}

void add_payload(struct nft_rule *r, int offset, int len)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("payload");
	if (expr == NULL)
		return;

	nft_rule_expr_set_u32(expr, NFT_EXPR_PAYLOAD_BASE,
			      NFT_PAYLOAD_NETWORK_HEADER);
	nft_rule_expr_set_u32(expr, NFT_EXPR_PAYLOAD_DREG, NFT_REG_1);
	nft_rule_expr_set_u32(expr, NFT_EXPR_PAYLOAD_OFFSET, offset);
	nft_rule_expr_set_u32(expr, NFT_EXPR_PAYLOAD_LEN, len);

	nft_rule_add_expr(r, expr);
}

/* bitwise operation is = sreg & mask ^ xor */
void add_bitwise_u16(struct nft_rule *r, int mask, int xor)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("bitwise");
	if (expr == NULL)
		return;

	nft_rule_expr_set_u32(expr, NFT_EXPR_BITWISE_SREG, NFT_REG_1);
	nft_rule_expr_set_u32(expr, NFT_EXPR_BITWISE_DREG, NFT_REG_1);
	nft_rule_expr_set_u32(expr, NFT_EXPR_BITWISE_LEN, sizeof(uint16_t));
	nft_rule_expr_set(expr, NFT_EXPR_BITWISE_MASK, &mask, sizeof(uint16_t));
	nft_rule_expr_set(expr, NFT_EXPR_BITWISE_XOR, &xor, sizeof(uint16_t));

	nft_rule_add_expr(r, expr);
}

void add_cmp_ptr(struct nft_rule *r, uint32_t op, void *data, size_t len)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("cmp");
	if (expr == NULL)
		return;

	nft_rule_expr_set_u8(expr, NFT_EXPR_CMP_SREG, NFT_REG_1);
	nft_rule_expr_set_u8(expr, NFT_EXPR_CMP_OP, op);
	nft_rule_expr_set(expr, NFT_EXPR_CMP_DATA, data, len);

	nft_rule_add_expr(r, expr);
}

void add_cmp_u8(struct nft_rule *r, uint8_t val, uint32_t op)
{
	add_cmp_ptr(r, op, &val, sizeof(val));
}

void add_cmp_u16(struct nft_rule *r, uint16_t val, uint32_t op)
{
	add_cmp_ptr(r, op, &val, sizeof(val));
}

void add_cmp_u32(struct nft_rule *r, uint32_t val, uint32_t op)
{
	add_cmp_ptr(r, op, &val, sizeof(val));
}

void add_iniface(struct nft_rule *r, char *iface, int invflags)
{
	int iface_len;
	uint32_t op;

	iface_len = strlen(iface);

	if (invflags & IPT_INV_VIA_IN)
		op = NFT_CMP_NEQ;
	else
		op = NFT_CMP_EQ;

	add_meta(r, NFT_META_IIFNAME);
	if (iface[iface_len - 1] == '+')
		add_cmp_ptr(r, op, iface, iface_len - 1);
	else
		add_cmp_ptr(r, op, iface, iface_len + 1);
}

void add_outiface(struct nft_rule *r, char *iface, int invflags)
{
	int iface_len;
	uint32_t op;

	iface_len = strlen(iface);

	if (invflags & IPT_INV_VIA_OUT)
		op = NFT_CMP_NEQ;
	else
		op = NFT_CMP_EQ;

	add_meta(r, NFT_META_OIFNAME);
	if (iface[iface_len - 1] == '+')
		add_cmp_ptr(r, op, iface, iface_len - 1);
	else
		add_cmp_ptr(r, op, iface, iface_len + 1);
}

void add_addr(struct nft_rule *r, int offset,
	      void *data, size_t len, int invflags)
{
	uint32_t op;

	add_payload(r, offset, len);

	if (invflags & IPT_INV_SRCIP || invflags & IPT_INV_DSTIP)
		op = NFT_CMP_NEQ;
	else
		op = NFT_CMP_EQ;

	add_cmp_ptr(r, op, data, len);
}

void add_proto(struct nft_rule *r, int offset, size_t len,
	       uint8_t proto, int invflags)
{
	uint32_t op;

	add_payload(r, offset, len);

	if (invflags & XT_INV_PROTO)
		op = NFT_CMP_NEQ;
	else
		op = NFT_CMP_EQ;

	add_cmp_u8(r, proto, op);
}

bool is_same_interfaces(const char *a_iniface, const char *a_outiface,
			unsigned const char *a_iniface_mask,
			unsigned const char *a_outiface_mask,
			const char *b_iniface, const char *b_outiface,
			unsigned const char *b_iniface_mask,
			unsigned const char *b_outiface_mask)
{
	int i;

	for (i = 0; i < IFNAMSIZ; i++) {
		if (a_iniface_mask[i] != b_iniface_mask[i]) {
			DEBUGP("different iniface mask %x, %x (%d)\n",
			a_iniface_mask[i] & 0xff, b_iniface_mask[i] & 0xff, i);
			return false;
		}
		if ((a_iniface[i] & a_iniface_mask[i])
		    != (b_iniface[i] & b_iniface_mask[i])) {
			DEBUGP("different iniface\n");
			return false;
		}
		if (a_outiface_mask[i] != b_outiface_mask[i]) {
			DEBUGP("different outiface mask\n");
			return false;
		}
		if ((a_outiface[i] & a_outiface_mask[i])
		    != (b_outiface[i] & b_outiface_mask[i])) {
			DEBUGP("different outiface\n");
			return false;
		}
	}

	return true;
}

void parse_meta(struct nft_rule_expr *e, uint8_t key, char *iniface,
		unsigned char *iniface_mask, char *outiface,
		unsigned char *outiface_mask, uint8_t *invflags)
{
	uint32_t value;
	const void *ifname;
	uint32_t len;

	switch(key) {
	case NFT_META_IIF:
		value = nft_rule_expr_get_u32(e, NFT_EXPR_CMP_DATA);
		if (nft_rule_expr_get_u8(e, NFT_EXPR_CMP_OP) == NFT_CMP_NEQ)
			*invflags |= IPT_INV_VIA_IN;

		if_indextoname(value, iniface);

		memset(iniface_mask, 0xff, strlen(iniface)+1);
		break;
	case NFT_META_OIF:
		value = nft_rule_expr_get_u32(e, NFT_EXPR_CMP_DATA);
		if (nft_rule_expr_get_u8(e, NFT_EXPR_CMP_OP) == NFT_CMP_NEQ)
			*invflags |= IPT_INV_VIA_OUT;

		if_indextoname(value, outiface);

		memset(outiface_mask, 0xff, strlen(outiface)+1);
		break;
	case NFT_META_IIFNAME:
		ifname = nft_rule_expr_get(e, NFT_EXPR_CMP_DATA, &len);
		if (nft_rule_expr_get_u8(e, NFT_EXPR_CMP_OP) == NFT_CMP_NEQ)
			*invflags |= IPT_INV_VIA_IN;

		memcpy(iniface, ifname, len);

		if (iniface[len] == '\0')
			memset(iniface_mask, 0xff, len);
		else {
			iniface[len] = '+';
			iniface[len+1] = '\0';
			memset(iniface_mask, 0xff, len + 1);
		}
		break;
	case NFT_META_OIFNAME:
		ifname = nft_rule_expr_get(e, NFT_EXPR_CMP_DATA, &len);
		if (nft_rule_expr_get_u8(e, NFT_EXPR_CMP_OP) == NFT_CMP_NEQ)
			*invflags |= IPT_INV_VIA_OUT;

		memcpy(outiface, ifname, len);

		if (outiface[len] == '\0')
			memset(outiface_mask, 0xff, len);
		else {
			outiface[len] = '+';
			outiface[len+1] = '\0';
			memset(outiface_mask, 0xff, len + 1);
		}
		break;
	default:
		DEBUGP("unknown meta key %d\n", key);
		break;
	}
}

void nft_parse_target(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
		 int family, void *data)
{
	uint32_t tg_len;
	const char *targname = nft_rule_expr_get_str(e, NFT_EXPR_TG_NAME);
	const void *targinfo = nft_rule_expr_get(e, NFT_EXPR_TG_INFO, &tg_len);
	struct xtables_target *target;
	struct xt_entry_target *t;
	struct nft_family_ops *ops;
	size_t size;

	target = xtables_find_target(targname, XTF_TRY_LOAD);
	if (target == NULL)
		return;

	size = XT_ALIGN(sizeof(struct xt_entry_target)) + tg_len;

	t = calloc(1, size);
	if (t == NULL) {
		fprintf(stderr, "OOM");
		exit(EXIT_FAILURE);
	}
	memcpy(&t->data, targinfo, tg_len);
	t->u.target_size = size;
	t->u.user.revision = nft_rule_expr_get_u32(e, NFT_EXPR_TG_REV);
	strcpy(t->u.user.name, target->name);

	target->t = t;

	ops = nft_family_ops_lookup(family);
	ops->parse_target(target, data);
}

static void
nft_parse_match(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
		struct iptables_command_state *cs)
{
	uint32_t mt_len;
	const char *mt_name = nft_rule_expr_get_str(e, NFT_EXPR_MT_NAME);
	const void *mt_info = nft_rule_expr_get(e, NFT_EXPR_MT_INFO, &mt_len);
	struct xtables_match *match;
	struct xt_entry_match *m;

	match = xtables_find_match(mt_name, XTF_TRY_LOAD, &cs->matches);
	if (match == NULL)
		return;

	m = calloc(1, sizeof(struct xt_entry_match) + mt_len);
	if (m == NULL) {
		fprintf(stderr, "OOM");
		exit(EXIT_FAILURE);
	}

	memcpy(&m->data, mt_info, mt_len);
	m->u.match_size = mt_len + XT_ALIGN(sizeof(struct xt_entry_match));
	m->u.user.revision = nft_rule_expr_get_u32(e, NFT_EXPR_TG_REV);
	strcpy(m->u.user.name, match->name);

	match->m = m;
}

void print_proto(uint16_t proto, int invert)
{
	const struct protoent *pent = getprotobynumber(proto);

	if (invert)
		printf("! ");

	if (pent) {
		printf("-p %s ", pent->p_name);
		return;
	}

	printf("-p %u ", proto);
}

void get_cmp_data(struct nft_rule_expr_iter *iter,
		  void *data, size_t dlen, bool *inv)
{
	struct nft_rule_expr *e;
	const char *name;
	uint32_t len;
	uint8_t op;

	e = nft_rule_expr_iter_next(iter);
	if (e == NULL)
		return;

	name = nft_rule_expr_get_str(e, NFT_RULE_EXPR_ATTR_NAME);
	if (strcmp(name, "cmp") != 0) {
		DEBUGP("skipping no cmp after meta\n");
		return;
	}

	memcpy(data, nft_rule_expr_get(e, NFT_EXPR_CMP_DATA, &len), dlen);
	op = nft_rule_expr_get_u8(e, NFT_EXPR_CMP_OP);
	if (op == NFT_CMP_NEQ)
		*inv = true;
	else
		*inv = false;
}

void
nft_parse_meta(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
	       int family, void *data)
{
	uint8_t key = nft_rule_expr_get_u8(e, NFT_EXPR_META_KEY);
	struct nft_family_ops *ops = nft_family_ops_lookup(family);
	const char *name;

	e = nft_rule_expr_iter_next(iter);
	if (e == NULL)
		return;

	name = nft_rule_expr_get_str(e, NFT_RULE_EXPR_ATTR_NAME);
	if (strcmp(name, "cmp") != 0) {
		DEBUGP("skipping no cmp after meta\n");
		return;
	}

	ops->parse_meta(e, key, data);
}

void
nft_parse_payload(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
		  int family, void *data)
{
	struct nft_family_ops *ops = nft_family_ops_lookup(family);
	uint32_t offset;

	offset = nft_rule_expr_get_u32(e, NFT_EXPR_PAYLOAD_OFFSET);

	ops->parse_payload(iter, offset, data);
}

void
nft_parse_counter(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
		  struct xt_counters *counters)
{
	counters->pcnt = nft_rule_expr_get_u64(e, NFT_EXPR_CTR_PACKETS);
	counters->bcnt = nft_rule_expr_get_u64(e, NFT_EXPR_CTR_BYTES);
}

void
nft_parse_immediate(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
		    int family, void *data)
{
	int verdict = nft_rule_expr_get_u32(e, NFT_EXPR_IMM_VERDICT);
	const char *chain = nft_rule_expr_get_str(e, NFT_EXPR_IMM_CHAIN);
	struct nft_family_ops *ops;
	const char *jumpto = NULL;
	bool nft_goto = false;

	/* Standard target? */
	switch(verdict) {
	case NF_ACCEPT:
		jumpto = "ACCEPT";
		break;
	case NF_DROP:
		jumpto = "DROP";
		break;
	case NFT_RETURN:
		jumpto = "RETURN";
		break;;
	case NFT_GOTO:
		nft_goto = true;
	case NFT_JUMP:
		jumpto = chain;
		break;
	}

	ops = nft_family_ops_lookup(family);
	ops->parse_immediate(jumpto, nft_goto, data);
}

void nft_rule_to_iptables_command_state(struct nft_rule *r,
					struct iptables_command_state *cs)
{
	struct nft_rule_expr_iter *iter;
	struct nft_rule_expr *expr;
	int family = nft_rule_attr_get_u8(r, NFT_RULE_ATTR_FAMILY);

	iter = nft_rule_expr_iter_create(r);
	if (iter == NULL)
		return;

	expr = nft_rule_expr_iter_next(iter);
	while (expr != NULL) {
		const char *name =
			nft_rule_expr_get_str(expr, NFT_RULE_EXPR_ATTR_NAME);

		if (strcmp(name, "counter") == 0)
			nft_parse_counter(expr, iter, &cs->counters);
		else if (strcmp(name, "payload") == 0)
			nft_parse_payload(expr, iter, family, cs);
		else if (strcmp(name, "meta") == 0)
			nft_parse_meta(expr, iter, family, cs);
		else if (strcmp(name, "immediate") == 0)
			nft_parse_immediate(expr, iter, family, cs);
		else if (strcmp(name, "match") == 0)
			nft_parse_match(expr, iter, cs);
		else if (strcmp(name, "target") == 0)
			nft_parse_target(expr, iter, family, cs);

		expr = nft_rule_expr_iter_next(iter);
	}

	nft_rule_expr_iter_destroy(iter);

	if (cs->target != NULL)
		cs->jumpto = cs->target->name;
	else if (cs->jumpto != NULL)
		cs->target = xtables_find_target(cs->jumpto, XTF_TRY_LOAD);
	else
		cs->jumpto = "";
}

void print_firewall_details(const struct iptables_command_state *cs,
			    const char *targname, uint8_t flags,
			    uint8_t invflags, uint8_t proto,
			    unsigned int num, unsigned int format)
{
	if (format & FMT_LINENUMBERS)
		printf(FMT("%-4u ", "%u "), num);

	if (!(format & FMT_NOCOUNTS)) {
		xtables_print_num(cs->counters.pcnt, format);
		xtables_print_num(cs->counters.bcnt, format);
	}

	if (!(format & FMT_NOTARGET))
		printf(FMT("%-9s ", "%s "), targname ? targname : "");

	fputc(invflags & XT_INV_PROTO ? '!' : ' ', stdout);
	{
		const char *pname =
			proto_to_name(proto, format&FMT_NUMERIC);
		if (pname)
			printf(FMT("%-5s", "%s "), pname);
		else
			printf(FMT("%-5hu", "%hu "), proto);
	}
}

void print_ifaces(const char *iniface, const char *outiface, uint8_t invflags,
		  unsigned int format)
{
	char iface[IFNAMSIZ+2];

	if (!(format & FMT_VIA))
		return;

	if (invflags & IPT_INV_VIA_IN) {
		iface[0] = '!';
		iface[1] = '\0';
	} else
		iface[0] = '\0';

	if (iniface[0] != '\0')
		strcat(iface, iniface);
	else if (format & FMT_NUMERIC)
		strcat(iface, "*");
	else
		strcat(iface, "any");

	printf(FMT(" %-6s ","in %s "), iface);

	if (invflags & IPT_INV_VIA_OUT) {
		iface[0] = '!';
		iface[1] = '\0';
	} else
		iface[0] = '\0';

	if (outiface[0] != '\0')
		strcat(iface, outiface);
	else if (format & FMT_NUMERIC)
		strcat(iface, "*");
	else
		strcat(iface, "any");

	printf(FMT("%-6s ","out %s "), iface);
}

static void
print_iface(char letter, const char *iface, const unsigned char *mask, int inv)
{
	unsigned int i;

	if (mask[0] == 0)
		return;

	printf("%s-%c ", inv ? "! " : "", letter);

	for (i = 0; i < IFNAMSIZ; i++) {
		if (mask[i] != 0) {
			if (iface[i] != '\0')
				printf("%c", iface[i]);
			} else {
				if (iface[i-1] != '\0')
					printf("+");
				break;
		}
	}

	printf(" ");
}

void save_firewall_details(const struct iptables_command_state *cs,
			   uint8_t invflags, uint16_t proto,
			   const char *iniface,
			   unsigned const char *iniface_mask,
			   const char *outiface,
			   unsigned const char *outiface_mask,
			   unsigned int format)
{
	if (!(format & FMT_NOCOUNTS)) {
		printf("-c ");
		xtables_print_num(cs->counters.pcnt, format);
		xtables_print_num(cs->counters.bcnt, format);
	}

	if (iniface != NULL) {
		print_iface('i', iniface, iniface_mask,
			    invflags & IPT_INV_VIA_IN);
	}
	if (outiface != NULL) {
		print_iface('o', outiface, outiface_mask,
			    invflags & IPT_INV_VIA_OUT);
	}

	if (proto > 0) {
		const struct protoent *pent = getprotobynumber(proto);

		if (invflags & XT_INV_PROTO)
			printf("! ");

		if (pent)
			printf("-p %s ", pent->p_name);
		else
			printf("-p %u ", proto);
	}
}

void print_matches_and_target(struct iptables_command_state *cs,
			      unsigned int format)
{
	struct xtables_rule_match *matchp;

	for (matchp = cs->matches; matchp; matchp = matchp->next) {
		if (matchp->match->print != NULL) {
			matchp->match->print(&cs->fw, matchp->match->m,
					     format & FMT_NUMERIC);
		}
	}

	if (cs->target != NULL) {
		if (cs->target->print != NULL) {
			cs->target->print(&cs->fw, cs->target->t,
					  format & FMT_NUMERIC);
		}
	}
}

struct nft_family_ops *nft_family_ops_lookup(int family)
{
	switch (family) {
	case AF_INET:
		return &nft_family_ops_ipv4;
	case AF_INET6:
		return &nft_family_ops_ipv6;
	case NFPROTO_ARP:
		return &nft_family_ops_arp;
	default:
		break;
	}

	return NULL;
}

static bool
compare_matches(struct xtables_rule_match *mt1, struct xtables_rule_match *mt2)
{
	struct xtables_rule_match *mp1;
	struct xtables_rule_match *mp2;

	for (mp1 = mt1, mp2 = mt2; mp1 && mp2; mp1 = mp1->next, mp2 = mp2->next) {
		struct xt_entry_match *m1 = mp1->match->m;
		struct xt_entry_match *m2 = mp2->match->m;

		if (strcmp(m1->u.user.name, m2->u.user.name) != 0) {
			DEBUGP("mismatching match name\n");
			return false;
		}

		if (m1->u.user.match_size != m2->u.user.match_size) {
			DEBUGP("mismatching match size\n");
			return false;
		}

		if (memcmp(m1->data, m2->data,
			   mp1->match->userspacesize) != 0) {
			DEBUGP("mismatch match data\n");
			return false;
		}
	}

	/* Both cursors should be NULL */
	if (mp1 != mp2) {
		DEBUGP("mismatch matches amount\n");
		return false;
	}

	return true;
}

bool compare_targets(struct xtables_target *tg1, struct xtables_target *tg2)
{
	if (tg1 == NULL && tg2 == NULL)
		return true;

	if ((tg1 == NULL && tg2 != NULL) || (tg1 != NULL && tg2 == NULL))
		return false;

	if (strcmp(tg1->t->u.user.name, tg2->t->u.user.name) != 0)
		return false;

	if (memcmp(tg1->t->data, tg2->t->data, tg1->userspacesize) != 0)
		return false;

	return true;
}

bool nft_ipv46_rule_find(struct nft_family_ops *ops,
			 struct nft_rule *r, struct iptables_command_state *cs)
{
	struct iptables_command_state this = {};

	nft_rule_to_iptables_command_state(r, &this);

	DEBUGP("comparing with... ");
#ifdef DEBUG_DEL
	nft_rule_print_save(&this, r, NFT_RULE_APPEND, 0);
#endif
	if (!ops->is_same(cs, &this))
		return false;

	if (!compare_matches(cs->matches, this.matches)) {
		DEBUGP("Different matches\n");
		return false;
	}

	if (!compare_targets(cs->target, this.target)) {
		DEBUGP("Different target\n");
		return false;
	}

	if (strcmp(cs->jumpto, this.jumpto) != 0) {
		DEBUGP("Different verdict\n");
		return false;
	}

	return true;
}
