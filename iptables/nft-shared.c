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

extern struct nft_family_ops nft_family_ops_ipv4;
extern struct nft_family_ops nft_family_ops_ipv6;

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

	if (iface[iface_len - 1] == '+') {
		add_meta(r, NFT_META_IIFNAME);
		add_cmp_ptr(r, op, iface, iface_len - 1);
	} else {
		add_meta(r, NFT_META_IIF);
		add_cmp_u32(r, if_nametoindex(iface), op);
	}
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

	if (iface[iface_len - 1] == '+') {
		add_meta(r, NFT_META_OIFNAME);
		add_cmp_ptr(r, op, iface, iface_len - 1);
	} else {
		add_meta(r, NFT_META_OIF);
		add_cmp_u32(r, if_nametoindex(iface), op);
	}
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
	size_t len;

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
		iniface[len] = '\0';

		/* If zero, then this is an interface mask */
		if (if_nametoindex(iniface) == 0) {
			iniface[len] = '+';
			iniface[len+1] = '\0';
		}

		memset(iniface_mask, 0xff, len);
		break;
	case NFT_META_OIFNAME:
		ifname = nft_rule_expr_get(e, NFT_EXPR_CMP_DATA, &len);
		if (nft_rule_expr_get_u8(e, NFT_EXPR_CMP_OP) == NFT_CMP_NEQ)
			*invflags |= IPT_INV_VIA_OUT;

		memcpy(outiface, ifname, len);
		outiface[len] = '\0';

		/* If zero, then this is an interface mask */
		if (if_nametoindex(outiface) == 0) {
			outiface[len] = '+';
			outiface[len+1] = '\0';
		}

		memset(outiface_mask, 0xff, len);
		break;
	default:
		DEBUGP("unknown meta key %d\n", key);
		break;
	}
}

const char *nft_parse_target(struct nft_rule *r, const void **targinfo,
			     size_t *target_len)
{
	struct nft_rule_expr_iter *iter;
	struct nft_rule_expr *expr;
	const char *targname = NULL;

	iter = nft_rule_expr_iter_create(r);
	if (iter == NULL)
		return NULL;

	expr = nft_rule_expr_iter_next(iter);
	while (expr != NULL) {
		const char *name =
			nft_rule_expr_get_str(expr, NFT_RULE_EXPR_ATTR_NAME);

		if (strcmp(name, "target") == 0) {
			targname = nft_rule_expr_get_str(expr,
							NFT_EXPR_TG_NAME);
			*targinfo = nft_rule_expr_get(expr, NFT_EXPR_TG_INFO,
								target_len);
			break;
		} else if (strcmp(name, "immediate") == 0) {
			uint32_t verdict =
			nft_rule_expr_get_u32(expr, NFT_EXPR_IMM_VERDICT);

			switch(verdict) {
			case NF_ACCEPT:
				targname = "ACCEPT";
				break;
			case NF_DROP:
				targname = "DROP";
				break;
			case NFT_RETURN:
				targname = "RETURN";
				break;
			case NFT_GOTO:
				targname = nft_rule_expr_get_str(expr,
							NFT_EXPR_IMM_CHAIN);
				break;
			case NFT_JUMP:
				targname = nft_rule_expr_get_str(expr,
							NFT_EXPR_IMM_CHAIN);
			break;
			}
		}
		expr = nft_rule_expr_iter_next(iter);
	}
	nft_rule_expr_iter_destroy(iter);

	return targname;
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
	size_t len;
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

static void
nft_parse_meta(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
	       int family, struct iptables_command_state *cs)
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

	ops->parse_meta(e, key, cs);
}

static void
nft_parse_payload(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
		  int family, struct iptables_command_state *cs)
{
	struct nft_family_ops *ops = nft_family_ops_lookup(family);
	uint32_t offset;

	offset = nft_rule_expr_get_u32(e, NFT_EXPR_PAYLOAD_OFFSET);

	ops->parse_payload(iter, cs, offset);
}

static void
nft_parse_counter(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
		  struct xt_counters *counters)
{
	counters->pcnt = nft_rule_expr_get_u64(e, NFT_EXPR_CTR_PACKETS);
	counters->bcnt = nft_rule_expr_get_u64(e, NFT_EXPR_CTR_BYTES);
}

static void
nft_parse_immediate(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
		    int family, struct iptables_command_state *cs)
{
	int verdict = nft_rule_expr_get_u32(e, NFT_EXPR_IMM_VERDICT);
	const char *chain = nft_rule_expr_get_str(e, NFT_EXPR_IMM_CHAIN);
	struct nft_family_ops *ops;

	/* Standard target? */
	switch(verdict) {
	case NF_ACCEPT:
		cs->jumpto = "ACCEPT";
		return;
	case NF_DROP:
		cs->jumpto = "DROP";
		return;
	case NFT_RETURN:
		cs->jumpto = "RETURN";
		return;
	case NFT_GOTO:
		ops = nft_family_ops_lookup(family);
		ops->parse_immediate(cs);
	case NFT_JUMP:
		cs->jumpto = chain;
		return;
	}
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

		if (strcmp(name, "counter") == 0) {
			nft_parse_counter(expr, iter, &cs->counters);
		} else if (strcmp(name, "payload") == 0) {
			nft_parse_payload(expr, iter, family, cs);
		} else if (strcmp(name, "meta") == 0) {
			nft_parse_meta(expr, iter, family, cs);
		} else if (strcmp(name, "immediate") == 0) {
			nft_parse_immediate(expr, iter, family, cs);
		}

		expr = nft_rule_expr_iter_next(iter);
	}

	nft_rule_expr_iter_destroy(iter);
}

static void
print_match(struct nft_rule_expr *expr, int numeric)
{
	size_t len;
	const char *match_name = nft_rule_expr_get_str(expr, NFT_EXPR_MT_NAME);
	const void *match_info = nft_rule_expr_get(expr, NFT_EXPR_MT_INFO, &len);
	const struct xtables_match *match =
		xtables_find_match(match_name, XTF_TRY_LOAD, NULL);
	struct xt_entry_match *m =
		calloc(1, sizeof(struct xt_entry_match) + len);

	/* emulate struct xt_entry_match since ->print needs it */
	memcpy((void *)&m->data, match_info, len);

	if (match) {
		if (match->print)
			/* FIXME missing first parameter */
			match->print(NULL, m, numeric);
		else
			printf("%s ", match_name);
	} else {
		if (match_name[0])
			printf("UNKNOWN match `%s' ", match_name);
	}

	free(m);
}

int print_matches(struct nft_rule *r, int format)
{
	struct nft_rule_expr_iter *iter;
	struct nft_rule_expr *expr;

	iter = nft_rule_expr_iter_create(r);
	if (iter == NULL)
		return -ENOMEM;

	expr = nft_rule_expr_iter_next(iter);
	while (expr != NULL) {
		const char *name =
			nft_rule_expr_get_str(expr, NFT_RULE_EXPR_ATTR_NAME);

		if (strcmp(name, "match") == 0)
			print_match(expr, format & FMT_NUMERIC);

		expr = nft_rule_expr_iter_next(iter);
	}
	nft_rule_expr_iter_destroy(iter);

	return 0;
}

int print_target(const char *targname, const void *targinfo,
		 size_t target_len, int format)
{
	struct xtables_target *target;
	struct xt_entry_target *t;

	if (targname == NULL)
		return 0;

	t = calloc(1, sizeof(struct xt_entry_target) + target_len);
	if (t == NULL)
		return -ENOMEM;

	/* emulate struct xt_entry_target since ->print needs it */
	memcpy((void *)&t->data, targinfo, target_len);

	target = xtables_find_target(targname, XTF_TRY_LOAD);
	if (target) {
		if (target->print)
			/* FIXME missing first parameter */
			target->print(NULL, t, format & FMT_NUMERIC);
	} else
		printf("[%ld bytes of unknown target data] ", target_len);

	free(t);

	return 0;
}

void print_num(uint64_t number, unsigned int format)
{
	if (format & FMT_KILOMEGAGIGA) {
		if (number > 99999) {
			number = (number + 500) / 1000;
			if (number > 9999) {
				number = (number + 500) / 1000;
				if (number > 9999) {
					number = (number + 500) / 1000;
					if (number > 9999) {
						number = (number + 500) / 1000;
						printf(FMT("%4lluT ","%lluT "), (unsigned long long)number);
					}
					else printf(FMT("%4lluG ","%lluG "), (unsigned long long)number);
				}
				else printf(FMT("%4lluM ","%lluM "), (unsigned long long)number);
			} else
				printf(FMT("%4lluK ","%lluK "), (unsigned long long)number);
		} else
			printf(FMT("%5llu ","%llu "), (unsigned long long)number);
	} else
		printf(FMT("%8llu ","%llu "), (unsigned long long)number);
}

void print_firewall_details(const struct iptables_command_state *cs,
			    const char *targname, uint8_t flags,
			    uint8_t invflags, uint8_t proto,
			    const char *iniface, const char *outiface,
			    unsigned int num, unsigned int format)
{
	if (format & FMT_LINENUMBERS)
		printf(FMT("%-4u ", "%u "), num);

	if (!(format & FMT_NOCOUNTS)) {
		print_num(cs->counters.pcnt, format);
		print_num(cs->counters.bcnt, format);
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

	if (format & FMT_OPTIONS) {
		if (format & FMT_NOTABLE)
			fputs("opt ", stdout);
		fputc(invflags & IPT_INV_FRAG ? '!' : '-', stdout);
		fputc(flags & IPT_F_FRAG ? 'f' : '-', stdout);
		fputc(' ', stdout);
	}

	if (format & FMT_VIA) {
		char iface[IFNAMSIZ+2];
		if (invflags & IPT_INV_VIA_IN) {
			iface[0] = '!';
			iface[1] = '\0';
		}
		else iface[0] = '\0';

		if (iniface[0] != '\0') {
			strcat(iface, iniface);
		}
		else if (format & FMT_NUMERIC) strcat(iface, "*");
		else strcat(iface, "any");
		printf(FMT(" %-6s ","in %s "), iface);

		if (invflags & IPT_INV_VIA_OUT) {
			iface[0] = '!';
			iface[1] = '\0';
		}
		else iface[0] = '\0';

		if (outiface[0] != '\0') {
			strcat(iface, outiface);
		}
		else if (format & FMT_NUMERIC) strcat(iface, "*");
		else strcat(iface, "any");
		printf(FMT("%-6s ","out %s "), iface);
	}
}

struct nft_family_ops *nft_family_ops_lookup(int family)
{
	switch (family) {
	case AF_INET:
		return &nft_family_ops_ipv4;
	case AF_INET6:
		return &nft_family_ops_ipv6;
	default:
		break;
	}

	return NULL;
}

