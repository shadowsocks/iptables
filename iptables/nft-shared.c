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
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

#include "nft-shared.h"
#include "nft-bridge.h"
#include "xshared.h"
#include "nft.h"

extern struct nft_family_ops nft_family_ops_ipv4;
extern struct nft_family_ops nft_family_ops_ipv6;
extern struct nft_family_ops nft_family_ops_arp;
extern struct nft_family_ops nft_family_ops_bridge;

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

void add_payload(struct nft_rule *r, int offset, int len, uint32_t base)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("payload");
	if (expr == NULL)
		return;

	nft_rule_expr_set_u32(expr, NFT_EXPR_PAYLOAD_BASE, base);
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

static void add_bitwise(struct nft_rule *r, uint8_t *mask, size_t len)
{
	struct nft_rule_expr *expr;
	uint32_t xor[4] = { 0 };

	expr = nft_rule_expr_alloc("bitwise");
	if (expr == NULL)
		return;

	nft_rule_expr_set_u32(expr, NFT_EXPR_BITWISE_SREG, NFT_REG_1);
	nft_rule_expr_set_u32(expr, NFT_EXPR_BITWISE_DREG, NFT_REG_1);
	nft_rule_expr_set_u32(expr, NFT_EXPR_BITWISE_LEN, len);
	nft_rule_expr_set(expr, NFT_EXPR_BITWISE_MASK, mask, len);
	nft_rule_expr_set(expr, NFT_EXPR_BITWISE_XOR, &xor, len);

	nft_rule_add_expr(r, expr);
}

void add_cmp_ptr(struct nft_rule *r, uint32_t op, void *data, size_t len)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("cmp");
	if (expr == NULL)
		return;

	nft_rule_expr_set_u32(expr, NFT_EXPR_CMP_SREG, NFT_REG_1);
	nft_rule_expr_set_u32(expr, NFT_EXPR_CMP_OP, op);
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

void add_iniface(struct nft_rule *r, char *iface, uint32_t op)
{
	int iface_len;

	iface_len = strlen(iface);

	add_meta(r, NFT_META_IIFNAME);
	if (iface[iface_len - 1] == '+')
		add_cmp_ptr(r, op, iface, iface_len - 1);
	else
		add_cmp_ptr(r, op, iface, iface_len + 1);
}

void add_outiface(struct nft_rule *r, char *iface, uint32_t op)
{
	int iface_len;

	iface_len = strlen(iface);

	add_meta(r, NFT_META_OIFNAME);
	if (iface[iface_len - 1] == '+')
		add_cmp_ptr(r, op, iface, iface_len - 1);
	else
		add_cmp_ptr(r, op, iface, iface_len + 1);
}

void add_addr(struct nft_rule *r, int offset,
	      void *data, void *mask, size_t len, uint32_t op)
{
	add_payload(r, offset, len, NFT_PAYLOAD_NETWORK_HEADER);
	add_bitwise(r, mask, len);

	add_cmp_ptr(r, op, data, len);
}

void add_proto(struct nft_rule *r, int offset, size_t len,
	       uint8_t proto, uint32_t op)
{
	add_payload(r, offset, len, NFT_PAYLOAD_NETWORK_HEADER);
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

int parse_meta(struct nft_rule_expr *e, uint8_t key, char *iniface,
		unsigned char *iniface_mask, char *outiface,
		unsigned char *outiface_mask, uint8_t *invflags)
{
	uint32_t value;
	const void *ifname;
	uint32_t len;

	switch(key) {
	case NFT_META_IIF:
		value = nft_rule_expr_get_u32(e, NFT_EXPR_CMP_DATA);
		if (nft_rule_expr_get_u32(e, NFT_EXPR_CMP_OP) == NFT_CMP_NEQ)
			*invflags |= IPT_INV_VIA_IN;

		if_indextoname(value, iniface);

		memset(iniface_mask, 0xff, strlen(iniface)+1);
		break;
	case NFT_META_OIF:
		value = nft_rule_expr_get_u32(e, NFT_EXPR_CMP_DATA);
		if (nft_rule_expr_get_u32(e, NFT_EXPR_CMP_OP) == NFT_CMP_NEQ)
			*invflags |= IPT_INV_VIA_OUT;

		if_indextoname(value, outiface);

		memset(outiface_mask, 0xff, strlen(outiface)+1);
		break;
	case NFT_META_IIFNAME:
		ifname = nft_rule_expr_get(e, NFT_EXPR_CMP_DATA, &len);
		if (nft_rule_expr_get_u32(e, NFT_EXPR_CMP_OP) == NFT_CMP_NEQ)
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
		if (nft_rule_expr_get_u32(e, NFT_EXPR_CMP_OP) == NFT_CMP_NEQ)
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
		return -1;
	}

	return 0;
}

static void *nft_get_data(struct nft_xt_ctx *ctx)
{
	switch(ctx->family) {
	case NFPROTO_IPV4:
	case NFPROTO_IPV6:
		return ctx->state.cs;
	case NFPROTO_ARP:
		return ctx->state.cs_arp;
	case NFPROTO_BRIDGE:
		return ctx->state.cs_eb;
	default:
		/* Should not happen */
		return NULL;
	}
}

void nft_parse_target(struct nft_xt_ctx *ctx, struct nft_rule_expr *e)
{
	uint32_t tg_len;
	const char *targname = nft_rule_expr_get_str(e, NFT_EXPR_TG_NAME);
	const void *targinfo = nft_rule_expr_get(e, NFT_EXPR_TG_INFO, &tg_len);
	struct xtables_target *target;
	struct xt_entry_target *t;
	size_t size;
	struct nft_family_ops *ops;
	void *data = nft_get_data(ctx);

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

	ops = nft_family_ops_lookup(ctx->family);
	ops->parse_target(target, data);
}

void nft_parse_match(struct nft_xt_ctx *ctx, struct nft_rule_expr *e)
{
	uint32_t mt_len;
	const char *mt_name = nft_rule_expr_get_str(e, NFT_EXPR_MT_NAME);
	const void *mt_info = nft_rule_expr_get(e, NFT_EXPR_MT_INFO, &mt_len);
	struct xtables_match *match;
	struct xtables_rule_match **matches;
	struct xt_entry_match *m;

	switch (ctx->family) {
	case NFPROTO_IPV4:
	case NFPROTO_IPV6:
		matches = &ctx->state.cs->matches;
		break;
	case NFPROTO_BRIDGE:
		matches = &ctx->state.cs_eb->matches;
		break;
	default:
		fprintf(stderr, "BUG: nft_parse_match() unknown family %d\n",
			ctx->family);
		exit(EXIT_FAILURE);
	}

	match = xtables_find_match(mt_name, XTF_TRY_LOAD, matches);
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

void get_cmp_data(struct nft_rule_expr *e, void *data, size_t dlen, bool *inv)
{
	uint32_t len;
	uint8_t op;

	memcpy(data, nft_rule_expr_get(e, NFT_EXPR_CMP_DATA, &len), dlen);
	op = nft_rule_expr_get_u32(e, NFT_EXPR_CMP_OP);
	if (op == NFT_CMP_NEQ)
		*inv = true;
	else
		*inv = false;
}

void nft_parse_meta(struct nft_xt_ctx *ctx, struct nft_rule_expr *e)
{
	ctx->reg = nft_rule_expr_get_u32(e, NFT_EXPR_META_DREG);
	ctx->meta.key = nft_rule_expr_get_u32(e, NFT_EXPR_META_KEY);
	ctx->flags |= NFT_XT_CTX_META;
}

void nft_parse_payload(struct nft_xt_ctx *ctx, struct nft_rule_expr *e)
{
	ctx->reg = nft_rule_expr_get_u32(e, NFT_EXPR_META_DREG);
	ctx->payload.offset = nft_rule_expr_get_u32(e, NFT_EXPR_PAYLOAD_OFFSET);
	ctx->flags |= NFT_XT_CTX_PAYLOAD;
}

void nft_parse_bitwise(struct nft_xt_ctx *ctx, struct nft_rule_expr *e)
{
	uint32_t reg, len;
	const void *data;

	reg = nft_rule_expr_get_u32(e, NFT_EXPR_BITWISE_SREG);
	if (ctx->reg && reg != ctx->reg)
		return;

	data = nft_rule_expr_get(e, NFT_EXPR_BITWISE_XOR, &len);
	memcpy(ctx->bitwise.xor, data, len);
	data = nft_rule_expr_get(e, NFT_EXPR_BITWISE_MASK, &len);
	memcpy(ctx->bitwise.mask, data, len);
	ctx->flags |= NFT_XT_CTX_BITWISE;
}

void nft_parse_cmp(struct nft_xt_ctx *ctx, struct nft_rule_expr *e)
{
	struct nft_family_ops *ops = nft_family_ops_lookup(ctx->family);
	void *data = nft_get_data(ctx);
	uint32_t reg;

	reg = nft_rule_expr_get_u32(e, NFT_EXPR_CMP_SREG);
	if (ctx->reg && reg != ctx->reg)
		return;

	if (ctx->flags & NFT_XT_CTX_META)
		ops->parse_meta(ctx, e, data);
	/* bitwise context is interpreted from payload */
	if (ctx->flags & NFT_XT_CTX_PAYLOAD)
		ops->parse_payload(ctx, e, data);
}

void nft_parse_counter(struct nft_rule_expr *e, struct xt_counters *counters)
{
	counters->pcnt = nft_rule_expr_get_u64(e, NFT_EXPR_CTR_PACKETS);
	counters->bcnt = nft_rule_expr_get_u64(e, NFT_EXPR_CTR_BYTES);
}

void nft_parse_immediate(struct nft_xt_ctx *ctx, struct nft_rule_expr *e)
{
	int verdict = nft_rule_expr_get_u32(e, NFT_EXPR_IMM_VERDICT);
	const char *chain = nft_rule_expr_get_str(e, NFT_EXPR_IMM_CHAIN);
	struct nft_family_ops *ops;
	const char *jumpto = NULL;
	bool nft_goto = false;
	void *data = nft_get_data(ctx);

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

	ops = nft_family_ops_lookup(ctx->family);
	ops->parse_immediate(jumpto, nft_goto, data);
}

void nft_rule_to_iptables_command_state(struct nft_rule *r,
					struct iptables_command_state *cs)
{
	struct nft_rule_expr_iter *iter;
	struct nft_rule_expr *expr;
	int family = nft_rule_attr_get_u32(r, NFT_RULE_ATTR_FAMILY);
	struct nft_xt_ctx ctx = {
		.state.cs = cs,
		.family = family,
	};

	iter = nft_rule_expr_iter_create(r);
	if (iter == NULL)
		return;

	ctx.iter = iter;
	expr = nft_rule_expr_iter_next(iter);
	while (expr != NULL) {
		const char *name =
			nft_rule_expr_get_str(expr, NFT_RULE_EXPR_ATTR_NAME);

		if (strcmp(name, "counter") == 0)
			nft_parse_counter(expr, &ctx.state.cs->counters);
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

void print_header(unsigned int format, const char *chain, const char *pol,
		  const struct xt_counters *counters, bool basechain,
		  uint32_t refs)
{
	printf("Chain %s", chain);
	if (basechain) {
		printf(" (policy %s", pol);
		if (!(format & FMT_NOCOUNTS)) {
			fputc(' ', stdout);
			xtables_print_num(counters->pcnt, (format|FMT_NOTABLE));
			fputs("packets, ", stdout);
			xtables_print_num(counters->bcnt, (format|FMT_NOTABLE));
			fputs("bytes", stdout);
		}
		printf(")\n");
	} else {
		printf(" (%u references)\n", refs);
	}

	if (format & FMT_LINENUMBERS)
		printf(FMT("%-4s ", "%s "), "num");
	if (!(format & FMT_NOCOUNTS)) {
		if (format & FMT_KILOMEGAGIGA) {
			printf(FMT("%5s ","%s "), "pkts");
			printf(FMT("%5s ","%s "), "bytes");
		} else {
			printf(FMT("%8s ","%s "), "pkts");
			printf(FMT("%10s ","%s "), "bytes");
		}
	}
	if (!(format & FMT_NOTARGET))
		printf(FMT("%-9s ","%s "), "target");
	fputs(" prot ", stdout);
	if (format & FMT_OPTIONS)
		fputs("opt", stdout);
	if (format & FMT_VIA) {
		printf(FMT(" %-6s ","%s "), "in");
		printf(FMT("%-6s ","%s "), "out");
	}
	printf(FMT(" %-19s ","%s "), "source");
	printf(FMT(" %-19s "," %s "), "destination");
	printf("\n");
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
			   unsigned const char *outiface_mask)
{
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

void save_counters(uint64_t pcnt, uint64_t bcnt)
{
	printf("[%llu:%llu] ", (unsigned long long)pcnt,
			       (unsigned long long)bcnt);
}

void save_matches_and_target(struct xtables_rule_match *m,
			     struct xtables_target *target,
			     const char *jumpto, uint8_t flags, const void *fw)
{
	struct xtables_rule_match *matchp;

	for (matchp = m; matchp; matchp = matchp->next) {
		if (matchp->match->alias) {
			printf("-m %s",
			       matchp->match->alias(matchp->match->m));
		} else
			printf("-m %s", matchp->match->name);

		if (matchp->match->save != NULL) {
			/* cs->fw union makes the trick */
			matchp->match->save(fw, matchp->match->m);
		}
		printf(" ");
	}

	if (target != NULL) {
		if (target->alias) {
			printf("-j %s", target->alias(target->t));
		} else
			printf("-j %s", jumpto);

		if (target->save != NULL)
			target->save(fw, target->t);
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
	case NFPROTO_BRIDGE:
		return &nft_family_ops_bridge;
	default:
		break;
	}

	return NULL;
}

bool compare_matches(struct xtables_rule_match *mt1,
		     struct xtables_rule_match *mt2)
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
