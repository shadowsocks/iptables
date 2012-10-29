/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Sophos Astaro <http://www.sophos.com>
 */

#if 0
#define DEBUGP(x, args...) fprintf(stdout, x, ## args)
#define NLDEBUG
#define DEBUG_DEL
#else
#define DEBUGP(x, args...)
#endif

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <errno.h>
#include <netdb.h>	/* getprotobynumber */
#include <time.h>

#include <xtables.h>
#include <libiptc/libxtc.h>
#include <libiptc/xtcshared.h>

#include <stdlib.h>
#include <string.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>	/* FIXME: only IPV4 by now */

#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nf_tables_compat.h>

#include <libmnl/libmnl.h>
#include <libnftables/table.h>
#include <libnftables/chain.h>
#include <libnftables/rule.h>
#include <libnftables/expr.h>

#include <netinet/in.h>	/* inet_ntoa */
#include <arpa/inet.h>

#include "nft.h"
#include "xshared.h" /* proto_to_name */

static void *nft_fn;

static int mnl_talk(struct nft_handle *h, struct nlmsghdr *nlh,
		    int (*cb)(const struct nlmsghdr *nlh, void *data),
		    void *data)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];

	if (mnl_socket_sendto(h->nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		return -1;
	}

	ret = mnl_socket_recvfrom(h->nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, h->seq, h->portid, cb, data);
		if (ret <= 0)
			break;

		ret = mnl_socket_recvfrom(h->nl, buf, sizeof(buf));
	}
	if (ret == -1) {
		return -1;
	}

	return 0;
}

static int nft_table_builtin_add(struct nft_handle *h, const char *table)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_table *t;
	int ret;

	t = nft_table_alloc();
	if (t == NULL)
		return -1;

	nft_table_attr_set(t, NFT_TABLE_ATTR_NAME, (char *)table);

	nlh = nft_table_nlmsg_build_hdr(buf, NFT_MSG_NEWTABLE, AF_INET,
					NLM_F_ACK|NLM_F_EXCL, h->seq);
	nft_table_nlmsg_build_payload(nlh, t);
	nft_table_free(t);

	ret = mnl_talk(h, nlh, NULL, NULL);
	if (ret < 0) {
		if (errno != EEXIST)
			perror("mnl-talk:nft_table_init_one");
	}
	return ret;
}

#define FILTER		0
#define MANGLE		1
#define RAW		2
#define SECURITY	3
#define TABLES_MAX	4

struct builtin_chain {
	const char *name;
	uint32_t hook;
};

static struct builtin_table {
	const char *name;
	uint32_t prio;
	struct builtin_chain chains[NF_INET_NUMHOOKS];
} tables[TABLES_MAX] = {
	[RAW] = {
		.name	= "raw",
		.prio	= -300,	/* NF_IP_PRI_RAW */
		.chains = {
			{
				.name	= "PREROUTING",
				.hook	= NF_INET_PRE_ROUTING,
			},
			{
				.name	= "OUTPUT",
				.hook	= NF_INET_LOCAL_OUT,
			},
		},
	},
	[MANGLE] = {
		.name	= "mangle",
		.prio	= -150,	/* NF_IP_PRI_MANGLE */
		.chains = {
			{
				.name	= "PREROUTING",
				.hook	= NF_INET_PRE_ROUTING,
			},
			{
				.name	= "INPUT",
				.hook	= NF_INET_LOCAL_IN,
			},
			{
				.name	= "FORWARD",
				.hook	= NF_INET_FORWARD,
			},
			{
				.name	= "OUTPUT",
				.hook	= NF_INET_LOCAL_OUT,
			},
			{
				.name	= "POSTROUTING",
				.hook	= NF_INET_POST_ROUTING,
			},
		},
	},
	[FILTER] = {
		.name	= "filter",
		.prio	= 0,	/* NF_IP_PRI_FILTER */
		.chains = {
			{
				.name	= "INPUT",
				.hook	= NF_INET_LOCAL_IN,
			},
			{
				.name	= "FORWARD",
				.hook	= NF_INET_FORWARD,
			},
			{
				.name	= "OUTPUT",
				.hook	= NF_INET_LOCAL_OUT,
			},
		},
	},
	[SECURITY] = {
		.name	= "security",
		.prio	= 150,	/* NF_IP_PRI_SECURITY */
		.chains = {
			{
				.name	= "INPUT",
				.hook	= NF_INET_LOCAL_IN,
			},
			{
				.name	= "FORWARD",
				.hook	= NF_INET_FORWARD,
			},
			{
				.name	= "OUTPUT",
				.hook	= NF_INET_LOCAL_OUT,
			},
		},
	},
	/* nat already registered by nf_tables */
};

static struct nft_chain *
nft_chain_builtin_alloc(struct builtin_table *table,
			struct builtin_chain *chain, int policy)
{
	struct nft_chain *c;

	c = nft_chain_alloc();
	if (c == NULL)
		return NULL;

	nft_chain_attr_set(c, NFT_CHAIN_ATTR_TABLE, (char *)table->name);
	nft_chain_attr_set(c, NFT_CHAIN_ATTR_NAME, (char *)chain->name);
	nft_chain_attr_set_u32(c, NFT_CHAIN_ATTR_HOOKNUM, chain->hook);
	nft_chain_attr_set_u32(c, NFT_CHAIN_ATTR_PRIO, table->prio);
	nft_chain_attr_set_u32(c, NFT_CHAIN_ATTR_POLICY, policy);

	return c;
}

static void
nft_chain_builtin_add(struct nft_handle *h, struct builtin_table *table,
		      struct builtin_chain *chain, int policy)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_chain *c;

	c = nft_chain_builtin_alloc(table, chain, policy);
	if (c == NULL)
		return;

	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_NEWCHAIN, AF_INET,
					NLM_F_ACK|NLM_F_EXCL, h->seq);
	nft_chain_nlmsg_build_payload(nlh, c);
	nft_chain_free(c);

	if (mnl_talk(h, nlh, NULL, NULL) < 0) {
		if (errno != EEXIST)
			perror("mnl_talk:nft_chain_builtin_add");
	}
}

/* find if built-in table already exists */
static struct builtin_table *nft_table_builtin_find(const char *table)
{
	int i;
	bool found = false;

	for (i=0; i<TABLES_MAX; i++) {
		if (strcmp(tables[i].name, table) != 0)
			continue;

		found = true;
		break;
	}

	return found ? &tables[i] : NULL;
}

/* find if built-in chain already exists */
static struct builtin_chain *
nft_chain_builtin_find(struct builtin_table *t, const char *chain)
{
	int i;
	bool found = false;

	for (i=0; i<NF_IP_NUMHOOKS && t->chains[i].name != NULL; i++) {
		if (strcmp(t->chains[i].name, chain) != 0)
			continue;

		found = true;
		break;
	}
	return found ? &t->chains[i] : NULL;
}

static void
__nft_chain_builtin_init(struct nft_handle *h,
			 struct builtin_table *table, const char *chain,
			 int policy)
{
	int i, default_policy;

	/* Initialize all built-in chains. Exception, for e one received as
	 * parameter, set the default policy as requested.
	 */
	for (i=0; i<NF_IP_NUMHOOKS && table->chains[i].name != NULL; i++) {
		if (chain && strcmp(table->chains[i].name, chain) == 0)
			default_policy = policy;
		else
			default_policy = NF_ACCEPT;

		nft_chain_builtin_add(h, table, &table->chains[i],
					default_policy);
	}
}

static int
nft_chain_builtin_init(struct nft_handle *h, const char *table,
		       const char *chain, int policy)
{
	int ret = 0;
	struct builtin_table *t;

	t = nft_table_builtin_find(table);
	if (t == NULL) {
		ret = -1;
		goto out;
	}
	if (nft_table_builtin_add(h, table) < 0) {
		/* Built-in table already initialized, skip. */
		if (errno == EEXIST)
			goto out;
	}
	__nft_chain_builtin_init(h, t, chain, policy);
out:
	return ret;
}

int nft_init(struct nft_handle *h)
{
	h->nl = mnl_socket_open(NETLINK_NETFILTER);
	if (h->nl == NULL) {
		perror("mnl_socket_open");
		return -1;
	}

	if (mnl_socket_bind(h->nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		return -1;
	}
	h->portid = mnl_socket_get_portid(h->nl);

	return 0;
}

void nft_fini(struct nft_handle *h)
{
	mnl_socket_close(h->nl);
}

int nft_table_add(struct nft_handle *h, const struct nft_table *t)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nft_table_nlmsg_build_hdr(buf, NFT_MSG_NEWTABLE, AF_INET,
					NLM_F_ACK|NLM_F_EXCL, h->seq);
	nft_table_nlmsg_build_payload(nlh, t);

	return mnl_talk(h, nlh, NULL, NULL);
}

int nft_chain_add(struct nft_handle *h, const struct nft_chain *c)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_NEWCHAIN, AF_INET,
					NLM_F_ACK|NLM_F_EXCL, h->seq);
	nft_chain_nlmsg_build_payload(nlh, c);

	return mnl_talk(h, nlh, NULL, NULL);
}

static void nft_chain_print_debug(struct nft_chain *c, struct nlmsghdr *nlh)
{
#ifdef NLDEBUG
	char tmp[1024];

	nft_chain_snprintf(tmp, sizeof(tmp), c, 0, 0);
	printf("DEBUG: chain: %s", tmp);
	mnl_nlmsg_fprintf(stdout, nlh, nlh->nlmsg_len, sizeof(struct nfgenmsg));
#endif
}

static int
__nft_chain_set(struct nft_handle *h, const char *table,
		const char *chain, int policy,
		const struct xt_counters *counters)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_chain *c;
	struct builtin_table *_t;
	struct builtin_chain *_c;
	int ret;

	_t = nft_table_builtin_find(table);
	/* if this built-in table does not exists, create it */
	if (_t != NULL)
		nft_table_builtin_add(h, table);

	_c = nft_chain_builtin_find(_t, chain);
	if (_c != NULL) {
		/* This is a built-in chain */
		c = nft_chain_builtin_alloc(_t, _c, policy);
		if (c == NULL)
			return -1;

	} else {
		/* This is a custom chain */
		c = nft_chain_alloc();
		if (c == NULL)
			return -1;

		nft_chain_attr_set(c, NFT_CHAIN_ATTR_TABLE, (char *)table);
		nft_chain_attr_set(c, NFT_CHAIN_ATTR_NAME, (char *)chain);
		nft_chain_attr_set_u32(c, NFT_CHAIN_ATTR_POLICY, policy);
	}

	if (counters) {
		nft_chain_attr_set_u64(c, NFT_CHAIN_ATTR_BYTES,
					counters->bcnt);
		nft_chain_attr_set_u64(c, NFT_CHAIN_ATTR_PACKETS,
					counters->pcnt);
	}

	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_NEWCHAIN, AF_INET,
					NLM_F_ACK, h->seq);
	nft_chain_nlmsg_build_payload(nlh, c);

	nft_chain_print_debug(c, nlh);

	nft_chain_free(c);

	ret = mnl_talk(h, nlh, NULL, NULL);
	if (ret < 0)
		perror("mnl_talk:__nft_chain_policy");

	return ret;
}

int nft_chain_set(struct nft_handle *h, const char *table,
		  const char *chain, const char *policy,
		  const struct xt_counters *counters)
{
	int ret = -1;

	nft_fn = nft_chain_set;

	if (strcmp(policy, "DROP") == 0)
		ret = __nft_chain_set(h, table, chain, NF_DROP, counters);
	else if (strcmp(policy, "ACCEPT") == 0)
		ret = __nft_chain_set(h, table, chain, NF_ACCEPT, counters);

	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

static void __add_match(struct nft_rule_expr *e, struct xt_entry_match *m)
{
	void *info;

	nft_rule_expr_set(e, NFT_EXPR_MT_NAME, m->u.user.name, strlen(m->u.user.name));
	nft_rule_expr_set_u32(e, NFT_EXPR_MT_REV, m->u.user.revision);

	info = calloc(1, m->u.match_size);
	if (info == NULL)
		return;

	memcpy(info, m->data, m->u.match_size);
	nft_rule_expr_set(e, NFT_EXPR_MT_INFO, info, m->u.match_size - sizeof(*m));
}

static void add_match(struct nft_rule *r, struct xt_entry_match *m)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("match");
	if (expr == NULL)
		return;

	__add_match(expr, m);
	nft_rule_add_expr(r, expr);
}

static void __add_target(struct nft_rule_expr *e, struct xt_entry_target *t)
{
	void *info = NULL;

	nft_rule_expr_set(e, NFT_EXPR_TG_NAME, t->u.user.name,
			  strlen(t->u.user.name));
	nft_rule_expr_set_u32(e, NFT_EXPR_TG_REV, t->u.user.revision);

	if (info == NULL) {
		info = calloc(1, t->u.target_size);
		if (info == NULL)
			return;

		memcpy(info, t->data, t->u.target_size);
	}

	nft_rule_expr_set(e, NFT_EXPR_TG_INFO, info, t->u.target_size - sizeof(*t));
}

static void add_target(struct nft_rule *r, struct xt_entry_target *t)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("target");
	if (expr == NULL)
		return;

	__add_target(expr, t);
	nft_rule_add_expr(r, expr);
}

static void add_jumpto(struct nft_rule *r, const char *name, int verdict)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("immediate");
	if (expr == NULL)
		return;

	nft_rule_expr_set_u32(expr, NFT_EXPR_IMM_DREG, NFT_REG_VERDICT);
	nft_rule_expr_set_u32(expr, NFT_EXPR_IMM_VERDICT, verdict);
	nft_rule_expr_set_str(expr, NFT_EXPR_IMM_CHAIN, (char *)name);
	nft_rule_add_expr(r, expr);
}

static void add_verdict(struct nft_rule *r, int verdict)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("immediate");
	if (expr == NULL)
		return;

	nft_rule_expr_set_u32(expr, NFT_EXPR_IMM_DREG, NFT_REG_VERDICT);
	nft_rule_expr_set_u32(expr, NFT_EXPR_IMM_VERDICT, verdict);
	nft_rule_add_expr(r, expr);
}

static void nft_rule_print_debug(struct nft_rule *r, struct nlmsghdr *nlh)
{
#ifdef NLDEBUG
	char tmp[1024];

	nft_rule_snprintf(tmp, sizeof(tmp), r, 0, 0);
	printf("DEBUG: rule: %s", tmp);
	mnl_nlmsg_fprintf(stdout, nlh, nlh->nlmsg_len, sizeof(struct nfgenmsg));
#endif
}

static void add_meta(struct nft_rule *r, uint32_t key)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("meta");
	if (expr == NULL)
		return;

	nft_rule_expr_set_u32(expr, NFT_EXPR_META_KEY, key);
	nft_rule_expr_set_u32(expr, NFT_EXPR_META_DREG, NFT_REG_1);

	nft_rule_add_expr(r, expr);
}

static void add_payload(struct nft_rule *r, int offset, int len)
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
static void add_bitwise_u16(struct nft_rule *r, int mask, int xor)
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

static void add_cmp_ptr(struct nft_rule *r, uint32_t op, void *data, size_t len)
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

static void add_cmp_u16(struct nft_rule *r, uint16_t val, uint32_t op)
{
	add_cmp_ptr(r, op, &val, sizeof(val));
}

static void add_cmp_u32(struct nft_rule *r, uint32_t val, uint32_t op)
{
	add_cmp_ptr(r, op, &val, sizeof(val));
}

static void add_counters(struct nft_rule *r, uint64_t packets, uint64_t bytes)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("counter");
	if (expr == NULL)
		return;

	nft_rule_expr_set_u64(expr, NFT_EXPR_CTR_BYTES, packets);
	nft_rule_expr_set_u64(expr, NFT_EXPR_CTR_PACKETS, bytes);

	nft_rule_add_expr(r, expr);
}

int
nft_rule_add(struct nft_handle *h, const char *chain, const char *table,
	     struct iptables_command_state *cs, bool append, bool verbose)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct xtables_rule_match *matchp;
	struct nft_rule *r;
	int ret = 1;
	uint32_t op;
	int flags = append ? NLM_F_APPEND : 0;

	/* If built-in chains don't exist for this table, create them */
	nft_chain_builtin_init(h, table, chain, NF_ACCEPT);

	nft_fn = nft_rule_add;

	r = nft_rule_alloc();
	if (r == NULL) {
		ret = 0;
		goto err;
	}

	nft_rule_attr_set(r, NFT_RULE_ATTR_TABLE, (char *)table);
	nft_rule_attr_set(r, NFT_RULE_ATTR_CHAIN, (char *)chain);

	if (cs->fw.ip.iniface[0] != '\0') {
		int iface_len = strlen(cs->fw.ip.iniface);

		if (cs->fw.ip.invflags & IPT_INV_VIA_IN)
			op = NFT_CMP_NEQ;
		else
			op = NFT_CMP_EQ;

		if (cs->fw.ip.iniface[iface_len - 1] == '+') {
			add_meta(r, NFT_META_IIFNAME);
			add_cmp_ptr(r, op, cs->fw.ip.iniface, iface_len - 1);
		} else {
			add_meta(r, NFT_META_IIF);
			add_cmp_u32(r, if_nametoindex(cs->fw.ip.iniface), op);
		}
	}
	if (cs->fw.ip.outiface[0] != '\0') {
		int iface_len = strlen(cs->fw.ip.outiface);

		if (cs->fw.ip.invflags & IPT_INV_VIA_OUT)
			op = NFT_CMP_NEQ;
		else
			op = NFT_CMP_EQ;

		if (cs->fw.ip.outiface[iface_len - 1] == '+') {
			add_meta(r, NFT_META_OIFNAME);
			add_cmp_ptr(r, op, cs->fw.ip.outiface, iface_len - 1);
		} else {
			add_meta(r, NFT_META_OIF);
			add_cmp_u32(r, if_nametoindex(cs->fw.ip.outiface), op);
		}
	}
	if (cs->fw.ip.src.s_addr != 0) {
		add_payload(r, offsetof(struct iphdr, saddr), 4);
		if (cs->fw.ip.invflags & IPT_INV_SRCIP)
			op = NFT_CMP_NEQ;
		else
			op = NFT_CMP_EQ;

		add_cmp_u32(r, cs->fw.ip.src.s_addr, op);
	}
	if (cs->fw.ip.dst.s_addr != 0) {
		add_payload(r, offsetof(struct iphdr, daddr), 4);
		if (cs->fw.ip.invflags & IPT_INV_DSTIP)
			op = NFT_CMP_NEQ;
		else
			op = NFT_CMP_EQ;

		add_cmp_u32(r, cs->fw.ip.dst.s_addr, op);
	}
	if (cs->fw.ip.proto != 0) {
		add_payload(r, offsetof(struct iphdr, protocol), 1);
		if (cs->fw.ip.invflags & XT_INV_PROTO)
			op = NFT_CMP_NEQ;
		else
			op = NFT_CMP_EQ;

		add_cmp_u32(r, cs->fw.ip.proto, op);
	}
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

	for (matchp = cs->matches; matchp; matchp = matchp->next)
		add_match(r, matchp->match->m);

	/* Counters need to me added before the target, otherwise they are
	 * increased for each rule because of the way nf_tables works.
	 */
	add_counters(r, cs->counters.pcnt, cs->counters.bcnt);

	/* If no target at all, add nothing (default to continue) */
	if (cs->target != NULL) {
		/* Standard target? */
		if (strcmp(cs->jumpto, XTC_LABEL_ACCEPT) == 0)
			add_verdict(r, NF_ACCEPT);
		else if (strcmp(cs->jumpto, XTC_LABEL_DROP) == 0)
			add_verdict(r, NF_DROP);
		else if (strcmp(cs->jumpto, XTC_LABEL_RETURN) == 0)
			add_verdict(r, NFT_RETURN);
		else
			add_target(r, cs->target->t);
	} else if (strlen(cs->jumpto) > 0) {
		/* Not standard, then it's a go / jump to chain */
		if (cs->fw.ip.flags & IPT_F_GOTO)
			add_jumpto(r, cs->jumpto, NFT_GOTO);
		else
			add_jumpto(r, cs->jumpto, NFT_JUMP);
	}

	/* NLM_F_CREATE autoloads the built-in table if it does not exists */
	nlh = nft_rule_nlmsg_build_hdr(buf, NFT_MSG_NEWRULE, AF_INET,
					NLM_F_ACK|NLM_F_CREATE|flags, h->seq);
	nft_rule_nlmsg_build_payload(nlh, r);

	nft_rule_print_debug(r, nlh);

	nft_rule_free(r);

	ret = mnl_talk(h, nlh, NULL, NULL);
	if (ret < 0)
		perror("mnl_talk:nft_rule_add");

err:
	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

static void nft_match_save(struct nft_rule_expr *expr)
{
	const char *name;
	const struct xtables_match *match;
	struct xt_entry_match *emu;
	const void *mtinfo;
	size_t len;

	name = nft_rule_expr_get_str(expr, NFT_EXPR_MT_NAME);

	match = xtables_find_match(name, XTF_TRY_LOAD, NULL);
	if (match == NULL)
		return;

	mtinfo = nft_rule_expr_get(expr, NFT_EXPR_MT_INFO, &len);
	if (mtinfo == NULL)
		return;

	emu = calloc(1, sizeof(struct xt_entry_match) + len);
	if (emu == NULL)
		return;

	memcpy(&emu->data, mtinfo, len);

	if (match->alias)
		printf("-m %s", match->alias(emu));
	else
		printf("-m %s", match->name);

	/* FIXME missing parameter */
	match->save(NULL, emu);

	printf(" ");

	free(emu);
}

static void nft_target_save(struct nft_rule_expr *expr)
{
	const char *name;
	const struct xtables_target *target;
	struct xt_entry_target *emu;
	const void *tginfo;
	size_t len;

	name = nft_rule_expr_get_str(expr, NFT_EXPR_TG_NAME);

	/* Standard target not supported, we use native immediate expression */
	if (strcmp(name, "") == 0) {
		printf("ERROR: standard target seen, should not happen\n");
		return;
	}

	target = xtables_find_target(name, XTF_TRY_LOAD);
	if (target == NULL)
		return;

	tginfo = nft_rule_expr_get(expr, NFT_EXPR_TG_INFO, &len);
	if (tginfo == NULL)
		return;

	emu = calloc(1, sizeof(struct xt_entry_match) + len);
	if (emu == NULL)
		return;

	memcpy(emu->data, tginfo, len);

	if (target->alias)
		printf("-j %s", target->alias(emu));
	else
		printf("-j %s", target->name);

	/* FIXME missing parameter */
	target->save(NULL, emu);

	free(emu);
}

static void nft_immediate_save(struct nft_rule_expr *expr)
{
	uint32_t verdict;

	verdict = nft_rule_expr_get_u32(expr, NFT_EXPR_IMM_VERDICT);

	switch(verdict) {
	case NF_ACCEPT:
		printf("-j ACCEPT");
		break;
	case NF_DROP:
		printf("-j DROP");
		break;
	case NFT_RETURN:
		printf("-j RETURN");
		break;
	case NFT_GOTO:
		printf("-g %s",
			nft_rule_expr_get_str(expr, NFT_EXPR_IMM_CHAIN));
		break;
	case NFT_JUMP:
		printf("-j %s",
			nft_rule_expr_get_str(expr, NFT_EXPR_IMM_CHAIN));
		break;
	}
}

static void
nft_print_meta(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter)
{
	uint8_t key = nft_rule_expr_get_u8(e, NFT_EXPR_META_KEY);
	uint32_t value;
	const char *name;
	char ifname[IFNAMSIZ];
	const char *ifname_ptr;
	size_t len;

	e = nft_rule_expr_iter_next(iter);
	if (e == NULL)
		return;

	name = nft_rule_expr_get_str(e, NFT_RULE_EXPR_ATTR_NAME);
	/* meta should be followed by cmp */
	if (strcmp(name, "cmp") != 0) {
		DEBUGP("skipping no cmp after meta\n");
		return;
	}

	switch(key) {
	case NFT_META_IIF:
		value = nft_rule_expr_get_u32(e, NFT_EXPR_CMP_DATA);
		if_indextoname(value, ifname);

		switch(nft_rule_expr_get_u8(e, NFT_EXPR_CMP_OP)) {
		case NFT_CMP_EQ:
			printf("-i %s ", ifname);
			break;
		case NFT_CMP_NEQ:
			printf("! -i %s ", ifname);
			break;
		}
		break;
	case NFT_META_OIF:
		value = nft_rule_expr_get_u32(e, NFT_EXPR_CMP_DATA);
		if_indextoname(value, ifname);

		switch(nft_rule_expr_get_u8(e, NFT_EXPR_CMP_OP)) {
		case NFT_CMP_EQ:
			printf("-o %s ", ifname);
			break;
		case NFT_CMP_NEQ:
			printf("! -o %s ", ifname);
			break;
		}
		break;
	case NFT_META_IIFNAME:
		ifname_ptr = nft_rule_expr_get(e, NFT_EXPR_CMP_DATA, &len);
		memcpy(ifname, ifname_ptr, len);
		ifname[len] = '\0';

		/* if this is zero, then assume this is a interface mask */
		if (if_nametoindex(ifname) == 0) {
			ifname[len] = '+';
			ifname[len+1] = '\0';
		}

		switch(nft_rule_expr_get_u8(e, NFT_EXPR_CMP_OP)) {
		case NFT_CMP_EQ:
			printf("-i %s ", ifname);
			break;
		case NFT_CMP_NEQ:
			printf("! -i %s ", ifname);
			break;
		}
		break;
	case NFT_META_OIFNAME:
		ifname_ptr = nft_rule_expr_get(e, NFT_EXPR_CMP_DATA, &len);
		memcpy(ifname, ifname_ptr, len);
		ifname[len] = '\0';

		/* if this is zero, then assume this is a interface mask */
		if (if_nametoindex(ifname) == 0) {
			ifname[len] = '+';
			ifname[len+1] = '\0';
		}

		switch(nft_rule_expr_get_u8(e, NFT_EXPR_CMP_OP)) {
		case NFT_CMP_EQ:
			printf("-o %s ", ifname);
			break;
		case NFT_CMP_NEQ:
			printf("! -o %s ", ifname);
			break;
		}
		break;
	default:
		DEBUGP("unknown meta key %d\n", key);
		break;
	}
}

static void
get_cmp_data(struct nft_rule_expr_iter *iter, void *data, size_t dlen, bool *inv)
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

static void print_frag(bool inv)
{
	if (inv)
		printf("! -f ");
	else
		printf("-f ");
}

static void print_proto(uint16_t proto, int invert)
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

static void
nft_print_payload(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter)
{
	uint32_t offset;
	bool inv;

	offset = nft_rule_expr_get_u32(e, NFT_EXPR_PAYLOAD_OFFSET);

	switch(offset) {
	struct in_addr addr;
	uint8_t proto;

	case offsetof(struct iphdr, saddr):
		get_cmp_data(iter, &addr, sizeof(addr), &inv);
		if (inv)
			printf("! -s %s/%s ", inet_ntoa(addr),
						mask_to_str(0xffffffff));
		else
			printf("-s %s/%s ", inet_ntoa(addr),
						mask_to_str(0xffffffff));
		break;
	case offsetof(struct iphdr, daddr):
		get_cmp_data(iter, &addr, sizeof(addr), &inv);
		if (inv)
			printf("! -d %s/%s ", inet_ntoa(addr),
						mask_to_str(0xffffffff));
		else
			printf("-d %s/%s ", inet_ntoa(addr),
						mask_to_str(0xffffffff));
		break;
	case offsetof(struct iphdr, protocol):
		get_cmp_data(iter, &proto, sizeof(proto), &inv);
		print_proto(proto, inv);
		break;
	case offsetof(struct iphdr, frag_off):
		get_frag(iter, &inv);
		print_frag(inv);
		break;
	default:
		DEBUGP("unknown payload offset %d\n", offset);
		break;
	}
}

static void
nft_print_counters(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
		   bool counters)
{
	if (counters) {
		printf("-c %lu %lu ",
			nft_rule_expr_get_u64(e, NFT_EXPR_CTR_PACKETS),
			nft_rule_expr_get_u64(e, NFT_EXPR_CTR_BYTES));
	}
}

static void nft_rule_print_save(struct nft_rule *r, bool counters)
{
	struct nft_rule_expr_iter *iter;
	struct nft_rule_expr *expr;

	/* print chain name */
	printf("-A %s ", nft_rule_attr_get_str(r, NFT_RULE_ATTR_CHAIN));

	iter = nft_rule_expr_iter_create(r);
	if (iter == NULL)
		return;

	expr = nft_rule_expr_iter_next(iter);
	while (expr != NULL) {
		const char *name =
			nft_rule_expr_get_str(expr, NFT_RULE_EXPR_ATTR_NAME);

		if (strcmp(name, "counter") == 0) {
			nft_print_counters(expr, iter, counters);
		} else if (strcmp(name, "payload") == 0) {
			nft_print_payload(expr, iter);
		} else if (strcmp(name, "meta") == 0) {
			nft_print_meta(expr, iter);
		} else if (strcmp(name, "match") == 0) {
			nft_match_save(expr);
		} else if (strcmp(name, "target") == 0) {
			nft_target_save(expr);
		} else if (strcmp(name, "immediate") == 0) {
			nft_immediate_save(expr);
		}

		expr = nft_rule_expr_iter_next(iter);
	}

	printf("\n");
}

static int nft_chain_list_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nft_chain *c;
	struct nft_chain_list *list = data;

	c = nft_chain_alloc();
	if (c == NULL) {
		perror("OOM");
		goto err;
	}

	if (nft_chain_nlmsg_parse(nlh, c) < 0) {
		perror("nft_rule_nlmsg_parse");
		goto out;
	}

	nft_chain_list_add(c, list);

	return MNL_CB_OK;
out:
	nft_chain_free(c);
err:
	return MNL_CB_OK;
}

static struct nft_chain_list *nft_chain_list_get(struct nft_handle *h)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	int ret;
	struct nft_chain_list *list;

	list = nft_chain_list_alloc();
	if (list == NULL) {
		DEBUGP("cannot allocate rule list\n");
		return 0;
	}

	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_GETCHAIN, AF_INET,
					NLM_F_DUMP, h->seq);

	ret = mnl_talk(h, nlh, nft_chain_list_cb, list);
	if (ret < 0)
		perror("mnl_talk:nft_chain_list_get");

	return list;
}

struct nft_chain_list *nft_chain_dump(struct nft_handle *h)
{
	return nft_chain_list_get(h);
}

static const char *policy_name[NF_ACCEPT+1] = {
	[NF_DROP] = "DROP",
	[NF_ACCEPT] = "ACCEPT",
};

static void nft_chain_print_save(struct nft_chain *c, bool basechain)
{
	const char *chain = nft_chain_attr_get_str(c, NFT_CHAIN_ATTR_NAME);
	uint64_t pkts = nft_chain_attr_get_u64(c, NFT_CHAIN_ATTR_PACKETS);
	uint64_t bytes = nft_chain_attr_get_u64(c, NFT_CHAIN_ATTR_BYTES);

	/* print chain name */
	if (basechain) {
		uint32_t pol = NF_ACCEPT;

		/* no default chain policy? don't crash, display accept */
		if (nft_chain_attr_get(c, NFT_CHAIN_ATTR_POLICY))
			pol = nft_chain_attr_get_u32(c, NFT_CHAIN_ATTR_POLICY);

		printf(":%s %s [%lu:%lu]\n", chain, policy_name[pol],
					     pkts, bytes);
	} else
		printf(":%s - [%lu:%lu]\n", chain, pkts, bytes);
}

int nft_chain_save(struct nft_handle *h, struct nft_chain_list *list,
		   const char *table)
{
	struct nft_chain_list_iter *iter;
	struct nft_chain *c;

	iter = nft_chain_list_iter_create(list);
	if (iter == NULL) {
		DEBUGP("cannot allocate rule list iterator\n");
		return 0;
	}

	c = nft_chain_list_iter_next(iter);
	while (c != NULL) {
		const char *chain_table =
			nft_chain_attr_get_str(c, NFT_CHAIN_ATTR_TABLE);
		bool basechain = false;

		if (strcmp(table, chain_table) != 0)
			goto next;

		if (nft_chain_attr_get(c, NFT_CHAIN_ATTR_HOOKNUM))
			basechain = true;

		nft_chain_print_save(c, basechain);
next:
		c = nft_chain_list_iter_next(iter);
	}

	nft_chain_list_free(list);

	return 1;
}

static int nft_rule_list_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nft_rule *r;
	struct nft_rule_list *list = data;

	r = nft_rule_alloc();
	if (r == NULL) {
		perror("OOM");
		goto err;
	}

	if (nft_rule_nlmsg_parse(nlh, r) < 0) {
		perror("nft_rule_nlmsg_parse");
		goto out;
	}

	nft_rule_list_add(r, list);

	return MNL_CB_OK;
out:
	nft_rule_free(r);
err:
	return MNL_CB_OK;
}

static struct nft_rule_list *nft_rule_list_get(struct nft_handle *h)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_rule_list *list;
	int ret;

	list = nft_rule_list_alloc();
	if (list == NULL) {
		DEBUGP("cannot allocate rule list\n");
		return 0;
	}

	nlh = nft_rule_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, AF_INET,
					NLM_F_DUMP, h->seq);

	ret = mnl_talk(h, nlh, nft_rule_list_cb, list);
	if (ret < 0) {
		perror("mnl_talk:nft_rule_save");
		nft_rule_list_free(list);
		return NULL;
	}

	return list;
}

int nft_rule_save(struct nft_handle *h, const char *table, bool counters)
{
	struct nft_rule_list *list;
	struct nft_rule_list_iter *iter;
	struct nft_rule *r;

	list = nft_rule_list_get(h);
	if (list == NULL) {
		DEBUGP("cannot retrieve rule list from kernel\n");
		return 0;
	}

	iter = nft_rule_list_iter_create(list);
	if (iter == NULL) {
		DEBUGP("cannot allocate rule list iterator\n");
		return 0;
	}

	r = nft_rule_list_iter_next(iter);
	while (r != NULL) {
		const char *rule_table =
			nft_rule_attr_get_str(r, NFT_RULE_ATTR_TABLE);

		if (strcmp(table, rule_table) != 0)
			goto next;

		nft_rule_print_save(r, counters);

next:
		r = nft_rule_list_iter_next(iter);
	}

	nft_rule_list_free(list);

	/* the core expects 1 for success and 0 for error */
	return 1;
}

static void
__nft_rule_flush(struct nft_handle *h, const char *table, const char *chain)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_rule *r;

	r = nft_rule_alloc();
	if (r == NULL)
		return;

	nft_rule_attr_set(r, NFT_RULE_ATTR_TABLE, (char *)table);
	nft_rule_attr_set(r, NFT_RULE_ATTR_CHAIN, (char *)chain);

	/* Delete all rules in this table + chain */
	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_DELRULE, AF_INET,
					NLM_F_ACK, h->seq);
	nft_rule_nlmsg_build_payload(nlh, r);
	nft_rule_free(r);

	if (mnl_talk(h, nlh, NULL, NULL) < 0) {
		if (errno != EEXIST)
			perror("mnl_talk:__nft_rule_flush");
	}
}

int nft_rule_flush(struct nft_handle *h, const char *chain, const char *table)
{
	int ret;
	struct nft_chain_list *list;
	struct nft_chain_list_iter *iter;
	struct nft_chain *c;

	nft_fn = nft_rule_flush;

	list = nft_chain_list_get(h);
	if (list == NULL) {
		ret = 0;
		goto err;
	}

	iter = nft_chain_list_iter_create(list);
	if (iter == NULL) {
		DEBUGP("cannot allocate rule list iterator\n");
		return 0;
	}

	c = nft_chain_list_iter_next(iter);
	while (c != NULL) {
		const char *table_name =
			nft_chain_attr_get_str(c, NFT_CHAIN_ATTR_TABLE);
		const char *chain_name =
			nft_chain_attr_get_str(c, NFT_CHAIN_ATTR_NAME);

		if (strcmp(table, table_name) != 0)
			goto next;

		if (chain != NULL && strcmp(chain, chain_name) != 0)
			goto next;

		__nft_rule_flush(h, table_name, chain_name);

next:
		c = nft_chain_list_iter_next(iter);
	}

err:
	nft_chain_list_free(list);

	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

int nft_chain_user_add(struct nft_handle *h, const char *chain, const char *table)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_chain *c;
	int ret;

	/* If built-in chains don't exist for this table, create them */
	nft_chain_builtin_init(h, table, NULL, NF_ACCEPT);

	c = nft_chain_alloc();
	if (c == NULL) {
		DEBUGP("cannot allocate chain\n");
		return -1;
	}

	nft_chain_attr_set(c, NFT_CHAIN_ATTR_TABLE, (char *)table);
	nft_chain_attr_set(c, NFT_CHAIN_ATTR_NAME, (char *)chain);

	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_NEWCHAIN, AF_INET,
					NLM_F_ACK|NLM_F_EXCL, h->seq);
	nft_chain_nlmsg_build_payload(nlh, c);
	nft_chain_free(c);

	ret = mnl_talk(h, nlh, NULL, NULL);
	if (ret < 0) {
		if (errno != EEXIST)
			perror("mnl_talk:nft_chain_add");
	}

	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

static int __nft_chain_del(struct nft_handle *h, struct nft_chain *c)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	int ret;

	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_DELCHAIN, AF_INET,
					NLM_F_ACK, h->seq);
	nft_chain_nlmsg_build_payload(nlh, c);

	ret = mnl_talk(h, nlh, NULL, NULL);
	if (ret < 0) {
		if (errno != EEXIST && errno != ENOENT)
			perror("mnl_talk:__nft_chain_del");
	}

	return ret;
}

static bool nft_chain_builtin(struct nft_chain *c)
{
	/* Check if this chain has hook number, in that case is built-in.
	 * Should we better export the flags to user-space via nf_tables?
	 */
	return nft_chain_attr_get(c, NFT_CHAIN_ATTR_HOOKNUM) != NULL;
}

int nft_chain_user_del(struct nft_handle *h, const char *chain, const char *table)
{
	struct nft_chain_list *list;
	struct nft_chain_list_iter *iter;
	struct nft_chain *c;
	int ret = 0;
	int deleted_ctr = 0;

	list = nft_chain_list_get(h);
	if (list == NULL)
		goto err;

	iter = nft_chain_list_iter_create(list);
	if (iter == NULL) {
		DEBUGP("cannot allocate rule list iterator\n");
		return 0;
	}

	c = nft_chain_list_iter_next(iter);
	while (c != NULL) {
		const char *table_name =
			nft_chain_attr_get_str(c, NFT_CHAIN_ATTR_TABLE);
		const char *chain_name =
			nft_chain_attr_get_str(c, NFT_CHAIN_ATTR_NAME);

		/* don't delete built-in chain */
		if (nft_chain_builtin(c))
			goto next;

		if (strcmp(table, table_name) != 0)
			goto next;

		if (chain != NULL && strcmp(chain, chain_name) != 0)
			goto next;

		ret = __nft_chain_del(h, c);
		if (ret < 0)
			break;

		deleted_ctr++;
next:
		c = nft_chain_list_iter_next(iter);
	}

err:
	nft_chain_list_free(list);

	/* chain not found */
	if (ret < 0 && deleted_ctr == 0)
		errno = ENOENT;

	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

int nft_chain_user_rename(struct nft_handle *h,const char *chain,
			  const char *table, const char *newname)
{
	int ret;

	/* XXX need new operation in nf_tables to support this */
	ret = nft_chain_user_del(h, chain, table);
	if (ret < 0)
		return ret;

	return nft_chain_user_add(h, newname, table);
}

static int nft_table_list_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nft_table *t;
	struct nft_table_list *list = data;

	t = nft_table_alloc();
	if (t == NULL) {
		perror("OOM");
		goto err;
	}

	if (nft_table_nlmsg_parse(nlh, t) < 0) {
		perror("nft_rule_nlmsg_parse");
		goto out;
	}

	nft_table_list_add(t, list);

	return MNL_CB_OK;
out:
	nft_table_free(t);
err:
	return MNL_CB_OK;
}

static struct nft_table_list *nft_table_list_get(struct nft_handle *h)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	int ret;
	struct nft_table_list *list;

	list = nft_table_list_alloc();
	if (list == NULL) {
		DEBUGP("cannot allocate table list\n");
		return 0;
	}

	nlh = nft_rule_nlmsg_build_hdr(buf, NFT_MSG_GETTABLE, AF_INET,
					NLM_F_DUMP, h->seq);

	ret = mnl_talk(h, nlh, nft_table_list_cb, list);
	if (ret < 0)
		perror("mnl_talk:nft_table_list_get");

	return list;
}

bool nft_table_find(struct nft_handle *h, const char *tablename)
{
	struct nft_table_list *list;
	struct nft_table_list_iter *iter;
	struct nft_table *t;
	bool ret = false;

	list = nft_table_list_get(h);
	if (list == NULL)
		goto err;

	iter = nft_table_list_iter_create(list);
	if (iter == NULL) {
		DEBUGP("cannot allocate rule list iterator\n");
		goto err;
	}

	t = nft_table_list_iter_next(iter);
	while (t != NULL) {
		const char *this_tablename =
			nft_table_attr_get(t, NFT_TABLE_ATTR_NAME);

		if (strcmp(tablename, this_tablename) == 0)
			return true;

		t = nft_table_list_iter_next(iter);
	}

	nft_table_list_free(list);

err:
	return ret;
}

int nft_for_each_table(struct nft_handle *h,
		       int (*func)(struct nft_handle *h, const char *tablename, bool counters),
		       bool counters)
{
	int ret = 1;
	struct nft_table_list *list;
	struct nft_table_list_iter *iter;
	struct nft_table *t;

	list = nft_table_list_get(h);
	if (list == NULL) {
		ret = 0;
		goto err;
	}

	iter = nft_table_list_iter_create(list);
	if (iter == NULL) {
		DEBUGP("cannot allocate rule list iterator\n");
		return 0;
	}

	t = nft_table_list_iter_next(iter);
	while (t != NULL) {
		const char *tablename =
			nft_table_attr_get(t, NFT_TABLE_ATTR_NAME);

		func(h, tablename, counters);

		t = nft_table_list_iter_next(iter);
	}

	nft_table_list_free(list);

err:
	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

static inline int
match_different(const struct xt_entry_match *a,
		const unsigned char *a_elems,
		const unsigned char *b_elems,
		unsigned char **maskptr)
{
	const struct xt_entry_match *b;
	unsigned int i;

	/* Offset of b is the same as a. */
	b = (void *)b_elems + ((unsigned char *)a - a_elems);

	if (a->u.match_size != b->u.match_size)
		return 1;

	if (strcmp(a->u.user.name, b->u.user.name) != 0)
		return 1;

	*maskptr += XT_ALIGN(sizeof(*a));

	for (i = 0; i < a->u.match_size - XT_ALIGN(sizeof(*a)); i++)
		if (((a->data[i] ^ b->data[i]) & (*maskptr)[i]) != 0)
			return 1;
	*maskptr += i;
	return 0;
}

static bool
is_same(const struct iptables_command_state *a, const struct iptables_command_state *b)
{
	unsigned int i;

	/* Always compare head structures: ignore mask here. */
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

	for (i = 0; i < IFNAMSIZ; i++) {
		if (a->fw.ip.iniface_mask[i] != b->fw.ip.iniface_mask[i]) {
			DEBUGP("different iniface mask %x, %x (%d)\n",
			a->fw.ip.iniface_mask[i] & 0xff, b->fw.ip.iniface_mask[i] & 0xff, i);
			return false;
		}
		if ((a->fw.ip.iniface[i] & a->fw.ip.iniface_mask[i])
		    != (b->fw.ip.iniface[i] & b->fw.ip.iniface_mask[i])) {
			DEBUGP("different iniface\n");
			return false;
		}
		if (a->fw.ip.outiface_mask[i] != b->fw.ip.outiface_mask[i]) {
			DEBUGP("different outiface mask\n");
			return false;
		}
		if ((a->fw.ip.outiface[i] & a->fw.ip.outiface_mask[i])
		    != (b->fw.ip.outiface[i] & b->fw.ip.outiface_mask[i])) {
			DEBUGP("different outiface\n");
			return false;
		}
	}

	return true;
}

static void
nft_parse_meta(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
	       struct iptables_command_state *cs)
{
	uint8_t key = nft_rule_expr_get_u8(e, NFT_EXPR_META_KEY);
	uint32_t value;
	const char *name;
	const void *ifname;
	size_t len;

	e = nft_rule_expr_iter_next(iter);
	if (e == NULL)
		return;

	name = nft_rule_expr_get_str(e, NFT_RULE_EXPR_ATTR_NAME);
	if (strcmp(name, "cmp") != 0) {
		DEBUGP("skipping no cmp after meta\n");
		return;
	}

	switch(key) {
	case NFT_META_IIF:
		value = nft_rule_expr_get_u32(e, NFT_EXPR_CMP_DATA);
		if (nft_rule_expr_get_u8(e, NFT_EXPR_CMP_OP) == NFT_CMP_NEQ)
			cs->fw.ip.invflags |= IPT_INV_VIA_IN;

		if_indextoname(value, cs->fw.ip.iniface);

		memset(cs->fw.ip.iniface_mask, 0xff,
		       strlen(cs->fw.ip.iniface)+1);
		break;
	case NFT_META_OIF:
		value = nft_rule_expr_get_u32(e, NFT_EXPR_CMP_DATA);
		if (nft_rule_expr_get_u8(e, NFT_EXPR_CMP_OP) == NFT_CMP_NEQ)
			cs->fw.ip.invflags |= IPT_INV_VIA_OUT;

		if_indextoname(value, cs->fw.ip.outiface);

		memset(cs->fw.ip.outiface_mask, 0xff,
		       strlen(cs->fw.ip.outiface)+1);
		break;
	case NFT_META_IIFNAME:
		ifname = nft_rule_expr_get(e, NFT_EXPR_CMP_DATA, &len);
		if (nft_rule_expr_get_u8(e, NFT_EXPR_CMP_OP) == NFT_CMP_NEQ)
			cs->fw.ip.invflags |= IPT_INV_VIA_IN;

		memcpy(cs->fw.ip.iniface, ifname, len);
		cs->fw.ip.iniface[len] = '\0';

		/* If zero, then this is an interface mask */
		if (if_nametoindex(cs->fw.ip.iniface) == 0) {
			cs->fw.ip.iniface[len] = '+';
			cs->fw.ip.iniface[len+1] = '\0';
		}

		memset(cs->fw.ip.iniface_mask, 0xff, len);
		break;
	case NFT_META_OIFNAME:
		ifname = nft_rule_expr_get(e, NFT_EXPR_CMP_DATA, &len);
		if (nft_rule_expr_get_u8(e, NFT_EXPR_CMP_OP) == NFT_CMP_NEQ)
			cs->fw.ip.invflags |= IPT_INV_VIA_OUT;

		memcpy(cs->fw.ip.outiface, ifname, len);
		cs->fw.ip.outiface[len] = '\0';

		/* If zero, then this is an interface mask */
		if (if_nametoindex(cs->fw.ip.outiface) == 0) {
			cs->fw.ip.outiface[len] = '+';
			cs->fw.ip.outiface[len+1] = '\0';
		}

		memset(cs->fw.ip.outiface_mask, 0xff, len);
		break;
	default:
		DEBUGP("unknown meta key %d\n", key);
		break;
	}
}

static void
nft_parse_payload(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
		  struct iptables_command_state *cs)
{
	uint32_t offset;
	bool inv;

	offset = nft_rule_expr_get_u32(e, NFT_EXPR_PAYLOAD_OFFSET);

	switch(offset) {
	struct in_addr addr;
	uint8_t proto;

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

static void
nft_parse_counter(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
		  struct xt_counters *counters)
{
	counters->pcnt = nft_rule_expr_get_u64(e, NFT_EXPR_CTR_PACKETS);
	counters->bcnt = nft_rule_expr_get_u64(e, NFT_EXPR_CTR_BYTES);
}

static void
nft_parse_immediate(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
		    struct iptables_command_state *cs)
{
	int verdict = nft_rule_expr_get_u32(e, NFT_EXPR_IMM_VERDICT);
	const char *chain = nft_rule_expr_get_str(e, NFT_EXPR_IMM_CHAIN);

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
		cs->fw.ip.flags |= IPT_F_GOTO;
	case NFT_JUMP:
		cs->jumpto = chain;
		return;
	}
}

static void
nft_rule_to_iptables_command_state(struct nft_rule *r,
				   struct iptables_command_state *cs)
{
	struct nft_rule_expr_iter *iter;
	struct nft_rule_expr *expr;

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
			nft_parse_payload(expr, iter, cs);
		} else if (strcmp(name, "meta") == 0) {
			nft_parse_meta(expr, iter, cs);
		} else if (strcmp(name, "immediate") == 0) {
			nft_parse_immediate(expr, iter, cs);
		}

		expr = nft_rule_expr_iter_next(iter);
	}

	nft_rule_expr_iter_destroy(iter);
}

static int matches_howmany(struct xtables_rule_match *matches)
{
	struct xtables_rule_match *matchp;
	int matches_ctr = 0;

	for (matchp = matches; matchp; matchp = matchp->next)
		matches_ctr++;

	return matches_ctr;
}

static bool
__find_match(struct nft_rule_expr *expr, struct xtables_rule_match *matches)
{
	const char *matchname = nft_rule_expr_get_str(expr, NFT_EXPR_MT_NAME);
	/* Netlink aligns this match info, don't trust this length variable */
	const char *data = nft_rule_expr_get_str(expr, NFT_EXPR_MT_INFO);
	struct xtables_rule_match *matchp;
	bool found = false;

	for (matchp = matches; matchp; matchp = matchp->next) {
		struct xt_entry_match *m = matchp->match->m;

		if (strcmp(m->u.user.name, matchname) != 0) {
			DEBUGP("mismatching match name\n");
			continue;
		}

		if (memcmp(data, m->data, m->u.user.match_size - sizeof(*m)) != 0) {
			DEBUGP("mismatch match data\n");
			continue;
		}
		found = true;
		break;
	}

	return found;
}

static bool find_matches(struct xtables_rule_match *matches, struct nft_rule *r)
{
	struct nft_rule_expr_iter *iter;
	struct nft_rule_expr *expr;
	int kernel_matches = 0;

	iter = nft_rule_expr_iter_create(r);
	if (iter == NULL) {
		DEBUGP("cannot allocate rule list iterator\n");
		return false;
	}

	expr = nft_rule_expr_iter_next(iter);
	while (expr != NULL) {
		const char *name =
			nft_rule_expr_get_str(expr, NFT_RULE_EXPR_ATTR_NAME);

		if (strcmp(name, "match") == 0) {
			if (!__find_match(expr, matches))
				return false;

			kernel_matches++;
		}
		expr = nft_rule_expr_iter_next(iter);
	}
	nft_rule_expr_iter_destroy(iter);

	/* same number of matches? */
	if (matches_howmany(matches) != kernel_matches)
		return false;

	return true;
}

static bool __find_target(struct nft_rule_expr *expr, struct xt_entry_target *t)
{
	size_t len;
	const char *tgname = nft_rule_expr_get_str(expr, NFT_EXPR_TG_NAME);
	/* Netlink aligns this target info, don't trust this length variable */
	const char *data = nft_rule_expr_get(expr, NFT_EXPR_TG_INFO, &len);

	if (strcmp(t->u.user.name, tgname) != 0) {
		DEBUGP("mismatching target name\n");
		return false;
	}

	if (memcmp(data, t->data,  t->u.user.target_size - sizeof(*t)) != 0)
		return false;

	return true;
}

static int targets_howmany(struct xtables_target *target)
{
	return target != NULL ? 1 : 0;
}

static bool
find_target(struct xtables_target *target, struct nft_rule *r)
{
	struct nft_rule_expr_iter *iter;
	struct nft_rule_expr *expr;
	int kernel_targets = 0;

	/* Special case: we use native immediate expressions to emulated
	 * standard targets. Also, we don't want to crash with no targets.
	 */
	if (target == NULL || strcmp(target->name, "standard") == 0)
		return true;

	iter = nft_rule_expr_iter_create(r);
	if (iter == NULL) {
		DEBUGP("cannot allocate rule list iterator\n");
		return false;
	}

	expr = nft_rule_expr_iter_next(iter);
	while (expr != NULL) {
		const char *name =
			nft_rule_expr_get_str(expr, NFT_RULE_EXPR_ATTR_NAME);

		if (strcmp(name, "target") == 0) {
			/* we may support several targets in the future */
			if (!__find_target(expr, target->t))
				return false;

			kernel_targets++;
		}
		expr = nft_rule_expr_iter_next(iter);
	}
	nft_rule_expr_iter_destroy(iter);

	/* same number of targets? */
	if (targets_howmany(target) != kernel_targets) {
		DEBUGP("kernel targets is %d but we passed %d\n",
		kernel_targets, targets_howmany(target));
		return false;
	}

	return true;
}

static bool
find_immediate(struct nft_rule *r, const char *jumpto)
{
	struct nft_rule_expr_iter *iter;
	struct nft_rule_expr *expr;

	iter = nft_rule_expr_iter_create(r);
	if (iter == NULL) {
		DEBUGP("cannot allocate rule list iterator\n");
		return false;
	}

	expr = nft_rule_expr_iter_next(iter);
	while (expr != NULL) {
		const char *name =
			nft_rule_expr_get_str(expr, NFT_RULE_EXPR_ATTR_NAME);

		if (strcmp(name, "immediate") == 0) {
			int verdict = nft_rule_expr_get_u32(expr, NFT_EXPR_IMM_VERDICT);
			const char *verdict_name = NULL;

			/* No target specified but immediate shows up, this
			 * is not the rule we are looking for.
			 */
			if (strlen(jumpto) == 0)
				return false;

			switch(verdict) {
			case NF_ACCEPT:
				verdict_name = "ACCEPT";
				break;
			case NF_DROP:
				verdict_name = "DROP";
				break;
			case NFT_RETURN:
				verdict_name = "RETURN";
				break;
			}

			/* Standard target? */
			if (verdict_name && strcmp(jumpto, verdict_name) != 0)
				return false;
		}
		expr = nft_rule_expr_iter_next(iter);
	}
	nft_rule_expr_iter_destroy(iter);

	return true;
}

static void
__nft_rule_del(struct nft_handle *h, struct nft_rule *r)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	int ret;

	nlh = nft_rule_nlmsg_build_hdr(buf, NFT_MSG_DELRULE, AF_INET,
					NLM_F_ACK, h->seq);
	nft_rule_nlmsg_build_payload(nlh, r);

	nft_rule_print_debug(r, nlh);

	ret = mnl_talk(h, nlh, NULL, NULL);
	if (ret < 0)
		perror("mnl_talk:nft_rule_del");
}

static int
__nft_rule_check(struct nft_handle *h, const char *chain, const char *table,
		 struct iptables_command_state *cs,
		 bool delete, int rulenum, bool verbose)
{
	struct nft_rule_list *list;
	struct nft_rule_list_iter *iter;
	struct nft_rule *r;
	int ret = 0;
	int rule_ctr = 0;
	bool found = false;

	list = nft_rule_list_get(h);
	if (list == NULL) {
		DEBUGP("cannot retrieve rule list from kernel\n");
		return 0;
	}

	iter = nft_rule_list_iter_create(list);
	if (iter == NULL) {
		DEBUGP("cannot allocate rule list iterator\n");
		return 0;
	}

	r = nft_rule_list_iter_next(iter);
	while (r != NULL) {
		const char *rule_table =
			nft_rule_attr_get_str(r, NFT_RULE_ATTR_TABLE);
		const char *rule_chain =
			nft_rule_attr_get_str(r, NFT_RULE_ATTR_CHAIN);
		struct iptables_command_state this = {};

		if (strcmp(table, rule_table) != 0 ||
		    strcmp(chain, rule_chain) != 0) {
			DEBUGP("different chain / table\n");
			goto next;
		}

		if (rulenum >= 0) {
			/* Delete by rule number case */
			if (rule_ctr != rulenum) {
				rule_ctr++;
				goto next;
			}
		} else {
			/* Delete by matching rule case */
			DEBUGP("comparing with... ");
#ifdef DEBUG_DEL
			nft_rule_print_save(r, 0);
#endif

			nft_rule_to_iptables_command_state(r, &this);

			if (!is_same(cs, &this))
				goto next;

			if (!find_matches(cs->matches, r)) {
				DEBUGP("matches not found\n");
				goto next;
			}

			if (!find_target(cs->target, r)) {
				DEBUGP("target not found\n");
				goto next;
			}

			if (!find_immediate(r, cs->jumpto)) {
				DEBUGP("immediate not found\n");
				goto next;
			}

			found = true;
			break;
		}
next:
		r = nft_rule_list_iter_next(iter);
	}

	if (found) {
		ret = 1;

		if (delete) {
			DEBUGP("deleting rule\n");
			__nft_rule_del(h, r);
		}
	}

	nft_rule_list_iter_destroy(iter);
	nft_rule_list_free(list);

	if (ret == 0)
		errno = ENOENT;

	return ret;
}

int nft_rule_check(struct nft_handle *h, const char *chain,
		   const char *table, struct iptables_command_state *e,
		   bool verbose)
{
	nft_fn = nft_rule_check;

	return __nft_rule_check(h, chain, table, e, false, -1, verbose);
}

int nft_rule_delete(struct nft_handle *h, const char *chain,
		    const char *table, struct iptables_command_state *e,
		    bool verbose)
{
	nft_fn = nft_rule_delete;

	return __nft_rule_check(h, chain, table, e, true, -1, verbose);
}

int nft_rule_delete_num(struct nft_handle *h, const char *chain,
			const char *table, int rulenum,
			bool verbose)
{
	nft_fn = nft_rule_delete_num;

	return __nft_rule_check(h, chain, table, NULL, true, rulenum, verbose);
}

int nft_rule_replace(struct nft_handle *h, const char *chain,
		     const char *table, struct iptables_command_state *cs,
		     int rulenum, bool verbose)
{
	int ret;

	nft_fn = nft_rule_replace;

	ret = __nft_rule_check(h, chain, table, NULL, true, rulenum, verbose);
	if (ret < 0)
		return ret;

	/* XXX needs to be inserted in position, this is appending */
	return nft_rule_add(h, chain, table, cs, true, verbose);
}

/*
 * iptables print output emulation
 */

#define FMT_NUMERIC	0x0001
#define FMT_NOCOUNTS	0x0002
#define FMT_KILOMEGAGIGA 0x0004
#define FMT_OPTIONS	0x0008
#define FMT_NOTABLE	0x0010
#define FMT_NOTARGET	0x0020
#define FMT_VIA		0x0040
#define FMT_NONEWLINE	0x0080
#define FMT_LINENUMBERS 0x0100

#define FMT_PRINT_RULE (FMT_NOCOUNTS | FMT_OPTIONS | FMT_VIA \
			| FMT_NUMERIC | FMT_NOTABLE)
#define FMT(tab,notab) ((format) & FMT_NOTABLE ? (notab) : (tab))

static void
print_num(uint64_t number, unsigned int format)
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

static void
print_header(unsigned int format, const char *chain, const char *pol,
	     const struct xt_counters *counters, bool basechain, uint32_t refs)
{
	printf("Chain %s", chain);
	if (basechain) {
		printf(" (policy %s", pol);
		if (!(format & FMT_NOCOUNTS)) {
			fputc(' ', stdout);
			print_num(counters->pcnt, (format|FMT_NOTABLE));
			fputs("packets, ", stdout);
			print_num(counters->bcnt, (format|FMT_NOTABLE));
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

static void
print_firewall(const struct iptables_command_state *cs, struct nft_rule *r,
	       unsigned int num, unsigned int format)
{
	const struct xtables_target *target = NULL;
	const char *targname = NULL;
	const void *targinfo = NULL;
	uint8_t flags;
	char buf[BUFSIZ];
	struct nft_rule_expr_iter *iter;
	struct nft_rule_expr *expr;
	struct xt_entry_target *t;
	size_t target_len = 0;

	iter = nft_rule_expr_iter_create(r);
	if (iter == NULL) {
		DEBUGP("cannot allocate rule list iterator\n");
		return;
	}

	expr = nft_rule_expr_iter_next(iter);
	while (expr != NULL) {
		const char *name =
			nft_rule_expr_get_str(expr, NFT_RULE_EXPR_ATTR_NAME);

		if (strcmp(name, "target") == 0) {
			targname = nft_rule_expr_get_str(expr, NFT_EXPR_TG_NAME);
			targinfo = nft_rule_expr_get(expr, NFT_EXPR_TG_INFO, &target_len);
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
				targname = nft_rule_expr_get_str(expr, NFT_EXPR_IMM_CHAIN);
				break;
			case NFT_JUMP:
				targname = nft_rule_expr_get_str(expr, NFT_EXPR_IMM_CHAIN);
			break;
			}
		}
		expr = nft_rule_expr_iter_next(iter);
	}
	nft_rule_expr_iter_destroy(iter);

	flags = cs->fw.ip.flags;

	if (format & FMT_LINENUMBERS)
		printf(FMT("%-4u ", "%u "), num);

	if (!(format & FMT_NOCOUNTS)) {
		print_num(cs->counters.pcnt, format);
		print_num(cs->counters.bcnt, format);
	}

	if (!(format & FMT_NOTARGET))
		printf(FMT("%-9s ", "%s "), targname ? targname : "");

	fputc(cs->fw.ip.invflags & XT_INV_PROTO ? '!' : ' ', stdout);
	{
		const char *pname =
			proto_to_name(cs->fw.ip.proto, format&FMT_NUMERIC);
		if (pname)
			printf(FMT("%-5s", "%s "), pname);
		else
			printf(FMT("%-5hu", "%hu "), cs->fw.ip.proto);
	}

	if (format & FMT_OPTIONS) {
		if (format & FMT_NOTABLE)
			fputs("opt ", stdout);
		fputc(cs->fw.ip.invflags & IPT_INV_FRAG ? '!' : '-', stdout);
		fputc(flags & IPT_F_FRAG ? 'f' : '-', stdout);
		fputc(' ', stdout);
	}

	if (format & FMT_VIA) {
		char iface[IFNAMSIZ+2];
		if (cs->fw.ip.invflags & IPT_INV_VIA_IN) {
			iface[0] = '!';
			iface[1] = '\0';
		}
		else iface[0] = '\0';

		if (cs->fw.ip.iniface[0] != '\0') {
			strcat(iface, cs->fw.ip.iniface);
		}
		else if (format & FMT_NUMERIC) strcat(iface, "*");
		else strcat(iface, "any");
		printf(FMT(" %-6s ","in %s "), iface);

		if (cs->fw.ip.invflags & IPT_INV_VIA_OUT) {
			iface[0] = '!';
			iface[1] = '\0';
		}
		else iface[0] = '\0';

		if (cs->fw.ip.outiface[0] != '\0') {
			strcat(iface, cs->fw.ip.outiface);
		}
		else if (format & FMT_NUMERIC) strcat(iface, "*");
		else strcat(iface, "any");
		printf(FMT("%-6s ","out %s "), iface);
	}

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

	if (format & FMT_NOTABLE)
		fputs("  ", stdout);

#ifdef IPT_F_GOTO
	if(cs->fw.ip.flags & IPT_F_GOTO)
		printf("[goto] ");
#endif

	iter = nft_rule_expr_iter_create(r);
	if (iter == NULL) {
		DEBUGP("cannot allocate rule list iterator\n");
		return;
	}

	expr = nft_rule_expr_iter_next(iter);
	while (expr != NULL) {
		const char *name =
			nft_rule_expr_get_str(expr, NFT_RULE_EXPR_ATTR_NAME);

		if (strcmp(name, "match") == 0)
			print_match(expr, format & FMT_NUMERIC);

		expr = nft_rule_expr_iter_next(iter);
	}
	nft_rule_expr_iter_destroy(iter);

	t = calloc(1, sizeof(struct xt_entry_target) + target_len);
	if (t == NULL)
		return;

	/* emulate struct xt_entry_match since ->print needs it */
	memcpy((void *)&t->data, targinfo, target_len);

	if (targname) {
		target = xtables_find_target(targname, XTF_TRY_LOAD);
		if (target) {
			if (target->print)
				/* FIXME missing first parameter */
				target->print(NULL, t, format & FMT_NUMERIC);
		} else
			printf("[%ld bytes of unknown target data] ",
				target_len);
	}
	free(t);

	if (!(format & FMT_NONEWLINE))
		fputc('\n', stdout);
}

static int
__nft_rule_list(struct nft_handle *h, struct nft_chain *c, const char *table,
		int rulenum, unsigned int format,
		void (*cb)(const struct iptables_command_state *cs,
			   struct nft_rule *r, unsigned int num,
			   unsigned int format))
{
	struct nft_rule_list *list;
	struct nft_rule_list_iter *iter;
	struct nft_rule *r;
	int rule_ctr = 0, ret = 0;
	const char *chain = nft_chain_attr_get_str(c, NFT_CHAIN_ATTR_NAME);

	list = nft_rule_list_get(h);
	if (list == NULL) {
		DEBUGP("cannot retrieve rule list from kernel\n");
		return 0;
	}

	iter = nft_rule_list_iter_create(list);
	if (iter == NULL) {
		DEBUGP("cannot allocate rule list iterator\n");
		return 0;
	}

	r = nft_rule_list_iter_next(iter);
	while (r != NULL) {
		const char *rule_table =
			nft_rule_attr_get_str(r, NFT_RULE_ATTR_TABLE);
		const char *rule_chain =
			nft_rule_attr_get_str(r, NFT_RULE_ATTR_CHAIN);

		rule_ctr++;

		if (strcmp(table, rule_table) != 0 ||
		    strcmp(chain, rule_chain) != 0)
			goto next;

		if (rulenum > 0) {
			/* List by rule number case */
			if (rule_ctr != rulenum) {
				rule_ctr++;
				goto next;
			}
		} else {
			struct iptables_command_state cs = {};
			/* Show all rules case */
			nft_rule_to_iptables_command_state(r, &cs);

			cb(&cs, r, rule_ctr, format);
		}
next:
		r = nft_rule_list_iter_next(iter);
	}

	nft_rule_list_iter_destroy(iter);
	nft_rule_list_free(list);

	if (ret == 0)
		errno = ENOENT;

	return ret;
}

int nft_rule_list(struct nft_handle *h, const char *chain, const char *table,
		  int rulenum, unsigned int format)
{
	struct nft_chain_list *list;
	struct nft_chain_list_iter *iter;
	struct nft_chain *c;

	list = nft_chain_dump(h);

	iter = nft_chain_list_iter_create(list);
	if (iter == NULL) {
		DEBUGP("cannot allocate rule list iterator\n");
		return 0;
	}

	c = nft_chain_list_iter_next(iter);
	while (c != NULL) {
		const char *chain_table =
			nft_chain_attr_get_str(c, NFT_CHAIN_ATTR_TABLE);
		const char *chain_name =
			nft_chain_attr_get_str(c, NFT_CHAIN_ATTR_NAME);
		uint32_t policy =
			nft_chain_attr_get_u32(c, NFT_CHAIN_ATTR_POLICY);
		uint32_t refs =
			nft_chain_attr_get_u32(c, NFT_CHAIN_ATTR_USE);
		struct xt_counters ctrs = {
			.pcnt = nft_chain_attr_get_u64(c, NFT_CHAIN_ATTR_PACKETS),
			.bcnt = nft_chain_attr_get_u64(c, NFT_CHAIN_ATTR_BYTES),
		};
		bool basechain = false;

		if (nft_chain_attr_get(c, NFT_CHAIN_ATTR_HOOKNUM))
			basechain = true;

		if (strcmp(table, chain_table) != 0)
			goto next;
		if (chain && strcmp(chain, chain_name) != 0)
			goto next;

		print_header(format, chain_name, policy_name[policy], &ctrs,
			     basechain, refs);

		/* this is a base chain */
		if (nft_chain_attr_get(c, NFT_CHAIN_ATTR_HOOKNUM)) {
			__nft_rule_list(h, c, table, rulenum, format,
					print_firewall);
		}
next:
		c = nft_chain_list_iter_next(iter);
	}

	nft_chain_list_free(list);

	return 1;
}

static void
list_save(const struct iptables_command_state *cs, struct nft_rule *r,
	  unsigned int num, unsigned int format)
{
	nft_rule_print_save(r, !(format & FMT_NOCOUNTS));
}

static int
nft_rule_list_chain_save(struct nft_handle *h, const char *table,
			 struct nft_chain_list *list, int counters)
{
	struct nft_chain_list_iter *iter;
	struct nft_chain *c;

	iter = nft_chain_list_iter_create(list);
	if (iter == NULL) {
		DEBUGP("cannot allocate rule list iterator\n");
		return 0;
	}

	c = nft_chain_list_iter_next(iter);
	while (c != NULL) {
		const char *chain_table =
			nft_chain_attr_get_str(c, NFT_CHAIN_ATTR_TABLE);
		const char *chain_name =
			nft_chain_attr_get_str(c, NFT_CHAIN_ATTR_NAME);
		uint32_t policy =
			nft_chain_attr_get_u32(c, NFT_CHAIN_ATTR_POLICY);

		if (strcmp(table, chain_table) != 0)
			goto next;

		/* this is a base chain */
		if (nft_chain_attr_get(c, NFT_CHAIN_ATTR_HOOKNUM)) {
			printf("-P %s %s", chain_name, policy_name[policy]);

			if (counters) {
				printf(" -c %lu %lu\n",
					nft_chain_attr_get_u64(c, NFT_CHAIN_ATTR_PACKETS),
					nft_chain_attr_get_u64(c, NFT_CHAIN_ATTR_BYTES));
			} else
				printf("\n");
		} else {
			printf("-N %s\n", chain_name);
		}
next:
		c = nft_chain_list_iter_next(iter);
	}

	return 1;
}

int nft_rule_list_save(struct nft_handle *h, const char *chain,
		       const char *table, int rulenum, int counters)
{
	struct nft_chain_list *list;
	struct nft_chain_list_iter *iter;
	struct nft_chain *c;

	list = nft_chain_dump(h);

	/* Dump policies and custom chains first */
	nft_rule_list_chain_save(h, table, list, counters);

	/* Now dump out rules in this table */
	iter = nft_chain_list_iter_create(list);
	if (iter == NULL) {
		DEBUGP("cannot allocate rule list iterator\n");
		return 0;
	}

	c = nft_chain_list_iter_next(iter);
	while (c != NULL) {
		const char *chain_table =
			nft_chain_attr_get_str(c, NFT_CHAIN_ATTR_TABLE);
		const char *chain_name =
			nft_chain_attr_get_str(c, NFT_CHAIN_ATTR_NAME);

		if (strcmp(table, chain_table) != 0)
			goto next;
		if (chain && strcmp(chain, chain_name) != 0)
			goto next;

		__nft_rule_list(h, c, table, rulenum,
				counters ? 0 : FMT_NOCOUNTS, list_save);
next:
		c = nft_chain_list_iter_next(iter);
	}

	nft_chain_list_free(list);

	return 1;
}

int nft_compatible_revision(const char *name, uint8_t rev, int opt)
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t portid, seq, type;
	int ret = 0;

	if (opt == IPT_SO_GET_REVISION_MATCH)
		type = 0;
	else
		type = 1;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = (NFNL_SUBSYS_NFT_COMPAT << 8) | NFNL_MSG_COMPAT_GET;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = seq = time(NULL);

	struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_INET;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = 0;

	mnl_attr_put_strz(nlh, NFTA_COMPAT_NAME, name);
	mnl_attr_put_u32(nlh, NFTA_COMPAT_REV, htonl(rev));
	mnl_attr_put_u32(nlh, NFTA_COMPAT_TYPE, htonl(type));

	DEBUGP("requesting `%s' rev=%d type=%d via nft_compat\n",
		name, rev, type);

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		perror("mnl_socket_open");
		return 0;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		goto err;
	}
	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		goto err;
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	if (ret == -1) {
		perror("mnl_socket_recvfrom");
		goto err;
	}

	ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
	if (ret == -1) {
		perror("mnl_cb_run");
		goto err;
	}

err:
	mnl_socket_close(nl);

	return ret < 0 ? 0 : 1;
}

/* Translates errno numbers into more human-readable form than strerror. */
const char *nft_strerror(int err)
{
	unsigned int i;
	static struct table_struct {
		void *fn;
		int err;
		const char *message;
	} table[] =
	  {
	    { nft_chain_user_del, ENOTEMPTY, "Chain is not empty" },
	    { nft_chain_user_del, EINVAL, "Can't delete built-in chain" },
	    { nft_chain_user_del, EMLINK,
	      "Can't delete chain with references left" },
	    { nft_chain_user_add, EEXIST, "Chain already exists" },
	    { nft_rule_add, E2BIG, "Index of insertion too big" },
	    { nft_rule_replace, E2BIG, "Index of replacement too big" },
	    { nft_rule_delete_num, E2BIG, "Index of deletion too big" },
/*	    { TC_READ_COUNTER, E2BIG, "Index of counter too big" },
	    { TC_ZERO_COUNTER, E2BIG, "Index of counter too big" }, */
	    { nft_rule_add, ELOOP, "Loop found in table" },
	    { nft_rule_add, EINVAL, "Target problem" },
	    /* ENOENT for DELETE probably means no matching rule */
	    { nft_rule_delete, ENOENT,
	      "Bad rule (does a matching rule exist in that chain?)" },
	    { nft_chain_set, ENOENT, "Bad built-in chain name" },
	    { nft_chain_set, EINVAL, "Bad policy name" },
	    { NULL, EPERM, "Permission denied (you must be root)" },
	    { NULL, 0, "Incompatible with this kernel" },
	    { NULL, ENOPROTOOPT, "iptables who? (do you need to insmod?)" },
	    { NULL, ENOSYS, "Will be implemented real soon.  I promise ;)" },
	    { NULL, ENOMEM, "Memory allocation problem" },
	    { NULL, ENOENT, "No chain/target/match by that name" },
	  };

	for (i = 0; i < sizeof(table)/sizeof(struct table_struct); i++) {
		if ((!table[i].fn || table[i].fn == nft_fn)
		    && table[i].err == err)
			return table[i].message;
	}

	return strerror(err);
}
