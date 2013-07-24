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

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <errno.h>
#include <netdb.h>	/* getprotobynumber */
#include <time.h>
#include <stdarg.h>
#include <inttypes.h>

#include <xtables.h>
#include <libiptc/libxtc.h>
#include <libiptc/xtcshared.h>

#include <stdlib.h>
#include <string.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <netinet/ip6.h>

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
#include "nft-shared.h"
#include "xtables-config-parser.h"

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

#define FILTER		0
#define MANGLE		1
#define RAW		2
#define SECURITY	3
#define NAT		4
#define TABLES_MAX	5

struct builtin_chain {
	const char *name;
	const char *type;
	uint32_t prio;
	uint32_t hook;
};

static struct builtin_table {
	const char *name;
	struct builtin_chain chains[NF_INET_NUMHOOKS];
} tables[TABLES_MAX] = {
	[RAW] = {
		.name	= "raw",
		.chains = {
			{
				.name	= "PREROUTING",
				.type	= "filter",
				.prio	= -300,	/* NF_IP_PRI_RAW */
				.hook	= NF_INET_PRE_ROUTING,
			},
			{
				.name	= "OUTPUT",
				.type	= "filter",
				.prio	= -300,	/* NF_IP_PRI_RAW */
				.hook	= NF_INET_LOCAL_OUT,
			},
		},
	},
	[MANGLE] = {
		.name	= "mangle",
		.chains = {
			{
				.name	= "PREROUTING",
				.type	= "filter",
				.prio	= -150,	/* NF_IP_PRI_MANGLE */
				.hook	= NF_INET_PRE_ROUTING,
			},
			{
				.name	= "INPUT",
				.type	= "filter",
				.prio	= -150,	/* NF_IP_PRI_MANGLE */
				.hook	= NF_INET_LOCAL_IN,
			},
			{
				.name	= "FORWARD",
				.type	= "filter",
				.prio	= -150,	/* NF_IP_PRI_MANGLE */
				.hook	= NF_INET_FORWARD,
			},
			{
				.name	= "OUTPUT",
				.type	= "route",
				.prio	= -150,	/* NF_IP_PRI_MANGLE */
				.hook	= NF_INET_LOCAL_OUT,
			},
			{
				.name	= "POSTROUTING",
				.type	= "filter",
				.prio	= -150,	/* NF_IP_PRI_MANGLE */
				.hook	= NF_INET_POST_ROUTING,
			},
		},
	},
	[FILTER] = {
		.name	= "filter",
		.chains = {
			{
				.name	= "INPUT",
				.type	= "filter",
				.prio	= 0,	/* NF_IP_PRI_FILTER */
				.hook	= NF_INET_LOCAL_IN,
			},
			{
				.name	= "FORWARD",
				.type	= "filter",
				.prio	= 0,	/* NF_IP_PRI_FILTER */
				.hook	= NF_INET_FORWARD,
			},
			{
				.name	= "OUTPUT",
				.type	= "filter",
				.prio	= 0,	/* NF_IP_PRI_FILTER */
				.hook	= NF_INET_LOCAL_OUT,
			},
		},
	},
	[SECURITY] = {
		.name	= "security",
		.chains = {
			{
				.name	= "INPUT",
				.type	= "filter",
				.prio	= 150,	/* NF_IP_PRI_SECURITY */
				.hook	= NF_INET_LOCAL_IN,
			},
			{
				.name	= "FORWARD",
				.type	= "filter",
				.prio	= 150,	/* NF_IP_PRI_SECURITY */
				.hook	= NF_INET_FORWARD,
			},
			{
				.name	= "OUTPUT",
				.type	= "filter",
				.prio	= 150,	/* NF_IP_PRI_SECURITY */
				.hook	= NF_INET_LOCAL_OUT,
			},
		},
	},
	[NAT] = {
		.name	= "nat",
		.chains = {
			{
				.name	= "PREROUTING",
				.type	= "nat",
				.prio	= -100, /* NF_IP_PRI_NAT_DST */
				.hook	= NF_INET_PRE_ROUTING,
			},
			{
				.name	= "INPUT",
				.type	= "nat",
				.prio	= 100, /* NF_IP_PRI_NAT_SRC */
				.hook	= NF_INET_LOCAL_IN,
			},
			{
				.name	= "POSTROUTING",
				.type	= "nat",
				.prio	= 100, /* NF_IP_PRI_NAT_SRC */
				.hook	= NF_INET_POST_ROUTING,
			},
			{
				.name	= "OUTPUT",
				.type	= "nat",
				.prio	= -100, /* NF_IP_PRI_NAT_DST */
				.hook	= NF_INET_LOCAL_OUT,
			},
		},
	},
};

static int
nft_table_builtin_add(struct nft_handle *h, struct builtin_table *_t,
			bool dormant)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_table *t;
	int ret;

	t = nft_table_alloc();
	if (t == NULL)
		return -1;

	nft_table_attr_set(t, NFT_TABLE_ATTR_NAME, (char *)_t->name);
	if (dormant) {
		nft_table_attr_set_u32(t, NFT_TABLE_ATTR_FLAGS,
					NFT_TABLE_F_DORMANT);
	}

	nlh = nft_table_nlmsg_build_hdr(buf, NFT_MSG_NEWTABLE, h->family,
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
	nft_chain_attr_set_u32(c, NFT_CHAIN_ATTR_PRIO, chain->prio);
	nft_chain_attr_set_u32(c, NFT_CHAIN_ATTR_POLICY, policy);
	nft_chain_attr_set(c, NFT_CHAIN_ATTR_TYPE, (char *)chain->type);

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

	/* NLM_F_CREATE requests module autoloading */
	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_NEWCHAIN, h->family,
					NLM_F_ACK|NLM_F_EXCL|NLM_F_CREATE,
					h->seq);
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
	if (nft_table_builtin_add(h, t, false) < 0) {
		/* Built-in table already initialized, skip. */
		if (errno == EEXIST)
			goto out;
	}
	__nft_chain_builtin_init(h, t, chain, policy);
out:
	return ret;
}

static bool nft_chain_builtin(struct nft_chain *c)
{
	/* Check if this chain has hook number, in that case is built-in.
	 * Should we better export the flags to user-space via nf_tables?
	 */
	return nft_chain_attr_get(c, NFT_CHAIN_ATTR_HOOKNUM) != NULL;
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

	nlh = nft_table_nlmsg_build_hdr(buf, NFT_MSG_NEWTABLE, h->family,
					NLM_F_ACK|NLM_F_EXCL, h->seq);
	nft_table_nlmsg_build_payload(nlh, t);

	return mnl_talk(h, nlh, NULL, NULL);
}

int nft_chain_add(struct nft_handle *h, const struct nft_chain *c)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_NEWCHAIN, h->family,
					NLM_F_ACK|NLM_F_EXCL, h->seq);
	nft_chain_nlmsg_build_payload(nlh, c);

	return mnl_talk(h, nlh, NULL, NULL);
}

int nft_table_set_dormant(struct nft_handle *h, const char *table)
{
	int ret = 0, i;
	struct builtin_table *t;

	t = nft_table_builtin_find(table);
	if (t == NULL) {
		ret = -1;
		goto out;
	}
	/* Add this table as dormant */
	if (nft_table_builtin_add(h, t, true) < 0) {
		/* Built-in table already initialized, skip. */
		if (errno == EEXIST)
			goto out;
	}
	for (i=0; t->chains[i].name != NULL && i<NF_INET_NUMHOOKS; i++)
		__nft_chain_builtin_init(h, t, t->chains[i].name, NF_ACCEPT);
out:
	return ret;
}

int nft_table_wake_dormant(struct nft_handle *h, const char *table)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_table *t;

	t = nft_table_alloc();
	if (t == NULL)
		return -1;

	nft_table_attr_set(t, NFT_TABLE_ATTR_NAME, (char *)table);
	nft_table_attr_set_u32(t, NFT_TABLE_ATTR_FLAGS, 0);

	nlh = nft_table_nlmsg_build_hdr(buf, NFT_MSG_NEWTABLE, h->family,
					NLM_F_ACK, h->seq);
	nft_table_nlmsg_build_payload(nlh, t);
	nft_table_free(t);

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
		nft_table_builtin_add(h, _t, false);

	_c = nft_chain_builtin_find(_t, chain);
	if (_c != NULL) {
		/* This is a built-in chain */
		c = nft_chain_builtin_alloc(_t, _c, policy);
		if (c == NULL)
			return -1;
	} else {
		errno = ENOENT;
		return -1;
	}

	if (counters) {
		nft_chain_attr_set_u64(c, NFT_CHAIN_ATTR_BYTES,
					counters->bcnt);
		nft_chain_attr_set_u64(c, NFT_CHAIN_ATTR_PACKETS,
					counters->pcnt);
	}

	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_NEWCHAIN, h->family,
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

static int __add_match(struct nft_rule_expr *e, struct xt_entry_match *m)
{
	void *info;

	nft_rule_expr_set(e, NFT_EXPR_MT_NAME, m->u.user.name, strlen(m->u.user.name));
	nft_rule_expr_set_u32(e, NFT_EXPR_MT_REV, m->u.user.revision);

	info = calloc(1, m->u.match_size);
	if (info == NULL)
		return -ENOMEM;

	memcpy(info, m->data, m->u.match_size);
	nft_rule_expr_set(e, NFT_EXPR_MT_INFO, info, m->u.match_size - sizeof(*m));

	return 0;
}

static int add_match(struct nft_rule *r, struct xt_entry_match *m)
{
	struct nft_rule_expr *expr;
	int ret;

	expr = nft_rule_expr_alloc("match");
	if (expr == NULL)
		return -ENOMEM;

	ret = __add_match(expr, m);
	nft_rule_add_expr(r, expr);

	return ret;
}

static int __add_target(struct nft_rule_expr *e, struct xt_entry_target *t)
{
	void *info = NULL;

	nft_rule_expr_set(e, NFT_EXPR_TG_NAME, t->u.user.name,
			  strlen(t->u.user.name));
	nft_rule_expr_set_u32(e, NFT_EXPR_TG_REV, t->u.user.revision);

	if (info == NULL) {
		info = calloc(1, t->u.target_size);
		if (info == NULL)
			return -ENOMEM;

		memcpy(info, t->data, t->u.target_size);
	}

	nft_rule_expr_set(e, NFT_EXPR_TG_INFO, info, t->u.target_size - sizeof(*t));

	return 0;
}

static int add_target(struct nft_rule *r, struct xt_entry_target *t)
{
	struct nft_rule_expr *expr;
	int ret;

	expr = nft_rule_expr_alloc("target");
	if (expr == NULL)
		return -ENOMEM;

	ret = __add_target(expr, t);
	nft_rule_add_expr(r, expr);

	return ret;
}

static int add_jumpto(struct nft_rule *r, const char *name, int verdict)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("immediate");
	if (expr == NULL)
		return -ENOMEM;

	nft_rule_expr_set_u32(expr, NFT_EXPR_IMM_DREG, NFT_REG_VERDICT);
	nft_rule_expr_set_u32(expr, NFT_EXPR_IMM_VERDICT, verdict);
	nft_rule_expr_set_str(expr, NFT_EXPR_IMM_CHAIN, (char *)name);
	nft_rule_add_expr(r, expr);

	return 0;
}

static int add_verdict(struct nft_rule *r, int verdict)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("immediate");
	if (expr == NULL)
		return -ENOMEM;

	nft_rule_expr_set_u32(expr, NFT_EXPR_IMM_DREG, NFT_REG_VERDICT);
	nft_rule_expr_set_u32(expr, NFT_EXPR_IMM_VERDICT, verdict);
	nft_rule_add_expr(r, expr);

	return 0;
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

static int add_counters(struct nft_rule *r, uint64_t packets, uint64_t bytes)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("counter");
	if (expr == NULL)
		return -ENOMEM;

	nft_rule_expr_set_u64(expr, NFT_EXPR_CTR_BYTES, packets);
	nft_rule_expr_set_u64(expr, NFT_EXPR_CTR_PACKETS, bytes);

	nft_rule_add_expr(r, expr);

	return 0;
}

void add_compat(struct nft_rule *r, uint32_t proto, bool inv)
{
	nft_rule_attr_set_u32(r, NFT_RULE_ATTR_COMPAT_PROTO, proto);
	nft_rule_attr_set_u32(r, NFT_RULE_ATTR_COMPAT_FLAGS,
			      inv ? NFT_RULE_COMPAT_F_INV : 0);
}

static struct nft_rule *
nft_rule_new(struct nft_handle *h, const char *chain, const char *table,
	     struct iptables_command_state *cs)
{
	struct nft_rule *r;
	int ret = 0, ip_flags = 0;
	struct xtables_rule_match *matchp;

	r = nft_rule_alloc();
	if (r == NULL)
		return NULL;

	nft_rule_attr_set_u32(r, NFT_RULE_ATTR_FAMILY, h->family);
	nft_rule_attr_set(r, NFT_RULE_ATTR_TABLE, (char *)table);
	nft_rule_attr_set(r, NFT_RULE_ATTR_CHAIN, (char *)chain);

	ip_flags = h->ops->add(r, cs);

	for (matchp = cs->matches; matchp; matchp = matchp->next) {
		if (add_match(r, matchp->match->m) < 0)
			goto err;
	}

	/* Counters need to me added before the target, otherwise they are
	 * increased for each rule because of the way nf_tables works.
	 */
	if (add_counters(r, cs->counters.pcnt, cs->counters.bcnt) < 0)
		goto err;

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
		/* Not standard, then it's a go / jump to chain */
		if (ip_flags & IPT_F_GOTO)
			ret = add_jumpto(r, cs->jumpto, NFT_GOTO);
		else
			ret = add_jumpto(r, cs->jumpto, NFT_JUMP);
	}

	if (ret < 0)
		goto err;

	return r;
err:
	nft_rule_free(r);
	return NULL;
}

int
nft_rule_append(struct nft_handle *h, const char *chain, const char *table,
		struct iptables_command_state *cs, uint64_t handle,
		bool verbose)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_rule *r;
	uint16_t flags = NLM_F_ACK|NLM_F_CREATE;
	int ret = 1;

	/* If built-in chains don't exist for this table, create them */
	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0)
		nft_chain_builtin_init(h, table, chain, NF_ACCEPT);

	nft_fn = nft_rule_append;

	r = nft_rule_new(h, chain, table, cs);
	if (r == NULL) {
		ret = 0;
		goto err;
	}

	if (handle > 0) {
		nft_rule_attr_set(r, NFT_RULE_ATTR_HANDLE, &handle);
		flags |= NLM_F_REPLACE;
	} else
		flags |= NLM_F_APPEND;

	if (h->commit) {
		nft_rule_attr_set_u32(r, NFT_RULE_ATTR_FLAGS,
				      NFT_RULE_F_COMMIT);
	}
	nlh = nft_rule_nlmsg_build_hdr(buf, NFT_MSG_NEWRULE, h->family,
				       flags, h->seq);

	nft_rule_nlmsg_build_payload(nlh, r);

	nft_rule_print_debug(r, nlh);

	nft_rule_free(r);

	ret = mnl_talk(h, nlh, NULL, NULL);
	if (ret < 0)
		perror("mnl_talk:nft_rule_append");

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
	if (match->save)
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
	if (target->save)
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
nft_print_counters(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
		   bool counters)
{
	if (counters) {
		printf("-c %"PRIu64" %"PRIu64" ",
			nft_rule_expr_get_u64(e, NFT_EXPR_CTR_PACKETS),
			nft_rule_expr_get_u64(e, NFT_EXPR_CTR_BYTES));
	}
}

void
nft_rule_print_save(struct nft_rule *r, enum nft_rule_print type, bool counters)
{
	struct nft_rule_expr_iter *iter;
	struct nft_rule_expr *expr;
	const char *chain = nft_rule_attr_get_str(r, NFT_RULE_ATTR_CHAIN);

	/* print chain name */
	switch(type) {
	case NFT_RULE_APPEND:
		printf("-A %s ", chain);
		break;
	case NFT_RULE_DEL:
		printf("-D %s ", chain);
		break;
	}

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
			struct nft_family_ops *ops = nft_family_ops_lookup(
				nft_rule_attr_get_u8(r, NFT_RULE_ATTR_FAMILY));
			ops->print_payload(expr, iter);
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

	nft_chain_list_add_tail(c, list);

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
		errno = ENOMEM;
		return NULL;
	}

	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_GETCHAIN, h->family,
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

		printf(":%s %s [%"PRIu64":%"PRIu64"]\n", chain, policy_name[pol],
					     pkts, bytes);
	} else
		printf(":%s - [%"PRIu64":%"PRIu64"]\n", chain, pkts, bytes);
}

int nft_chain_save(struct nft_handle *h, struct nft_chain_list *list,
		   const char *table)
{
	struct nft_chain_list_iter *iter;
	struct nft_chain *c;

	iter = nft_chain_list_iter_create(list);
	if (iter == NULL)
		return 0;

	c = nft_chain_list_iter_next(iter);
	while (c != NULL) {
		const char *chain_table =
			nft_chain_attr_get_str(c, NFT_CHAIN_ATTR_TABLE);
		bool basechain = false;

		if (strcmp(table, chain_table) != 0)
			goto next;

		basechain = nft_chain_builtin(c);
		nft_chain_print_save(c, basechain);
next:
		c = nft_chain_list_iter_next(iter);
	}

	nft_chain_list_iter_destroy(iter);
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

	nft_rule_list_add_tail(r, list);

	return MNL_CB_OK;
out:
	nft_rule_free(r);
	nft_rule_list_free(list);
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
	if (list == NULL)
		return 0;

	nlh = nft_rule_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, h->family,
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
	if (list == NULL)
		return 0;

	iter = nft_rule_list_iter_create(list);
	if (iter == NULL)
		return 0;

	r = nft_rule_list_iter_next(iter);
	while (r != NULL) {
		const char *rule_table =
			nft_rule_attr_get_str(r, NFT_RULE_ATTR_TABLE);

		if (strcmp(table, rule_table) != 0)
			goto next;

		nft_rule_print_save(r, NFT_RULE_APPEND, counters);

next:
		r = nft_rule_list_iter_next(iter);
	}

	nft_rule_list_iter_destroy(iter);
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

	if (h->commit) {
		nft_rule_attr_set_u32(r, NFT_RULE_ATTR_FLAGS,
					 NFT_RULE_F_COMMIT);
	}

	/* Delete all rules in this table + chain */
	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_DELRULE, h->family,
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
	if (iter == NULL)
		goto err;

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

		if (chain != NULL)
			break;
next:
		c = nft_chain_list_iter_next(iter);
	}

	nft_chain_list_iter_destroy(iter);
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
	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0)
		nft_chain_builtin_init(h, table, NULL, NF_ACCEPT);

	c = nft_chain_alloc();
	if (c == NULL)
		return 0;

	nft_chain_attr_set(c, NFT_CHAIN_ATTR_TABLE, (char *)table);
	nft_chain_attr_set(c, NFT_CHAIN_ATTR_NAME, (char *)chain);

	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_NEWCHAIN, h->family,
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

	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_DELCHAIN, h->family,
					NLM_F_ACK, h->seq);
	nft_chain_nlmsg_build_payload(nlh, c);

	ret = mnl_talk(h, nlh, NULL, NULL);
	if (ret < 0) {
		if (errno != EEXIST && errno != ENOENT)
			perror("mnl_talk:__nft_chain_del");
	}

	return ret;
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
	if (iter == NULL)
		goto err;

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

		if (chain != NULL)
			break;
next:
		c = nft_chain_list_iter_next(iter);
	}

	nft_chain_list_iter_destroy(iter);
err:
	nft_chain_list_free(list);

	/* chain not found */
	if (ret < 0 && deleted_ctr == 0)
		errno = ENOENT;

	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

struct nft_chain *
nft_chain_list_find(struct nft_chain_list *list,
		    const char *table, const char *chain)
{
	struct nft_chain_list_iter *iter;
	struct nft_chain *c;

	iter = nft_chain_list_iter_create(list);
	if (iter == NULL)
		return NULL;

	c = nft_chain_list_iter_next(iter);
	while (c != NULL) {
		const char *table_name =
			nft_chain_attr_get_str(c, NFT_CHAIN_ATTR_TABLE);
		const char *chain_name =
			nft_chain_attr_get_str(c, NFT_CHAIN_ATTR_NAME);

		if (strcmp(table, table_name) != 0)
			goto next;

		if (strcmp(chain, chain_name) != 0)
			goto next;

		nft_chain_list_iter_destroy(iter);
		return c;
next:
		c = nft_chain_list_iter_next(iter);
	}
	nft_chain_list_iter_destroy(iter);
	return NULL;
}

static struct nft_chain *
nft_chain_find(struct nft_handle *h, const char *table, const char *chain)
{
	struct nft_chain_list *list;

	list = nft_chain_list_get(h);
	if (list == NULL)
		return NULL;

	return nft_chain_list_find(list, table, chain);
}

int nft_chain_user_rename(struct nft_handle *h,const char *chain,
			  const char *table, const char *newname)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_chain *c;
	uint64_t handle;
	int ret;

	/* If built-in chains don't exist for this table, create them */
	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0)
		nft_chain_builtin_init(h, table, NULL, NF_ACCEPT);

	/* Find the old chain to be renamed */
	c = nft_chain_find(h, table, chain);
	if (c == NULL) {
		errno = ENOENT;
		return -1;
	}
	handle = nft_chain_attr_get_u64(c, NFT_CHAIN_ATTR_HANDLE);

	/* Now prepare the new name for the chain */
	c = nft_chain_alloc();
	if (c == NULL)
		return -1;

	nft_chain_attr_set(c, NFT_CHAIN_ATTR_TABLE, (char *)table);
	nft_chain_attr_set(c, NFT_CHAIN_ATTR_NAME, (char *)newname);
	nft_chain_attr_set_u64(c, NFT_CHAIN_ATTR_HANDLE, handle);

	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_NEWCHAIN, h->family,
					NLM_F_ACK, h->seq);
	nft_chain_nlmsg_build_payload(nlh, c);
	nft_chain_free(c);

	ret = mnl_talk(h, nlh, NULL, NULL);
	if (ret < 0) {
		if (errno != EEXIST)
			perror("mnl_talk:nft_chain_rename");
	}

	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
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

	nft_table_list_add_tail(t, list);

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
	if (list == NULL)
		return 0;

	nlh = nft_rule_nlmsg_build_hdr(buf, NFT_MSG_GETTABLE, h->family,
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
	if (iter == NULL)
		goto err;

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
	if (iter == NULL)
		return 0;

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

int nft_table_purge_chains(struct nft_handle *h, const char *this_table,
			   struct nft_chain_list *chain_list)
{
	struct nft_chain_list_iter *iter;
	struct nft_chain *chain_obj;

	iter = nft_chain_list_iter_create(chain_list);
	if (iter == NULL)
		return 0;

	chain_obj = nft_chain_list_iter_next(iter);
	while (chain_obj != NULL) {
		const char *table =
			nft_chain_attr_get_str(chain_obj, NFT_CHAIN_ATTR_TABLE);

		if (strcmp(this_table, table) != 0)
			goto next;

		if (nft_chain_builtin(chain_obj))
			goto next;

		if ( __nft_chain_del(h, chain_obj) < 0) {
			if (errno != EBUSY)
				return -1;
		}
next:
		chain_obj = nft_chain_list_iter_next(iter);
	}
	nft_chain_list_iter_destroy(iter);

	return 0;
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

static void
nft_rule_to_iptables_command_state(struct nft_rule *r,
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
	if (iter == NULL)
		return false;

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
	if (iter == NULL)
		return false;

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
	if (iter == NULL)
		return false;

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

	nlh = nft_rule_nlmsg_build_hdr(buf, NFT_MSG_DELRULE, h->family,
					NLM_F_ACK, h->seq);
	nft_rule_nlmsg_build_payload(nlh, r);

	nft_rule_print_debug(r, nlh);

	ret = mnl_talk(h, nlh, NULL, NULL);
	if (ret < 0)
		perror("mnl_talk:nft_rule_del");
}

static struct nft_rule_list *nft_rule_list_create(struct nft_handle *h)
{
	return nft_rule_list_get(h);
}

static void nft_rule_list_destroy(struct nft_rule_list *list)
{
	nft_rule_list_free(list);
}

static struct nft_rule *
nft_rule_find(struct nft_rule_list *list, const char *chain, const char *table,
	      struct iptables_command_state *cs, int rulenum)
{
	struct nft_rule *r;
	struct nft_rule_list_iter *iter;
	int rule_ctr = 0;
	bool found = false;

	iter = nft_rule_list_iter_create(list);
	if (iter == NULL)
		return 0;

	r = nft_rule_list_iter_next(iter);
	while (r != NULL) {
		const char *rule_table =
			nft_rule_attr_get_str(r, NFT_RULE_ATTR_TABLE);
		const char *rule_chain =
			nft_rule_attr_get_str(r, NFT_RULE_ATTR_CHAIN);
		const struct nft_family_ops *ops = nft_family_ops_lookup(
				nft_rule_attr_get_u8(r, NFT_RULE_ATTR_FAMILY));
		struct iptables_command_state this = {};

		if (strcmp(table, rule_table) != 0 ||
		    strcmp(chain, rule_chain) != 0) {
			DEBUGP("different chain / table\n");
			goto next;
		}

		if (rulenum >= 0) {
			/* Delete by rule number case */
			if (rule_ctr != rulenum)
				goto next;
			found = true;
			break;
		} else {
			/* Delete by matching rule case */
			DEBUGP("comparing with... ");
#ifdef DEBUG_DEL
			nft_rule_print_save(r, NFT_RULE_APPEND, 0);
#endif

			nft_rule_to_iptables_command_state(r, &this);

			if (!ops->is_same(cs, &this))
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
		rule_ctr++;
		r = nft_rule_list_iter_next(iter);
	}

	nft_rule_list_iter_destroy(iter);

	return found ? r : NULL;
}

int nft_rule_check(struct nft_handle *h, const char *chain,
		   const char *table, struct iptables_command_state *e,
		   bool verbose)
{
	struct nft_rule_list *list;
	int ret;

	nft_fn = nft_rule_check;

	list = nft_rule_list_create(h);
	if (list == NULL)
		return 0;

	ret = nft_rule_find(list, chain, table, e, -1) ? 1 : 0;
	if (ret == 0)
		errno = ENOENT;

	nft_rule_list_destroy(list);

	return ret;
}

int nft_rule_delete(struct nft_handle *h, const char *chain,
		    const char *table, struct iptables_command_state *cs,
		    bool verbose)
{
	int ret = 0;
	struct nft_rule *r;
	struct nft_rule_list *list;

	nft_fn = nft_rule_delete;

	list = nft_rule_list_create(h);
	if (list == NULL)
		return 0;

	r = nft_rule_find(list, chain, table, cs, -1);
	if (r != NULL) {
		ret = 1;

		if (h->commit) {
			nft_rule_attr_set_u32(r, NFT_RULE_ATTR_FLAGS,
						 NFT_RULE_F_COMMIT);
		}
		DEBUGP("deleting rule\n");
		__nft_rule_del(h, r);
	} else
		errno = ENOENT;

	nft_rule_list_destroy(list);

	return ret;
}

static int
nft_rule_add(struct nft_handle *h, const char *chain,
	     const char *table, struct iptables_command_state *cs,
	     uint64_t handle, bool verbose)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_rule *r;
	int ret = 1;

	r = nft_rule_new(h, chain, table, cs);
	if (r == NULL) {
		ret = 0;
		goto err;
	}
	if (handle > 0)
		nft_rule_attr_set_u64(r, NFT_RULE_ATTR_POSITION, handle);

	if (h->commit) {
		nft_rule_attr_set_u32(r, NFT_RULE_ATTR_FLAGS,
				      NFT_RULE_F_COMMIT);
	}
	nlh = nft_rule_nlmsg_build_hdr(buf, NFT_MSG_NEWRULE, h->family,
				       NLM_F_ACK|NLM_F_CREATE, h->seq);
	nft_rule_nlmsg_build_payload(nlh, r);
	nft_rule_print_debug(r, nlh);
	nft_rule_free(r);

	ret = mnl_talk(h, nlh, NULL, NULL);
	if (ret < 0)
		perror("mnl_talk:nft_rule_add_num");

err:
	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

int nft_rule_insert(struct nft_handle *h, const char *chain,
		    const char *table, struct iptables_command_state *cs,
		    int rulenum, bool verbose)
{
	struct nft_rule_list *list;
	struct nft_rule *r;
	uint64_t handle = 0;

	/* If built-in chains don't exist for this table, create them */
	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0)
		nft_chain_builtin_init(h, table, chain, NF_ACCEPT);

	nft_fn = nft_rule_insert;

	if (rulenum > 0) {
		list = nft_rule_list_create(h);
		if (list == NULL)
			goto err;

		r = nft_rule_find(list, chain, table, cs, rulenum);
		if (r == NULL) {
			errno = ENOENT;
			goto err;
		}

		handle = nft_rule_attr_get_u64(r, NFT_RULE_ATTR_HANDLE);
		DEBUGP("adding after rule handle %"PRIu64"\n", handle);

		nft_rule_list_destroy(list);
	}

	return nft_rule_add(h, chain, table, cs, handle, verbose);
err:
	nft_rule_list_destroy(list);
	return 0;
}

int nft_rule_delete_num(struct nft_handle *h, const char *chain,
			const char *table, int rulenum, bool verbose)
{
	int ret = 0;
	struct nft_rule *r;
	struct nft_rule_list *list;

	nft_fn = nft_rule_delete_num;

	list = nft_rule_list_create(h);
	if (list == NULL)
		return 0;

	r = nft_rule_find(list, chain, table, NULL, rulenum);
	if (r != NULL) {
		ret = 1;

		if (h->commit) {
			nft_rule_attr_set_u32(r, NFT_RULE_ATTR_FLAGS,
						 NFT_RULE_F_COMMIT);
		}
		DEBUGP("deleting rule by number %d\n", rulenum);
		__nft_rule_del(h, r);
	} else
		errno = ENOENT;

	nft_rule_list_destroy(list);

	return ret;
}

int nft_rule_replace(struct nft_handle *h, const char *chain,
		     const char *table, struct iptables_command_state *cs,
		     int rulenum, bool verbose)
{
	int ret = 0;
	struct nft_rule *r;
	struct nft_rule_list *list;

	nft_fn = nft_rule_replace;

	list = nft_rule_list_create(h);
	if (list == NULL)
		return 0;

	r = nft_rule_find(list, chain, table, cs, rulenum);
	if (r != NULL) {
		DEBUGP("replacing rule with handle=%llu\n",
			(unsigned long long)
			nft_rule_attr_get_u64(r, NFT_RULE_ATTR_HANDLE));

		if (h->commit) {
			nft_rule_attr_set_u32(r, NFT_RULE_ATTR_FLAGS,
						 NFT_RULE_F_COMMIT);
		}
		ret = nft_rule_append(h, chain, table, cs,
				      nft_rule_attr_get_u64(r, NFT_RULE_ATTR_HANDLE),
				      verbose);
	} else
		errno = ENOENT;

	nft_rule_list_destroy(list);

	return ret;
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
	int family;
	struct nft_family_ops *ops;
	uint8_t flags = 0;
	struct nft_rule_expr_iter *iter;
	struct nft_rule_expr *expr;
	struct xt_entry_target *t;
	size_t target_len = 0;

	iter = nft_rule_expr_iter_create(r);
	if (iter == NULL)
		return;

	expr = nft_rule_expr_iter_next(iter);
	while (expr != NULL) {
		const char *name =
			nft_rule_expr_get_str(expr, NFT_RULE_EXPR_ATTR_NAME);

		if (strcmp(name, "target") == 0) {
			targname = nft_rule_expr_get_str(expr,
							 NFT_EXPR_TG_NAME);
			targinfo = nft_rule_expr_get(expr, NFT_EXPR_TG_INFO,
						     &target_len);
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

	family = nft_rule_attr_get_u8(r, NFT_RULE_ATTR_FAMILY);
	ops = nft_family_ops_lookup(family);

	flags = ops->print_firewall(cs, targname, num, format);

	if (format & FMT_NOTABLE)
		fputs("  ", stdout);

#ifdef IPT_F_GOTO
	if(flags & IPT_F_GOTO)
		printf("[goto] ");
#endif

	iter = nft_rule_expr_iter_create(r);
	if (iter == NULL)
		return;

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
	if (list == NULL)
		return 0;

	iter = nft_rule_list_iter_create(list);
	if (iter == NULL)
		goto err;

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

		if (rulenum > 0 && rule_ctr != rulenum) {
			/* List by rule number case */
			goto next;
		}

		struct iptables_command_state cs = {};
		/* Show all rules case */
		nft_rule_to_iptables_command_state(r, &cs);

		cb(&cs, r, rule_ctr, format);
		if (rulenum > 0 && rule_ctr == rulenum) {
			ret = 1;
			break;
		}

next:
		r = nft_rule_list_iter_next(iter);
	}

	nft_rule_list_iter_destroy(iter);
err:
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
	bool found = false;

	/* If built-in chains don't exist for this table, create them */
	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0)
		nft_chain_builtin_init(h, table, NULL, NF_ACCEPT);

	list = nft_chain_dump(h);

	iter = nft_chain_list_iter_create(list);
	if (iter == NULL)
		goto err;

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

		if (found)
			printf("\n");

		if (!rulenum) {
			print_header(format, chain_name, policy_name[policy],
				     &ctrs, basechain, refs);
		}
		__nft_rule_list(h, c, table, rulenum, format, print_firewall);

		/* we printed the chain we wanted, stop processing. */
		if (chain)
			break;

		found = true;

next:
		c = nft_chain_list_iter_next(iter);
	}

	nft_chain_list_iter_destroy(iter);
err:
	nft_chain_list_free(list);

	return 1;
}

static void
list_save(const struct iptables_command_state *cs, struct nft_rule *r,
	  unsigned int num, unsigned int format)
{
	nft_rule_print_save(r, NFT_RULE_APPEND, !(format & FMT_NOCOUNTS));
}

static int
nft_rule_list_chain_save(struct nft_handle *h, const char *chain,
			 const char *table, struct nft_chain_list *list,
			 int counters)
{
	struct nft_chain_list_iter *iter;
	struct nft_chain *c;

	iter = nft_chain_list_iter_create(list);
	if (iter == NULL)
		return 0;

	c = nft_chain_list_iter_next(iter);
	while (c != NULL) {
		const char *chain_table =
			nft_chain_attr_get_str(c, NFT_CHAIN_ATTR_TABLE);
		const char *chain_name =
			nft_chain_attr_get_str(c, NFT_CHAIN_ATTR_NAME);
		uint32_t policy =
			nft_chain_attr_get_u32(c, NFT_CHAIN_ATTR_POLICY);

		if (strcmp(table, chain_table) != 0 ||
		    (chain && strcmp(chain, chain_name) != 0))
			goto next;

		/* this is a base chain */
		if (nft_chain_builtin(c)) {
			printf("-P %s %s", chain_name, policy_name[policy]);

			if (counters) {
				printf(" -c %"PRIu64" %"PRIu64"\n",
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

	nft_chain_list_iter_destroy(iter);

	return 1;
}

int nft_rule_list_save(struct nft_handle *h, const char *chain,
		       const char *table, int rulenum, int counters)
{
	struct nft_chain_list *list;
	struct nft_chain_list_iter *iter;
	struct nft_chain *c;
	int ret = 1;

	list = nft_chain_dump(h);

	/* Dump policies and custom chains first */
	if (!rulenum)
		nft_rule_list_chain_save(h, chain, table, list, counters);

	/* Now dump out rules in this table */
	iter = nft_chain_list_iter_create(list);
	if (iter == NULL)
		goto err;

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

		ret = __nft_rule_list(h, c, table, rulenum,
				      counters ? 0 : FMT_NOCOUNTS, list_save);

		/* we printed the chain we wanted, stop processing. */
		if (chain)
			break;
next:
		c = nft_chain_list_iter_next(iter);
	}

	nft_chain_list_iter_destroy(iter);
err:
	nft_chain_list_free(list);

	return ret;
}

static int nft_action(struct nft_handle *h, int type)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t seq;
	int ret;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES<< 8) | type;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = seq = time(NULL);

	struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = h->family;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = 0;

	ret = mnl_talk(h, nlh, NULL, NULL);
	if (ret < 0) {
		if (errno != EEXIST)
			perror("mnl-talk:nft_commit");
	}
	return ret == 0 ? 1 : 0;
}

int nft_commit(struct nft_handle *h)
{
	return nft_action(h, NFT_MSG_COMMIT);
}

int nft_abort(struct nft_handle *h)
{
	return nft_action(h, NFT_MSG_ABORT);
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

static void xtables_config_perror(uint32_t flags, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);

	if (flags & NFT_LOAD_VERBOSE)
		vfprintf(stderr, fmt, args);

	va_end(args);
}

int nft_xtables_config_load(struct nft_handle *h, const char *filename,
			    uint32_t flags)
{
	struct nft_table_list *table_list = nft_table_list_alloc();
	struct nft_chain_list *chain_list = nft_chain_list_alloc();
	struct nft_table_list_iter *titer;
	struct nft_chain_list_iter *citer;
	struct nft_table *table;
	struct nft_chain *chain;

	if (xtables_config_parse(filename, table_list, chain_list) < 0) {
		if (errno == ENOENT) {
			xtables_config_perror(flags,
				"configuration file `%s' does not exists\n",
				filename);
		} else {
			xtables_config_perror(flags,
				"Fatal error parsing config file: %s\n",
				 strerror(errno));
		}
		return -1;
	}

	/* Stage 1) create tables */
	titer = nft_table_list_iter_create(table_list);
	while ((table = nft_table_list_iter_next(titer)) != NULL) {
		if (nft_table_add(h, table) < 0) {
			if (errno == EEXIST) {
				xtables_config_perror(flags,
					"table `%s' already exists, skipping\n",
					(char *)nft_table_attr_get(table, NFT_TABLE_ATTR_NAME));
			} else {
				xtables_config_perror(flags,
					"table `%s' cannot be create, reason `%s'. Exitting\n",
					(char *)nft_table_attr_get(table, NFT_TABLE_ATTR_NAME),
					strerror(errno));
				nft_table_list_iter_destroy(titer);
				nft_table_list_free(table_list);
				return -1;
			}
			continue;
		}
		xtables_config_perror(flags, "table `%s' has been created\n",
			(char *)nft_table_attr_get(table, NFT_TABLE_ATTR_NAME));
	}
	nft_table_list_iter_destroy(titer);
	nft_table_list_free(table_list);

	/* Stage 2) create chains */
	citer = nft_chain_list_iter_create(chain_list);
	while ((chain = nft_chain_list_iter_next(citer)) != NULL) {
		if (nft_chain_add(h, chain) < 0) {
			if (errno == EEXIST) {
				xtables_config_perror(flags,
					"chain `%s' already exists in table `%s', skipping\n",
					(char *)nft_chain_attr_get(chain, NFT_CHAIN_ATTR_NAME),
					(char *)nft_chain_attr_get(chain, NFT_CHAIN_ATTR_TABLE));
			} else {
				xtables_config_perror(flags,
					"chain `%s' cannot be create, reason `%s'. Exitting\n",
					(char *)nft_chain_attr_get(chain, NFT_CHAIN_ATTR_NAME),
					strerror(errno));
				nft_chain_list_iter_destroy(citer);
				nft_chain_list_free(chain_list);
				return -1;
			}
			continue;
		}

		xtables_config_perror(flags,
			"chain `%s' in table `%s' has been created\n",
			(char *)nft_chain_attr_get(chain, NFT_CHAIN_ATTR_NAME),
			(char *)nft_chain_attr_get(chain, NFT_CHAIN_ATTR_TABLE));
	}
	nft_chain_list_iter_destroy(citer);
	nft_chain_list_free(chain_list);

	return 0;
}

int nft_chain_zero_counters(struct nft_handle *h, const char *chain, 
			    const char *table)
{
	struct nft_chain_list *list;
	struct nft_chain_list_iter *iter;
	struct nft_chain *c;
	struct nlmsghdr *nlh;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	int ret = 0;

	list = nft_chain_list_get(h);
	if (list == NULL)
		goto err;

	iter = nft_chain_list_iter_create(list);
	if (iter == NULL)
		goto err;

	c = nft_chain_list_iter_next(iter);
	while (c != NULL) {
		const char *chain_name =
			nft_chain_attr_get(c, NFT_CHAIN_ATTR_NAME);
		const char *chain_table =
			nft_chain_attr_get(c, NFT_CHAIN_ATTR_TABLE);

		if (strcmp(table, chain_table) != 0)
			goto next;

		if (chain != NULL && strcmp(chain, chain_name) != 0)
			goto next;

		nft_chain_attr_set_u64(c, NFT_CHAIN_ATTR_PACKETS, 0);
		nft_chain_attr_set_u64(c, NFT_CHAIN_ATTR_BYTES, 0);

		nft_chain_attr_unset(c, NFT_CHAIN_ATTR_HANDLE);

		nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_NEWCHAIN,
						h->family, NLM_F_ACK, h->seq);

		nft_chain_nlmsg_build_payload(nlh, c);

		ret = mnl_talk(h, nlh, NULL, NULL);
		if (ret < 0)
			perror("mnl_talk:nft_chain_zero_counters");

		if (chain != NULL)
			break;
next:
		c = nft_chain_list_iter_next(iter);
	}

	nft_chain_list_iter_destroy(iter);

err:
	nft_chain_list_free(list);

	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

