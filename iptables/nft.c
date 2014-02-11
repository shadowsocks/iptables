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
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

#include <netinet/in.h>	/* inet_ntoa */
#include <arpa/inet.h>

#include "nft.h"
#include "xshared.h" /* proto_to_name */
#include "nft-shared.h"
#include "xtables-config-parser.h"

static void *nft_fn;

int mnl_talk(struct nft_handle *h, struct nlmsghdr *nlh,
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

static LIST_HEAD(batch_page_list);
static int batch_num_pages;

struct batch_page {
	struct list_head	head;
	struct mnl_nlmsg_batch	*batch;
};

/* selected batch page is 256 Kbytes long to load ruleset of
 * half a million rules without hitting -EMSGSIZE due to large
 * iovec.
 */
#define BATCH_PAGE_SIZE getpagesize() * 32

static struct mnl_nlmsg_batch *mnl_nft_batch_alloc(void)
{
	static char *buf;

	/* libmnl needs higher buffer to handle batch overflows */
	buf = malloc(BATCH_PAGE_SIZE + getpagesize());
	if (buf == NULL)
		return NULL;

	return mnl_nlmsg_batch_start(buf, BATCH_PAGE_SIZE);
}

static struct mnl_nlmsg_batch *
mnl_nft_batch_page_add(struct mnl_nlmsg_batch *batch)
{
	struct batch_page *batch_page;

	batch_page = malloc(sizeof(struct batch_page));
	if (batch_page == NULL)
		return NULL;

	batch_page->batch = batch;
	list_add_tail(&batch_page->head, &batch_page_list);
	batch_num_pages++;

	return mnl_nft_batch_alloc();
}

static int nlbuffsiz;

static void mnl_nft_set_sndbuffer(const struct mnl_socket *nl)
{
	int newbuffsiz;

	if (batch_num_pages * BATCH_PAGE_SIZE <= nlbuffsiz)
		return;

	newbuffsiz = batch_num_pages * BATCH_PAGE_SIZE;

	/* Rise sender buffer length to avoid hitting -EMSGSIZE */
	if (setsockopt(mnl_socket_get_fd(nl), SOL_SOCKET, SO_SNDBUFFORCE,
		       &newbuffsiz, sizeof(socklen_t)) < 0)
		return;

	nlbuffsiz = newbuffsiz;
}

static ssize_t mnl_nft_socket_sendmsg(const struct mnl_socket *nl)
{
	static const struct sockaddr_nl snl = {
		.nl_family = AF_NETLINK
	};
	struct iovec iov[batch_num_pages];
	struct msghdr msg = {
		.msg_name	= (struct sockaddr *) &snl,
		.msg_namelen	= sizeof(snl),
		.msg_iov	= iov,
		.msg_iovlen	= batch_num_pages,
	};
	struct batch_page *batch_page, *next;
	int i = 0;

	mnl_nft_set_sndbuffer(nl);

	list_for_each_entry_safe(batch_page, next, &batch_page_list, head) {
		iov[i].iov_base = mnl_nlmsg_batch_head(batch_page->batch);
		iov[i].iov_len = mnl_nlmsg_batch_size(batch_page->batch);
		i++;
#ifdef NL_DEBUG
		mnl_nlmsg_fprintf(stdout,
				  mnl_nlmsg_batch_head(batch_page->batch),
				  mnl_nlmsg_batch_size(batch_page->batch),
				  sizeof(struct nfgenmsg));
#endif
		list_del(&batch_page->head);
		free(batch_page->batch);
		free(batch_page);
		batch_num_pages--;
	}

	return sendmsg(mnl_socket_get_fd(nl), &msg, 0);
}

static int cb_err(const struct nlmsghdr *nlh, void *data)
{
	/* We can provide better error reporting than iptables-restore */
	errno = EINVAL;
	return MNL_CB_ERROR;
}

static mnl_cb_t cb_ctl_array[NLMSG_MIN_TYPE] = {
	[NLMSG_ERROR] = cb_err,
};

static int mnl_nft_batch_talk(struct nft_handle *h)
{
	int ret, fd = mnl_socket_get_fd(h->nl);
	char rcv_buf[MNL_SOCKET_BUFFER_SIZE];
	fd_set readfds;
	struct timeval tv = {
		.tv_sec		= 0,
		.tv_usec	= 0
	};
	int err = 0;

	ret = mnl_nft_socket_sendmsg(h->nl);
	if (ret == -1) {
		perror("mnl_socket_sendmsg");
		return -1;
	}

	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);

	/* receive and digest all the acknowledgments from the kernel. */
	ret = select(fd+1, &readfds, NULL, NULL, &tv);
	if (ret == -1) {
		perror("select");
		return -1;
	}
	while (ret > 0 && FD_ISSET(fd, &readfds)) {
		ret = mnl_socket_recvfrom(h->nl, rcv_buf, sizeof(rcv_buf));
		if (ret == -1) {
			perror("mnl_socket_recvfrom");
			return -1;
		}

		ret = mnl_cb_run2(rcv_buf, ret, 0, h->portid,
				  NULL, NULL, cb_ctl_array,
				  MNL_ARRAY_SIZE(cb_ctl_array));
		/* Continue on error, make sure we get all acknoledgments */
		if (ret == -1)
			err = errno;

		ret = select(fd+1, &readfds, NULL, NULL, &tv);
		if (ret == -1) {
			perror("select");
			return -1;
		}
		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);
	}
	return err ? -1 : 0;
}

static void mnl_nft_batch_put(struct mnl_nlmsg_batch *batch, int type,
			      uint32_t seq)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfg;

	nlh = mnl_nlmsg_put_header(mnl_nlmsg_batch_current(batch));
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = seq;

	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_INET;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = NFNL_SUBSYS_NFTABLES;

	if (!mnl_nlmsg_batch_next(batch))
		mnl_nft_batch_page_add(batch);
}

static void mnl_nft_batch_begin(struct mnl_nlmsg_batch *batch, uint32_t seq)
{
	mnl_nft_batch_put(batch, NFNL_MSG_BATCH_BEGIN, seq);
}

static void mnl_nft_batch_end(struct mnl_nlmsg_batch *batch, uint32_t seq)
{
	mnl_nft_batch_put(batch, NFNL_MSG_BATCH_END, seq);
}

struct builtin_table xtables_ipv4[TABLES_MAX] = {
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

#include <linux/netfilter_arp.h>

struct builtin_table xtables_arp[TABLES_MAX] = {
	[FILTER] = {
	.name   = "filter",
	.chains = {
			{
				.name   = "INPUT",
				.type   = "filter",
				.prio   = NF_IP_PRI_FILTER,
				.hook   = NF_ARP_IN,
			},
			{
				.name   = "FORWARD",
				.type   = "filter",
				.prio   = NF_IP_PRI_FILTER,
				.hook   = NF_ARP_FORWARD,
			},
			{
				.name   = "OUTPUT",
				.type   = "filter",
				.prio   = NF_IP_PRI_FILTER,
				.hook   = NF_ARP_OUT,
			},
		},
	},
};

int
nft_table_builtin_add(struct nft_handle *h, struct builtin_table *_t,
			bool dormant)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_table *t;
	int ret;

	if (_t->initialized)
		return 0;

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

#ifdef NLDEBUG
	char tmp[1024];

	nft_table_snprintf(tmp, sizeof(tmp), t, 0, 0);
	printf("DEBUG: table: %s\n", tmp);
	mnl_nlmsg_fprintf(stdout, nlh, nlh->nlmsg_len, sizeof(struct nfgenmsg));
#endif

	ret = mnl_talk(h, nlh, NULL, NULL);
	if (ret == 0 || errno == EEXIST)
		_t->initialized = true;

	return ret;
}

struct nft_chain *
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

void
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

	mnl_talk(h, nlh, NULL, NULL);
}

/* find if built-in table already exists */
struct builtin_table *
nft_table_builtin_find(struct nft_handle *h, const char *table)
{
	int i;
	bool found = false;

	for (i=0; i<TABLES_MAX; i++) {
		if (h->tables[i].name == NULL)
			break;

		if (strcmp(h->tables[i].name, table) != 0)
			continue;

		found = true;
		break;
	}

	return found ? &h->tables[i] : NULL;
}

/* find if built-in chain already exists */
struct builtin_chain *
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

int
nft_chain_builtin_init(struct nft_handle *h, const char *table,
		       const char *chain, int policy)
{
	int ret = 0;
	struct builtin_table *t;

	t = nft_table_builtin_find(h, table);
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

int nft_init(struct nft_handle *h, struct builtin_table *t)
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
	h->tables = t;

	INIT_LIST_HEAD(&h->rule_list);

	h->batch = mnl_nft_batch_alloc();

	return 0;
}

void nft_fini(struct nft_handle *h)
{
	mnl_socket_close(h->nl);
	free(mnl_nlmsg_batch_head(h->batch));
	mnl_nlmsg_batch_stop(h->batch);
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

	t = nft_table_builtin_find(h, table);
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
	printf("DEBUG: chain: %s\n", tmp);
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

	_t = nft_table_builtin_find(h, table);
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
					h->restore ? NLM_F_ACK|NLM_F_CREATE :
					NLM_F_ACK, h->seq);
	nft_chain_nlmsg_build_payload(nlh, c);

	nft_chain_print_debug(c, nlh);

	nft_chain_free(c);

	return mnl_talk(h, nlh, NULL, NULL);
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

	memcpy(info, m->data, m->u.match_size - sizeof(*m));
	nft_rule_expr_set(e, NFT_EXPR_MT_INFO, info, m->u.match_size - sizeof(*m));

	return 0;
}

int add_match(struct nft_rule *r, struct xt_entry_match *m)
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
	void *info;

	nft_rule_expr_set(e, NFT_EXPR_TG_NAME, t->u.user.name,
			  strlen(t->u.user.name));
	nft_rule_expr_set_u32(e, NFT_EXPR_TG_REV, t->u.user.revision);

	info = calloc(1, t->u.target_size);
	if (info == NULL)
		return -ENOMEM;

	memcpy(info, t->data, t->u.target_size - sizeof(*t));
	nft_rule_expr_set(e, NFT_EXPR_TG_INFO, info, t->u.target_size - sizeof(*t));

	return 0;
}

int add_target(struct nft_rule *r, struct xt_entry_target *t)
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

int add_jumpto(struct nft_rule *r, const char *name, int verdict)
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

int add_verdict(struct nft_rule *r, int verdict)
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

int add_action(struct nft_rule *r, struct iptables_command_state *cs,
	       bool goto_set)
{
       int ret = 0;

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
	       if (goto_set)
		       ret = add_jumpto(r, cs->jumpto, NFT_GOTO);
	       else
		       ret = add_jumpto(r, cs->jumpto, NFT_JUMP);
       }
       return ret;
}

static void nft_rule_print_debug(struct nft_rule *r, struct nlmsghdr *nlh)
{
#ifdef NLDEBUG
	char tmp[1024];

	nft_rule_snprintf(tmp, sizeof(tmp), r, 0, 0);
	printf("DEBUG: rule: %s\n", tmp);
	mnl_nlmsg_fprintf(stdout, nlh, nlh->nlmsg_len, sizeof(struct nfgenmsg));
#endif
}

int add_counters(struct nft_rule *r, uint64_t packets, uint64_t bytes)
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
	     void *data)
{
	struct nft_rule *r;

	r = nft_rule_alloc();
	if (r == NULL)
		return NULL;

	nft_rule_attr_set_u32(r, NFT_RULE_ATTR_FAMILY, h->family);
	nft_rule_attr_set(r, NFT_RULE_ATTR_TABLE, (char *)table);
	nft_rule_attr_set(r, NFT_RULE_ATTR_CHAIN, (char *)chain);

	if (h->ops->add(r, data) < 0)
		goto err;

	return r;
err:
	nft_rule_free(r);
	return NULL;
}

enum rule_update_type {
       NFT_DO_APPEND,
       NFT_DO_INSERT,
       NFT_DO_REPLACE,
       NFT_DO_DELETE,
       NFT_DO_FLUSH,
       NFT_DO_COMMIT,
       NFT_DO_ABORT,
};

struct rule_update {
       struct list_head        head;
       enum rule_update_type   type;
       struct nft_rule	       *rule;
};

static int rule_update_add(struct nft_handle *h, enum rule_update_type type,
			  struct nft_rule *r)
{
       struct rule_update *rupd;

       rupd = calloc(1, sizeof(struct rule_update));
       if (rupd == NULL)
	       return -1;

       rupd->rule = r;
       rupd->type = type;
       list_add_tail(&rupd->head, &h->rule_list);
       h->rule_list_num++;

       return 0;
}

int
nft_rule_append(struct nft_handle *h, const char *chain, const char *table,
		void *data, uint64_t handle, bool verbose)
{
	struct nft_rule *r;
	int type;

	/* If built-in chains don't exist for this table, create them */
	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0)
		nft_chain_builtin_init(h, table, chain, NF_ACCEPT);

	nft_fn = nft_rule_append;

	r = nft_rule_new(h, chain, table, data);
	if (r == NULL)
		return 0;

	if (handle > 0) {
		nft_rule_attr_set(r, NFT_RULE_ATTR_HANDLE, &handle);
		type = NFT_DO_REPLACE;
	} else
		type = NFT_DO_APPEND;

	if (rule_update_add(h, type, r) < 0)
		nft_rule_free(r);

	return 1;
}

void
nft_rule_print_save(const void *data,
		    struct nft_rule *r, enum nft_rule_print type,
		    unsigned int format)
{
	const char *chain = nft_rule_attr_get_str(r, NFT_RULE_ATTR_CHAIN);
	int family = nft_rule_attr_get_u8(r, NFT_RULE_ATTR_FAMILY);
	struct nft_family_ops *ops;

	/* print chain name */
	switch(type) {
	case NFT_RULE_APPEND:
		printf("-A %s ", chain);
		break;
	case NFT_RULE_DEL:
		printf("-D %s ", chain);
		break;
	}

	ops = nft_family_ops_lookup(family);

	if (ops->save_firewall)
		ops->save_firewall(data, format);

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
	struct nft_chain_list *list;

	list = nft_chain_list_alloc();
	if (list == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_GETCHAIN, h->family,
					NLM_F_DUMP, h->seq);

	mnl_talk(h, nlh, nft_chain_list_cb, list);

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
		struct iptables_command_state cs = {};

		if (strcmp(table, rule_table) != 0)
			goto next;

		nft_rule_to_iptables_command_state(r, &cs);

		nft_rule_print_save(&cs, r, NFT_RULE_APPEND,
				    counters ? 0 : FMT_NOCOUNTS);

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
	struct nft_rule *r;

	r = nft_rule_alloc();
	if (r == NULL)
		return;

	nft_rule_attr_set(r, NFT_RULE_ATTR_TABLE, (char *)table);
	nft_rule_attr_set(r, NFT_RULE_ATTR_CHAIN, (char *)chain);

	if (rule_update_add(h, NFT_DO_FLUSH, r) < 0)
		nft_rule_free(r);
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

	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

static int __nft_chain_del(struct nft_handle *h, struct nft_chain *c)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_DELCHAIN, h->family,
					NLM_F_ACK, h->seq);
	nft_chain_nlmsg_build_payload(nlh, c);

	return mnl_talk(h, nlh, NULL, NULL);
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
	struct nft_table_list *list;

	list = nft_table_list_alloc();
	if (list == NULL)
		return 0;

	nlh = nft_rule_nlmsg_build_hdr(buf, NFT_MSG_GETTABLE, h->family,
					NLM_F_DUMP, h->seq);

	mnl_talk(h, nlh, nft_table_list_cb, list);

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

static int __nft_rule_del(struct nft_handle *h, struct nft_rule_list *list,
			  struct nft_rule *r)
{
	int ret;

	nft_rule_list_del(r);

	ret = rule_update_add(h, NFT_DO_DELETE, r);
	if (ret < 0) {
		nft_rule_free(r);
		return -1;
	}
	return 1;
}

struct nft_rule_list *nft_rule_list_create(struct nft_handle *h)
{
	return nft_rule_list_get(h);
}

void nft_rule_list_destroy(struct nft_rule_list *list)
{
	nft_rule_list_free(list);
}

static struct nft_rule *
nft_rule_find(struct nft_handle *h, struct nft_rule_list *list,
	      const char *chain, const char *table, void *data, int rulenum)
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
			found = h->ops->rule_find(h->ops, r, data);
			if (found)
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
		   const char *table, void *data, bool verbose)
{
	struct nft_rule_list *list;
	int ret;

	nft_fn = nft_rule_check;

	list = nft_rule_list_create(h);
	if (list == NULL)
		return 0;

	ret = nft_rule_find(h, list, chain, table, data, -1) ? 1 : 0;
	if (ret == 0)
		errno = ENOENT;

	nft_rule_list_destroy(list);

	return ret;
}

int nft_rule_delete(struct nft_handle *h, const char *chain,
		    const char *table, void *data, bool verbose)
{
	int ret = 0;
	struct nft_rule *r;
	struct nft_rule_list *list;

	nft_fn = nft_rule_delete;

	list = nft_rule_list_create(h);
	if (list == NULL)
		return 0;

	r = nft_rule_find(h, list, chain, table, data, -1);
	if (r != NULL) {
		ret =__nft_rule_del(h, list, r);
		if (ret < 0)
			errno = ENOMEM;
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
	struct nft_rule *r;

	r = nft_rule_new(h, chain, table, cs);
	if (r == NULL)
		return 0;

	if (handle > 0)
		nft_rule_attr_set_u64(r, NFT_RULE_ATTR_POSITION, handle);

	if (rule_update_add(h, NFT_DO_INSERT, r) < 0) {
		nft_rule_free(r);
		return 0;
	}

	return 1;
}

int nft_rule_insert(struct nft_handle *h, const char *chain,
		    const char *table, void *data, int rulenum, bool verbose)
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

		r = nft_rule_find(h, list, chain, table, data, rulenum);
		if (r == NULL) {
			errno = ENOENT;
			goto err;
		}

		handle = nft_rule_attr_get_u64(r, NFT_RULE_ATTR_HANDLE);
		DEBUGP("adding after rule handle %"PRIu64"\n", handle);

		nft_rule_list_destroy(list);
	}

	return nft_rule_add(h, chain, table, data, handle, verbose);
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

	r = nft_rule_find(h, list, chain, table, NULL, rulenum);
	if (r != NULL) {
		ret = 1;

		DEBUGP("deleting rule by number %d\n", rulenum);
		ret = __nft_rule_del(h, list, r);
		if (ret < 0)
			errno = ENOMEM;
	} else
		errno = ENOENT;

	nft_rule_list_destroy(list);

	return ret;
}

int nft_rule_replace(struct nft_handle *h, const char *chain,
		     const char *table, void *data, int rulenum, bool verbose)
{
	int ret = 0;
	struct nft_rule *r;
	struct nft_rule_list *list;

	nft_fn = nft_rule_replace;

	list = nft_rule_list_create(h);
	if (list == NULL)
		return 0;

	r = nft_rule_find(h, list, chain, table, data, rulenum);
	if (r != NULL) {
		DEBUGP("replacing rule with handle=%llu\n",
			(unsigned long long)
			nft_rule_attr_get_u64(r, NFT_RULE_ATTR_HANDLE));

		ret = nft_rule_append(h, chain, table, data,
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

static int
__nft_rule_list(struct nft_handle *h, const char *chain, const char *table,
		int rulenum, unsigned int format,
		void (*cb)(struct nft_rule *r, unsigned int num,
			   unsigned int format))
{
	struct nft_rule_list *list;
	struct nft_rule_list_iter *iter;
	struct nft_rule *r;
	int rule_ctr = 0, ret = 0;

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

		cb(r, rule_ctr, format);
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
	const struct nft_family_ops *ops;
	struct nft_chain_list *list;
	struct nft_chain_list_iter *iter;
	struct nft_chain *c;
	bool found = false;

	/* If built-in chains don't exist for this table, create them */
	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0)
		nft_chain_builtin_init(h, table, NULL, NF_ACCEPT);

	ops = nft_family_ops_lookup(h->family);

	if (chain && rulenum) {
		__nft_rule_list(h, chain, table,
				rulenum, format, ops->print_firewall);
		return 1;
	}

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

		print_header(format, chain_name, policy_name[policy],
				     &ctrs, basechain, refs);

		__nft_rule_list(h, chain_name, table,
				rulenum, format, ops->print_firewall);

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
list_save(struct nft_rule *r, unsigned int num, unsigned int format)
{
	struct iptables_command_state cs = {};

	nft_rule_to_iptables_command_state(r, &cs);

	nft_rule_print_save(&cs, r, NFT_RULE_APPEND, !(format & FMT_NOCOUNTS));
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

		ret = __nft_rule_list(h, chain_name, table, rulenum,
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

int nft_rule_zero_counters(struct nft_handle *h, const char *chain,
			   const char *table, int rulenum)
{
	struct iptables_command_state cs = {};
	struct nft_rule_list *list;
	struct nft_rule *r;
	int ret = 0;

	nft_fn = nft_rule_delete;

	list = nft_rule_list_create(h);
	if (list == NULL)
		return 0;

	r = nft_rule_find(h, list, chain, table, NULL, rulenum);
	if (r == NULL) {
		errno = ENOENT;
		ret = 1;
		goto error;
	}

	nft_rule_to_iptables_command_state(r, &cs);

	cs.counters.pcnt = cs.counters.bcnt = 0;

	ret =  nft_rule_append(h, chain, table, &cs,
			       nft_rule_attr_get_u64(r, NFT_RULE_ATTR_HANDLE),
			       false);

error:
	nft_rule_list_destroy(list);

	return ret;
}

static int nft_action(struct nft_handle *h, int action)
{
	int flags = NLM_F_CREATE, type;
	struct rule_update *n, *tmp;
	struct nlmsghdr *nlh;
	uint32_t seq = 1;
	int ret;

	mnl_nft_batch_begin(h->batch, seq++);

	list_for_each_entry_safe(n, tmp, &h->rule_list, head) {
		switch (n->type) {
		case NFT_DO_APPEND:
			type = NFT_MSG_NEWRULE;
			flags |= NLM_F_APPEND;
			break;
		case NFT_DO_INSERT:
			type = NFT_MSG_NEWRULE;
			break;
		case NFT_DO_REPLACE:
			type = NFT_MSG_NEWRULE;
			flags |= NLM_F_REPLACE;
			break;
		case NFT_DO_DELETE:
		case NFT_DO_FLUSH:
			type = NFT_MSG_DELRULE;
			break;
		default:
			return 0;
		}

		nlh = nft_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(h->batch),
					       type, h->family, flags, seq++);
		nft_rule_nlmsg_build_payload(nlh, n->rule);
		nft_rule_print_debug(n->rule, nlh);

		h->rule_list_num--;
		list_del(&n->head);
		nft_rule_free(n->rule);
		free(n);

		if (!mnl_nlmsg_batch_next(h->batch))
			h->batch = mnl_nft_batch_page_add(h->batch);
	}

	switch (action) {
	case NFT_DO_COMMIT:
		mnl_nft_batch_end(h->batch, seq++);
		break;
	case NFT_DO_ABORT:
		break;
	}

	if (!mnl_nlmsg_batch_is_empty(h->batch))
		h->batch = mnl_nft_batch_page_add(h->batch);

	ret = mnl_nft_batch_talk(h);
	if (ret < 0)
		perror("mnl_nft_batch_talk:");

	mnl_nlmsg_batch_reset(h->batch);

	return ret == 0 ? 1 : 0;
}

int nft_commit(struct nft_handle *h)
{
	return nft_action(h, NFT_DO_COMMIT);
}

int nft_abort(struct nft_handle *h)
{
	return nft_action(h, NFT_DO_ABORT);
}

int nft_compatible_revision(const char *name, uint8_t rev, int opt)
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t portid, seq, type;
	int ret = 0;

	if (opt == IPT_SO_GET_REVISION_MATCH ||
	    opt == IP6T_SO_GET_REVISION_MATCH)
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
	struct nft_table_list_iter *titer = NULL;
	struct nft_chain_list_iter *citer = NULL;
	struct nft_table *table;
	struct nft_chain *chain;
	uint32_t table_family, chain_family;
	bool found = false;

	if (h->restore)
		return 0;

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
		goto err;
	}

	/* Stage 1) create tables */
	titer = nft_table_list_iter_create(table_list);
	while ((table = nft_table_list_iter_next(titer)) != NULL) {
		table_family = nft_table_attr_get_u32(table,
						      NFT_TABLE_ATTR_FAMILY);
		if (h->family != table_family)
			continue;

		found = true;

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
				goto err;
			}
			continue;
		}
		xtables_config_perror(flags, "table `%s' has been created\n",
			(char *)nft_table_attr_get(table, NFT_TABLE_ATTR_NAME));
	}
	nft_table_list_iter_destroy(titer);
	nft_table_list_free(table_list);

	if (!found)
		goto err;

	/* Stage 2) create chains */
	citer = nft_chain_list_iter_create(chain_list);
	while ((chain = nft_chain_list_iter_next(citer)) != NULL) {
		chain_family = nft_chain_attr_get_u32(chain,
						      NFT_CHAIN_ATTR_TABLE);
		if (h->family != chain_family)
			continue;

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
				goto err;
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

err:
	nft_table_list_free(table_list);
	nft_chain_list_free(chain_list);

	if (titer != NULL)
		nft_table_list_iter_destroy(titer);
	if (citer != NULL)
		nft_chain_list_iter_destroy(citer);

	return -1;
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
