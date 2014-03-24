/*
 * (C) 2012-2013 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This software has been sponsored by Sophos Astaro <http://www.sophos.com>
 */

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>
#include <getopt.h>

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>

#include <include/xtables.h>
#include "iptables.h" /* for xtables_globals */
#include "xtables-multi.h"
#include "nft.h"

static int table_cb(const struct nlmsghdr *nlh, int type)
{
	struct nft_table *t;
	char buf[4096];

	t = nft_table_alloc();
	if (t == NULL) {
		perror("OOM");
		goto err;
	}

	if (nft_table_nlmsg_parse(nlh, t) < 0) {
		perror("nft_table_nlmsg_parse");
		goto err_free;
	}

	nft_table_snprintf(buf, sizeof(buf), t, NFT_OUTPUT_DEFAULT, 0);
	/* FIXME: define syntax to represent table events */
	printf("# [table: %s]\t%s\n", type == NFT_MSG_NEWTABLE ? "NEW" : "DEL", buf);

err_free:
	nft_table_free(t);
err:
	return MNL_CB_OK;
}

static bool counters;

static int rule_cb(const struct nlmsghdr *nlh, int type)
{
	struct iptables_command_state cs = {};
	struct arpt_entry fw_arp = {};
	struct nft_rule *r;
	void *fw = NULL;
	uint8_t family;

	r = nft_rule_alloc();
	if (r == NULL) {
		perror("OOM");
		goto err;
	}

	if (nft_rule_nlmsg_parse(nlh, r) < 0) {
		perror("nft_rule_nlmsg_parse");
		goto err_free;
	}

	family = nft_rule_attr_get_u32(r, NFT_RULE_ATTR_FAMILY);
	switch (family) {
	case AF_INET:
	case AF_INET6:
		printf("-%c ", family == AF_INET ? '4' : '6');
		nft_rule_to_iptables_command_state(r, &cs);
		fw = &cs;
		break;
	case NFPROTO_ARP:
		printf("-0 ");
		nft_rule_to_arpt_entry(r, &fw_arp);
		fw = &fw_arp;
		break;
	default:
		goto err_free;
	}


	nft_rule_print_save(fw, r,
			    type == NFT_MSG_NEWRULE ? NFT_RULE_APPEND :
						      NFT_RULE_DEL,
			    counters ? 0 : FMT_NOCOUNTS);
err_free:
	nft_rule_free(r);
err:
	return MNL_CB_OK;
}

static int chain_cb(const struct nlmsghdr *nlh, int type)
{
	struct nft_chain *t;
	char buf[4096];

	t = nft_chain_alloc();
	if (t == NULL) {
		perror("OOM");
		goto err;
	}

	if (nft_chain_nlmsg_parse(nlh, t) < 0) {
		perror("nft_chain_nlmsg_parse");
		goto err_free;
	}

	nft_chain_snprintf(buf, sizeof(buf), t, NFT_OUTPUT_DEFAULT, 0);
	/* FIXME: define syntax to represent chain events */
	printf("# [chain: %s]\t%s\n", type == NFT_MSG_NEWCHAIN ? "NEW" : "DEL", buf);

err_free:
	nft_chain_free(t);
err:
	return MNL_CB_OK;
}

static int events_cb(const struct nlmsghdr *nlh, void *data)
{
	int ret = MNL_CB_OK;
	int type = nlh->nlmsg_type & 0xFF;

	switch(type) {
	case NFT_MSG_NEWTABLE:
	case NFT_MSG_DELTABLE:
		ret = table_cb(nlh, type);
		break;
	case NFT_MSG_NEWCHAIN:
	case NFT_MSG_DELCHAIN:
		ret = chain_cb(nlh, type);
		break;
	case NFT_MSG_NEWRULE:
	case NFT_MSG_DELRULE:
		ret = rule_cb(nlh, type);
		break;
	}

	return ret;
}

static const struct option options[] = {
	{.name = "counters", .has_arg = false, .val = 'c'},
	{NULL},
};

static void print_usage(const char *name, const char *version)
{
	fprintf(stderr, "Usage: %s [-c]\n"
			"	   [ --counters ]\n", name);
	exit(EXIT_FAILURE);
}

int xtables_events_main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	int ret, c;

	xtables_globals.program_name = "xtables-events";
	/* XXX xtables_init_all does several things we don't want */
	c = xtables_init_all(&xtables_globals, NFPROTO_IPV4);
	if (c < 0) {
		fprintf(stderr, "%s/%s Failed to initialize xtables\n",
				xtables_globals.program_name,
				xtables_globals.program_version);
		exit(1);
	}
#if defined(ALL_INCLUSIVE) || defined(NO_SHARED_LIBS)
	init_extensions();
	init_extensions4();
#endif

	opterr = 0;
	while ((c = getopt_long(argc, argv, "c", options, NULL)) != -1) {
		switch (c) {
	        case 'c':
			counters = true;
			break;
		default:
			print_usage(argv[0], XTABLES_VERSION);
			exit(EXIT_FAILURE);
		}
	}

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(nl, (1 << (NFNLGRP_NFTABLES-1)), MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, 0, events_cb, NULL);
		if (ret <= 0)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}
	if (ret == -1) {
		perror("error");
		exit(EXIT_FAILURE);
	}
	mnl_socket_close(nl);

	return EXIT_SUCCESS;
}
