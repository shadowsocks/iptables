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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <libnftables/table.h>
#include <libnftables/chain.h>

#include "xtables-multi.h"
#include "xtables-config-parser.h"

#include "nft.h"

extern int xtables_config_parse(const char *filename,
				struct nft_table_list *table_list,
				struct nft_chain_list *chain_list);

#define XTABLES_CONFIG_DEFAULT	"/etc/xtables.conf"

int xtables_config_main(int argc, char *argv[])
{
	struct nft_table_list *table_list = nft_table_list_alloc();
	struct nft_chain_list *chain_list = nft_chain_list_alloc();
	struct nft_table_list_iter *titer;
	struct nft_chain_list_iter *citer;
	struct nft_table *table;
	struct nft_chain *chain;
	const char *filename = NULL;
	struct nft_handle h = {
		.family = AF_INET,
	};

	if (argc > 2) {
		fprintf(stderr, "Usage: %s [<config_file>]\n", argv[0]);
		return EXIT_SUCCESS;
	}
	if (argc == 1)
		filename = XTABLES_CONFIG_DEFAULT;
	else
		filename = argv[1];

	if (xtables_config_parse(filename, table_list, chain_list) < 0) {
		if (errno == ENOENT) {
			fprintf(stderr, "configuration file `%s' does not "
					"exists\n", filename);
		} else {
			fprintf(stderr, "Fatal error: %s\n", strerror(errno));
		}
		return EXIT_FAILURE;
	}

	nft_init(&h);

	/* Stage 1) create tables */
	titer = nft_table_list_iter_create(table_list);
	while ((table = nft_table_list_iter_next(titer)) != NULL) {
		if (nft_table_add(&h, table) < 0) {
			if (errno == EEXIST) {
				printf("table `%s' already exists, skipping\n",
					(char *)nft_table_attr_get(table, NFT_TABLE_ATTR_NAME));
			} else {
				printf("table `%s' cannot be create, reason `%s'. Exitting\n",
					(char *)nft_table_attr_get(table, NFT_TABLE_ATTR_NAME),
					strerror(errno));
				return EXIT_FAILURE;
			}
			continue;
		}
		printf("table `%s' has been created\n",
			(char *)nft_table_attr_get(table, NFT_TABLE_ATTR_NAME));
	}

	/* Stage 2) create chains */
	citer = nft_chain_list_iter_create(chain_list);
	while ((chain = nft_chain_list_iter_next(citer)) != NULL) {
		if (nft_chain_add(&h, chain) < 0) {
			if (errno == EEXIST) {
				printf("chain `%s' already exists in table `%s', skipping\n",
					(char *)nft_chain_attr_get(chain, NFT_CHAIN_ATTR_NAME),
					(char *)nft_chain_attr_get(chain, NFT_CHAIN_ATTR_TABLE));
			} else {
				printf("chain `%s' cannot be create, reason `%s'. Exitting\n",
					(char *)nft_chain_attr_get(chain, NFT_CHAIN_ATTR_NAME),
					strerror(errno));
				return EXIT_FAILURE;
			}
			continue;
		}

		printf("chain `%s' in table `%s' has been created\n",
			(char *)nft_chain_attr_get(chain, NFT_CHAIN_ATTR_NAME),
			(char *)nft_chain_attr_get(chain, NFT_CHAIN_ATTR_TABLE));
	}

	return EXIT_SUCCESS;
}
