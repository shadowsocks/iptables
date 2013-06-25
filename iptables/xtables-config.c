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

#include "xtables-multi.h"
#include "nft.h"

int xtables_config_main(int argc, char *argv[])
{
	struct nft_handle h = {
		.family = AF_INET,
	};
	const char *filename = NULL;

	if (argc > 2) {
		fprintf(stderr, "Usage: %s [<config_file>]\n", argv[0]);
		return EXIT_SUCCESS;
	}
	if (argc == 1)
		filename = XTABLES_CONFIG_DEFAULT;
	else
		filename = argv[1];

	if (nft_init(&h) < 0) {
                fprintf(stderr, "Failed to initialize nft: %s\n",
			strerror(errno));
		return EXIT_FAILURE;
	}

	return nft_xtables_config_load(&h, filename, NFT_LOAD_VERBOSE) == 0 ?
						    EXIT_SUCCESS : EXIT_FAILURE;
}
