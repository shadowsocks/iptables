/*
 * Author: Paul.Russell@rustcorp.com.au and mneuling@radlogic.com.au
 *
 * Based on the ipchains code by Paul Russell and Michael Neuling
 *
 * (C) 2000-2002 by the netfilter coreteam <coreteam@netfilter.org>:
 * 		    Paul 'Rusty' Russell <rusty@rustcorp.com.au>
 * 		    Marc Boucher <marc+nf@mbsi.ca>
 * 		    James Morris <jmorris@intercode.com.au>
 * 		    Harald Welte <laforge@gnumonks.org>
 * 		    Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 *	arptables -- IP firewall administration for kernels with
 *	firewall table (aimed for the 2.3 kernels)
 *
 *	See the accompanying manual page arptables(8) for information
 *	about proper usage of this program.
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <xtables.h>
#include <iptables.h>
#include "nft.h"

#include "xtables-multi.h"

extern struct xtables_globals ebtables_globals;

int xtables_eb_main(int argc, char *argv[])
{
	int ret;
	char *table = "filter";
	struct nft_handle h = {
		.family = NFPROTO_BRIDGE,
	};

	ebtables_globals.program_name = "ebtables";
	ret = xtables_init_all(&ebtables_globals, NFPROTO_BRIDGE);
	if (ret < 0) {
		fprintf(stderr, "%s/%s Failed to initialize ebtables-compat\n",
			ebtables_globals.program_name,
			ebtables_globals.program_version);
		exit(1);
	}

#if defined(ALL_INCLUSIVE) || defined(NO_SHARED_LIBS)
	init_extensionsb();
#endif
	ret = do_commandeb(&h, argc, argv, &table);
	if (ret)
		ret = nft_commit(&h);

	if (!ret)
		fprintf(stderr, "%s\n", nft_strerror(errno));

	exit(!ret);
}
