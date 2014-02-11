/* Code to restore the iptables state, from file by iptables-save.
 * (C) 2000-2002 by Harald Welte <laforge@gnumonks.org>
 * based on previous code from Rusty Russell <rusty@linuxcare.com.au>
 *
 * This code is distributed under the terms of GNU GPL v2
 */

#include <getopt.h>
#include <sys/errno.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "iptables.h"
#include "xtables.h"
#include "libiptc/libiptc.h"
#include "xtables-multi.h"
#include "nft.h"
#include <libnftnl/chain.h>

#ifdef DEBUG
#define DEBUGP(x, args...) fprintf(stderr, x, ## args)
#else
#define DEBUGP(x, args...)
#endif

static int binary = 0, counters = 0, verbose = 0, noflush = 0;

/* Keeping track of external matches and targets.  */
static const struct option options[] = {
	{.name = "binary",   .has_arg = false, .val = 'b'},
	{.name = "counters", .has_arg = false, .val = 'c'},
	{.name = "verbose",  .has_arg = false, .val = 'v'},
	{.name = "test",     .has_arg = false, .val = 't'},
	{.name = "help",     .has_arg = false, .val = 'h'},
	{.name = "noflush",  .has_arg = false, .val = 'n'},
	{.name = "modprobe", .has_arg = true,  .val = 'M'},
	{.name = "table",    .has_arg = true,  .val = 'T'},
	{.name = "ipv4",     .has_arg = false, .val = '4'},
	{.name = "ipv6",     .has_arg = false, .val = '6'},
	{NULL},
};

static void print_usage(const char *name, const char *version) __attribute__((noreturn));

#define prog_name xtables_globals.program_name

static void print_usage(const char *name, const char *version)
{
	fprintf(stderr, "Usage: %s [-b] [-c] [-v] [-t] [-h]\n"
			"	   [ --binary ]\n"
			"	   [ --counters ]\n"
			"	   [ --verbose ]\n"
			"	   [ --test ]\n"
			"	   [ --help ]\n"
			"	   [ --noflush ]\n"
			"	   [ --table=<TABLE> ]\n"
			"          [ --modprobe=<command>]\n", name);

	exit(1);
}

static int parse_counters(char *string, struct xt_counters *ctr)
{
	unsigned long long pcnt, bcnt;
	int ret;

	ret = sscanf(string, "[%llu:%llu]", &pcnt, &bcnt);
	ctr->pcnt = pcnt;
	ctr->bcnt = bcnt;
	return ret == 2;
}

/* global new argv and argc */
static char *newargv[255];
static int newargc;

/* function adding one argument to newargv, updating newargc 
 * returns true if argument added, false otherwise */
static int add_argv(char *what) {
	DEBUGP("add_argv: %s\n", what);
	if (what && newargc + 1 < ARRAY_SIZE(newargv)) {
		newargv[newargc] = strdup(what);
		newargv[++newargc] = NULL;
		return 1;
	} else {
		xtables_error(PARAMETER_PROBLEM,
			"Parser cannot handle more arguments\n");
		return 0;
	}
}

static void free_argv(void) {
	int i;

	for (i = 0; i < newargc; i++)
		free(newargv[i]);
}

static void add_param_to_argv(char *parsestart)
{
	int quote_open = 0, escaped = 0, param_len = 0;
	char param_buffer[1024], *curchar;

	/* After fighting with strtok enough, here's now
	 * a 'real' parser. According to Rusty I'm now no
	 * longer a real hacker, but I can live with that */

	for (curchar = parsestart; *curchar; curchar++) {
		if (quote_open) {
			if (escaped) {
				param_buffer[param_len++] = *curchar;
				escaped = 0;
				continue;
			} else if (*curchar == '\\') {
				escaped = 1;
				continue;
			} else if (*curchar == '"') {
				quote_open = 0;
				*curchar = ' ';
			} else {
				param_buffer[param_len++] = *curchar;
				continue;
			}
		} else {
			if (*curchar == '"') {
				quote_open = 1;
				continue;
			}
		}

		if (*curchar == ' '
		    || *curchar == '\t'
		    || * curchar == '\n') {
			if (!param_len) {
				/* two spaces? */
				continue;
			}

			param_buffer[param_len] = '\0';

			/* check if table name specified */
			if (!strncmp(param_buffer, "-t", 2)
			    || !strncmp(param_buffer, "--table", 8)) {
				xtables_error(PARAMETER_PROBLEM,
				"The -t option (seen in line %u) cannot be "
				"used in xtables-restore.\n", line);
				exit(1);
			}

			add_argv(param_buffer);
			param_len = 0;
		} else {
			/* regular character, copy to buffer */
			param_buffer[param_len++] = *curchar;

			if (param_len >= sizeof(param_buffer))
				xtables_error(PARAMETER_PROBLEM,
				   "Parameter too long!");
		}
	}
}

static const struct xtc_ops xtc_ops = {
	.strerror	= nft_strerror,
};

static int
xtables_restore_main(int family, const char *progname, int argc, char *argv[])
{
	struct nft_handle h = {
		.family = family,
	};
	char buffer[10240];
	int c;
	char curtable[XT_TABLE_MAXNAMELEN + 1];
	FILE *in;
	int in_table = 0, testing = 0;
	const char *tablename = NULL;
	const struct xtc_ops *ops = &xtc_ops;
	struct nft_chain_list *chain_list;
	struct nft_chain *chain_obj;

	line = 0;

	xtables_globals.program_name = progname;
	c = xtables_init_all(&xtables_globals, family);
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

	if (nft_init(&h, xtables_ipv4) < 0) {
		fprintf(stderr, "%s/%s Failed to initialize nft: %s\n",
				xtables_globals.program_name,
				xtables_globals.program_version,
				strerror(errno));
		exit(EXIT_FAILURE);
	}

	while ((c = getopt_long(argc, argv, "bcvthnM:T:46", options, NULL)) != -1) {
		switch (c) {
			case 'b':
				binary = 1;
				break;
			case 'c':
				counters = 1;
				break;
			case 'v':
				verbose = 1;
				break;
			case 't':
				testing = 1;
				break;
			case 'h':
				print_usage("xtables-restore",
					    IPTABLES_VERSION);
				break;
			case 'n':
				noflush = 1;
				break;
			case 'M':
				xtables_modprobe_program = optarg;
				break;
			case 'T':
				tablename = optarg;
				break;
			case '4':
				h.family = AF_INET;
				break;
			case '6':
				h.family = AF_INET6;
				xtables_set_nfproto(AF_INET6);
				break;
		}
	}

	if (optind == argc - 1) {
		in = fopen(argv[optind], "re");
		if (!in) {
			fprintf(stderr, "Can't open %s: %s\n", argv[optind],
				strerror(errno));
			exit(1);
		}
	}
	else if (optind < argc) {
		fprintf(stderr, "Unknown arguments found on commandline\n");
		exit(1);
	}
	else in = stdin;

	chain_list = nft_chain_dump(&h);
	if (chain_list == NULL)
		xtables_error(OTHER_PROBLEM, "cannot retrieve chain list\n");

	/* Grab standard input. */
	while (fgets(buffer, sizeof(buffer), in)) {
		int ret = 0;

		line++;
		if (buffer[0] == '\n')
			continue;
		else if (buffer[0] == '#') {
			if (verbose)
				fputs(buffer, stdout);
			continue;
		} else if ((strcmp(buffer, "COMMIT\n") == 0) && (in_table)) {
			if (!testing) {
				/* Commit per table, although we support
				 * global commit at once, stick by now to
				 * the existing behaviour.
				 */
				DEBUGP("Calling commit\n");
				ret = nft_commit(&h);
			} else {
				DEBUGP("Not calling commit, testing\n");
				ret = nft_abort(&h);
			}
			in_table = 0;

			/* Purge out unused chains in this table */
			if (!testing)
				nft_table_purge_chains(&h, curtable, chain_list);

		} else if ((buffer[0] == '*') && (!in_table)) {
			/* New table */
			char *table;

			table = strtok(buffer+1, " \t\n");
			DEBUGP("line %u, table '%s'\n", line, table);
			if (!table) {
				xtables_error(PARAMETER_PROBLEM,
					"%s: line %u table name invalid\n",
					xt_params->program_name, line);
				exit(1);
			}
			strncpy(curtable, table, XT_TABLE_MAXNAMELEN);
			curtable[XT_TABLE_MAXNAMELEN] = '\0';

			if (tablename && (strcmp(tablename, table) != 0))
				continue;

			if (noflush == 0) {
				DEBUGP("Cleaning all chains of table '%s'\n",
					table);
				nft_rule_flush(&h, NULL, table);
			}

			ret = 1;
			in_table = 1;

		} else if ((buffer[0] == ':') && (in_table)) {
			/* New chain. */
			char *policy, *chain = NULL;
			struct xt_counters count = {};

			chain = strtok(buffer+1, " \t\n");
			DEBUGP("line %u, chain '%s'\n", line, chain);
			if (!chain) {
				xtables_error(PARAMETER_PROBLEM,
					   "%s: line %u chain name invalid\n",
					   xt_params->program_name, line);
				exit(1);
			}

			chain_obj = nft_chain_list_find(chain_list,
							curtable, chain);
			/* This chain has been found, delete from list. Later
			 * on, unvisited chains will be purged out.
			 */
			if (chain_obj != NULL)
				nft_chain_list_del(chain_obj);

			if (strlen(chain) >= XT_EXTENSION_MAXNAMELEN)
				xtables_error(PARAMETER_PROBLEM,
					   "Invalid chain name `%s' "
					   "(%u chars max)",
					   chain, XT_EXTENSION_MAXNAMELEN - 1);

			policy = strtok(NULL, " \t\n");
			DEBUGP("line %u, policy '%s'\n", line, policy);
			if (!policy) {
				xtables_error(PARAMETER_PROBLEM,
					   "%s: line %u policy invalid\n",
					   xt_params->program_name, line);
				exit(1);
			}

			if (strcmp(policy, "-") != 0) {
				if (counters) {
					char *ctrs;
					ctrs = strtok(NULL, " \t\n");

					if (!ctrs || !parse_counters(ctrs, &count))
						xtables_error(PARAMETER_PROBLEM,
							   "invalid policy counters "
							   "for chain '%s'\n", chain);

				}
				if (nft_chain_set(&h, curtable, chain, policy, &count) < 0) {
					xtables_error(OTHER_PROBLEM,
						      "Can't set policy `%s'"
						      " on `%s' line %u: %s\n",
						      policy, chain, line,
						      ops->strerror(errno));
				}
				DEBUGP("Setting policy of chain %s to %s\n",
				       chain, policy);
				ret = 1;

			} else {
				if (nft_chain_user_add(&h, chain, curtable) < 0) {
					if (errno == EEXIST)
						continue;

					xtables_error(PARAMETER_PROBLEM,
						      "cannot create chain "
						      "'%s' (%s)\n", chain,
						      strerror(errno));
				}
				continue;
			}

		} else if (in_table) {
			int a;
			char *ptr = buffer;
			char *pcnt = NULL;
			char *bcnt = NULL;
			char *parsestart;

			/* reset the newargv */
			newargc = 0;

			if (buffer[0] == '[') {
				/* we have counters in our input */
				ptr = strchr(buffer, ']');
				if (!ptr)
					xtables_error(PARAMETER_PROBLEM,
						   "Bad line %u: need ]\n",
						   line);

				pcnt = strtok(buffer+1, ":");
				if (!pcnt)
					xtables_error(PARAMETER_PROBLEM,
						   "Bad line %u: need :\n",
						   line);

				bcnt = strtok(NULL, "]");
				if (!bcnt)
					xtables_error(PARAMETER_PROBLEM,
						   "Bad line %u: need ]\n",
						   line);

				/* start command parsing after counter */
				parsestart = ptr + 1;
			} else {
				/* start command parsing at start of line */
				parsestart = buffer;
			}

			add_argv(argv[0]);
			add_argv("-t");
			add_argv(curtable);

			if (counters && pcnt && bcnt) {
				add_argv("--set-counters");
				add_argv((char *) pcnt);
				add_argv((char *) bcnt);
			}

			add_param_to_argv(parsestart);

			DEBUGP("calling do_command4(%u, argv, &%s, handle):\n",
				newargc, curtable);

			for (a = 0; a < newargc; a++)
				DEBUGP("argv[%u]: %s\n", a, newargv[a]);

			ret = do_commandx(&h, newargc, newargv,
					  &newargv[2], true);
			if (ret < 0) {
				ret = nft_abort(&h);
				if (ret < 0) {
					fprintf(stderr, "failed to abort "
							"commit operation\n");
				}
				exit(1);
			}

			free_argv();
			fflush(stdout);
		}
		if (tablename && (strcmp(tablename, curtable) != 0))
			continue;
		if (!ret) {
			fprintf(stderr, "%s: line %u failed\n",
					xt_params->program_name, line);
			exit(1);
		}
	}
	if (in_table) {
		fprintf(stderr, "%s: COMMIT expected at line %u\n",
				xt_params->program_name, line + 1);
		exit(1);
	}

	fclose(in);
	return 0;
}

int xtables_ip4_restore_main(int argc, char *argv[])
{
	return xtables_restore_main(NFPROTO_IPV4, "iptables-restore",
				    argc, argv);
}

int xtables_ip6_restore_main(int argc, char *argv[])
{
	return xtables_restore_main(NFPROTO_IPV6, "ip6tables-restore",
				    argc, argv);
}
