/* Code to restore the iptables state, from file by iptables-save. 
 * (C) 2000 by Harald Welte <laforge@gnumonks.org>
 * based on previous code from Rusty Russell <rusty@linuxcare.com.au>
 *
 * This coude is distributed under the terms of GNU GPL
 *
 * $Id: iptables-restore.c,v 1.9 2001/02/26 17:31:20 laforge Exp $
 */

#include <getopt.h>
#include <sys/errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "iptables.h"
#include "libiptc/libiptc.h"

#ifdef DEBUG
#define DEBUGP(x, args...) fprintf(stderr, x, ## args)
#else
#define DEBUGP(x, args...) 
#endif

static int binary = 0, counters = 0, verbose = 0, noflush = 0;

/* Keeping track of external matches and targets.  */
static struct option options[] = {
	{ "binary", 0, 0, 'b' },
	{ "counters", 0, 0, 'c' },
/*	{ "verbose", 1, 0, 'v' }, */
	{ "help", 0, 0, 'h' },
	{ "noflush", 0, 0, 'n'},
	{ 0 }
};

static void print_usage(const char *name, const char *version) __attribute__((noreturn));

static void print_usage(const char *name, const char *version)
{
	fprintf(stderr, "Usage: %s [-b] [-c] [-v] [-h]\n"
			"	   [ --binary ]\n"
			"	   [ --counters ]\n"
			"	   [ --verbose ]\n"
			"	   [ --help ]\n"
			"	   [ --noflush ]\n", name);
		
	exit(1);
}

iptc_handle_t create_handle(const char *tablename)
{
	iptc_handle_t handle;

	handle = iptc_init(tablename);
	if (!handle) {
		exit_error(PARAMETER_PROBLEM, "%s: unable to initialize"
			"table '%s'\n", program_name, tablename);
		exit(1);
	}
	return handle;
}

int parse_counters(char *string, struct ipt_counters *ctr)
{
	return (sscanf(string, "[%llu:%llu]", &ctr->pcnt, &ctr->bcnt) == 2);
}

/* global new argv and argc */
static char* newargv[1024];
static int newargc;

/* function adding one argument to newargv, updating newargc 
 * returns true if argument added, false otherwise */
static int add_argv(char *what) {
	if (what && ((newargc + 1) < sizeof(newargv)/sizeof(char *))) {
		newargv[newargc] = what;
		newargc++;
		return 1;
	} else 
		return 0;
}

int main(int argc, char *argv[])
{
	iptc_handle_t handle;
	char buffer[10240];
	unsigned int line = 0;
	int c;
	char curtable[IPT_TABLE_MAXNAMELEN + 1];
	FILE *in;

	program_name = "iptables-restore";
	program_version = NETFILTER_VERSION;

	while ((c = getopt_long(argc, argv, "bcvhn", options, NULL)) != -1) {
		switch (c) {
			case 'b':
				binary = 1;
				break;
			case 'c':
				counters = 1;
				break;
			case 'h':
				print_usage("iptables-restore",
					    NETFILTER_VERSION);
				break;
			case 'n':
				noflush = 1;
				break;
		}
	}
	
	if (optind == argc - 1) {
		in = fopen(argv[optind], "r");
		if (!in) {
			fprintf(stderr, "Can't open %s: %s", argv[optind],
				strerror(errno));
			exit(1);
		}
	}
	else if (optind < argc) {
		fprintf(stderr, "Unknown arguments found on commandline");
		exit(1);
	}
	else in = stdin;
	
	/* Grab standard input. */
	while (fgets(buffer, sizeof(buffer), in)) {
		int ret;

		line++;
		if (buffer[0] == '\n') continue;
		else if (buffer[0] == '#') {
			if (verbose) fputs(buffer, stdout);
			continue;
		} else if (strcmp(buffer, "COMMIT\n") == 0) {
			DEBUGP("Calling commit\n");
			ret = iptc_commit(&handle);
		} else if (buffer[0] == '*') {
			/* New table */
			char *table;

			table = strtok(buffer+1, " \t\n");
			DEBUGP("line %u, table '%s'\n", line, table);
			if (!table) {
				exit_error(PARAMETER_PROBLEM, 
					"%s: line %u table name invalid\n",
					program_name, line);
				exit(1);
			}
			strncpy(curtable, table, IPT_TABLE_MAXNAMELEN);

			handle = create_handle(table);
			if (noflush == 0) {
				DEBUGP("Cleaning all chains of table '%s'\n",
					table);
				for_each_chain(flush_entries, verbose, 1, 
						&handle);
	
				DEBUGP("Deleting all user-defined chains "
				       "of table '%s'\n", table);
				for_each_chain(delete_chain, verbose, 0, 
						&handle) ;
			}

			ret = 1;

		} else if (buffer[0] == ':') {
			/* New chain. */
			char *policy, *chain;

			chain = strtok(buffer+1, " \t\n");
			DEBUGP("line %u, chain '%s'\n", line, chain);
			if (!chain) {
				exit_error(PARAMETER_PROBLEM,
					   "%s: line %u chain name invalid\n",
					   program_name, line);
				exit(1);
			}

			/* FIXME: abort if chain creation fails --RR */
			if (!iptc_builtin(chain, handle)) {
				DEBUGP("Creating new chain '%s'\n", chain);
				if (!iptc_create_chain(chain, &handle))
				DEBUGP("unable to create chain '%s':%s\n", chain,
					strerror(errno));
			}

			policy = strtok(NULL, " \t\n");
			DEBUGP("line %u, policy '%s'\n", line, policy);
			if (!policy) {
				exit_error(PARAMETER_PROBLEM,
					   "%s: line %u policy invalid\n",
					   program_name, line);
				exit(1);
			}

			if (strcmp(policy, "-") != 0) {
				struct ipt_counters count;

				if (counters) {
					char *ctrs;
					ctrs = strtok(NULL, " \t\n");

					parse_counters(ctrs, &count);

				} else {
					memset(&count, 0, 
					       sizeof(struct ipt_counters));
				}

				DEBUGP("Setting policy of chain %s to %s\n",
					chain, policy);

				if (!iptc_set_policy(chain, policy, &count,
						     &handle))
					exit_error(OTHER_PROBLEM,
						"Can't set policy `%s'"
						" on `%s' line %u: %s\n",
						chain, policy, line,
						iptc_strerror(errno));
			}

			ret = 1;

		} else {
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
					exit_error(PARAMETER_PROBLEM,
						   "Bad line %u: need ]\n",
						   line);

				pcnt = strtok(buffer+1, ":");
				if (!pcnt)
					exit_error(PARAMETER_PROBLEM,
						   "Bad line %u: need :\n",
						   line);

				bcnt = strtok(NULL, "]");
				if (!bcnt)
					exit_error(PARAMETER_PROBLEM,
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
			add_argv((char *) &curtable);
			
			if (counters && pcnt && bcnt) {
				add_argv("--set-counters");
				add_argv((char *) pcnt);
				add_argv((char *) bcnt);
			}

			/* parse till end of line */
			if (add_argv(strtok(parsestart, " \t\n"))) {
				while (add_argv(strtok(NULL, " \t\n")));
			}

			DEBUGP("===>calling do_command(%u, argv, &%s, handle):\n",
					newargc, curtable);

			for (a = 0; a <= newargc; a++)
				DEBUGP("argv[%u]: %s\n", a, newargv[a]);

			ret = do_command(newargc, newargv, &newargv[2], &handle);
		}
		if (!ret) {
			fprintf(stderr, "%s: line %u failed\n",
					program_name, line);
			exit(1);
		}
	}

	return 0;
}
