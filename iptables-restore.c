/* Code to restore the iptables state, from file by iptables-save. 
 * (C) 2000 by Harald Welte <laforge@gnumonks.org>
 * based on previous code from Rusty Russell <rusty@linuxcare.com.au>
 *
 * This coude is distributed under the terms of GNU GPL
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

/* Keeping track of external matches and targets.  */
static struct option options[] = {
	{ "binary", 1, 0, 'b' },
	{ "counters", 1, 0, 'c' },
	{ "verbose", 1, 0, 'v' },
	{ "help", 1, 0, 'h' },
	{ 0 }
};

static void print_usage(const char *name, const char *version) __attribute__((noreturn));

static void print_usage(const char *name, const char *version)
{
	fprintf(stderr, "Usage: %s [-b] [-c] [-v] [-h]\n", name);
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


int main(int argc, char *argv[])
{
	iptc_handle_t handle;
	char buffer[10240];
	int counters = 0, binary = 0, verbose = 0;
	unsigned int line = 0;
	char curtable[IPT_TABLE_MAXNAMELEN + 1];
	char curchain[IPT_FUNCTION_MAXNAMELEN + 1];
	FILE *in;

	program_name = "iptables-restore";
	program_version = NETFILTER_VERSION;

	/* Don't use getopt here; it would interfere 8-(. */
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
/*
	handle = iptc_init("filter");
	if (!handle)
		exit_error(VERSION_PROBLEM,
			   "can't initialize iptables-restore: %s",
			   iptc_strerror(errno));

	if (!clean_slate(&handle))
		exit_error(OTHER_PROBLEM, "Deleting old chains: %s",
			   iptc_strerror(errno));
*/
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

			DEBUGP("Cleaning all chains of table '%s'\n", table);
			for_each_chain(flush_entries, verbose, 1, &handle) ;

			DEBUGP("Deleting all user-defined chains of table '%s'\n", table);
			for_each_chain(delete_chain, verbose, 0, &handle) ;

			ret = 1;

		} else if (buffer[0] == ':') {
			/* New chain. */
			char *policy, *chain;

			/* FIXME: Don't ignore counters. */

			chain = strtok(buffer+1, " \t\n");
			DEBUGP("line %u, chain '%s'\n", line, chain);
			if (!chain) {
				exit_error(PARAMETER_PROBLEM,
					   "%s: line %u chain name invalid\n",
					   program_name, line);
				exit(1);
			}
			strncpy(curchain, chain, IPT_FUNCTION_MAXNAMELEN);

			/* why the f... does iptc_builtin not work here ? */
//			if (!iptc_builtin(curchain, &handle)) {
				DEBUGP("Creating new chain '%s'\n", curchain);
				if (!iptc_create_chain(curchain, &handle))
				DEBUGP("unable to create chain '%s':%s\n", curchain,
					strerror(errno));
//			}

			policy = strtok(NULL, " \t\n");
			DEBUGP("line %u, policy '%s'\n", line, policy);
			if (!policy) {
				exit_error(PARAMETER_PROBLEM,
					   "%s: line %u policy invalid\n",
					   program_name, line);
				exit(1);
			}

			if (strcmp(policy, "-") != 0) {

				DEBUGP("Setting policy of chain %s to %s\n",
					chain, policy);

				if (!iptc_set_policy(chain, policy, &handle))
					exit_error(OTHER_PROBLEM,
						"Can't set policy `%s'"
						" on `%s' line %u: %s\n",
						chain, policy, line,
						iptc_strerror(errno));
			}

			ret = 1;

		} else {
			char *newargv[1024];
			int i,a;
			char *ptr = buffer;

			/* FIXME: Don't ignore counters. */
			if (buffer[0] == '[') {
				ptr = strchr(buffer, ']');
				if (!ptr)
					exit_error(PARAMETER_PROBLEM,
						   "Bad line %u: need ]\n",
						   line);
			}

			newargv[0] = argv[0];
			newargv[1] = "-t";
			newargv[2] = (char *) &curtable;
			newargv[3] = "-A";
			newargv[4] = (char *) &curchain;

			/* strtok: a function only a coder could love */
			for (i = 5; i < sizeof(newargv)/sizeof(char *); i++) {
				if (!(newargv[i] = strtok(ptr, " \t\n")))
					break;
				ptr = NULL;
			}
			if (i == sizeof(newargv)/sizeof(char *)) {
				fprintf(stderr,
					"%s: line %u too many arguments\n",
					program_name, line);
				exit(1);
			}

			DEBUGP("===>calling do_command(%u, argv, &%s, handle):\n",
					i, curtable);

			for (a = 0; a <= i; a++)
				DEBUGP("argv[%u]: %s\n", a, newargv[a]);

			ret = do_command(i, newargv, &newargv[2], &handle);
		}
		if (!ret) {
			fprintf(stderr, "%s: line %u failed\n",
					program_name, line);
			exit(1);
		}
	}

	return 0;
}
