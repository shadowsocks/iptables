/* Code to restore the iptables state, from file by ip6tables-save. 
 * Author:  Andras Kis-Szabo <kisza@sch.bme.hu>
 *
 * based on iptables-restore
 * Authors:
 * 	Harald Welte <laforge@gnumonks.org>
 * 	Rusty Russell <rusty@linuxcare.com.au>
 *
 */

#include <getopt.h>
#include <sys/errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "ip6tables.h"
#include "libiptc/libip6tc.h"

#ifdef DEBUG
#define DEBUGP(x, args...) fprintf(stderr, x, ## args)
#else
#define DEBUGP(x, args...) 
#endif

extern int for_each_chain(int (*fn)(const ip6t_chainlabel, int, ip6tc_handle_t *), int verbose, int builtinstoo, ip6tc_handle_t *handle);
extern int flush_entries(const ip6t_chainlabel chain, int verbose, ip6tc_handle_t *handle);
extern int delete_chain(const ip6t_chainlabel chain, int verbose, ip6tc_handle_t *handle);

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

ip6tc_handle_t create_handle(const char *tablename)
{
	ip6tc_handle_t handle;

	handle = ip6tc_init(tablename);
	if (!handle) {
		exit_error(PARAMETER_PROBLEM, "%s: unable to initialize"
			"table '%s'\n", program_name, tablename);
		exit(1);
	}
	return handle;
}

int parse_counters(char *string, struct ip6t_counters *ctr)
{
	return (sscanf(string, "[%llu:%llu]", &ctr->pcnt, &ctr->bcnt) == 2);
}

int main(int argc, char *argv[])
{
	ip6tc_handle_t handle;
	char buffer[10240];
	unsigned int line = 0;
	int c;
	char curtable[IP6T_TABLE_MAXNAMELEN + 1];
	char curchain[IP6T_FUNCTION_MAXNAMELEN + 1];
	FILE *in;

	program_name = "ip6tables-restore";
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
				print_usage("ip6tables-restore",
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
			ret = ip6tc_commit(&handle);
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
			strncpy(curtable, table, IP6T_TABLE_MAXNAMELEN);

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
			strncpy(curchain, chain, IP6T_FUNCTION_MAXNAMELEN);

			/* why the f... does iptc_builtin not work here ? */
			/* FIXME: abort if chain creation fails --RR */
//			if (!iptc_builtin(curchain, &handle)) {
				DEBUGP("Creating new chain '%s'\n", curchain);
				if (!ip6tc_create_chain(curchain, &handle))
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
				struct ip6t_counters count;

				if (counters) {
					char *ctrs;
					ctrs = strtok(NULL, " \t\n");

					parse_counters(ctrs, &count);

				} else {
					memset(&count, 0, 
					       sizeof(struct ip6t_counters));
				}

				DEBUGP("Setting policy of chain %s to %s\n",
					chain, policy);

				if (!ip6tc_set_policy(chain, policy, &count,
						     &handle))
					exit_error(OTHER_PROBLEM,
						"Can't set policy `%s'"
						" on `%s' line %u: %s\n",
						chain, policy, line,
						ip6tc_strerror(errno));
			}

			ret = 1;

		} else {
			char *newargv[1024];
			int i,a, argvsize;
			char *ptr = buffer;
			char *pcnt = NULL;
			char *bcnt = NULL;

			if (buffer[0] == '[') {
				ptr = strchr(buffer, ']');
				if (!ptr)
					exit_error(PARAMETER_PROBLEM,
						   "Bad line %u: need ]\n",
						   line);
				pcnt = strtok(buffer+1, ":");
				bcnt = strtok(NULL, "]");
			} 

			newargv[0] = argv[0];
			newargv[1] = "-t";
			newargv[2] = (char *) &curtable;
			newargv[3] = "-A";
			newargv[4] = (char *) &curchain;
			argvsize = 5;

			if (counters && pcnt && bcnt) {
				newargv[5] = "--set-counters";
				newargv[6] = (char *) pcnt;
				newargv[7] = (char *) bcnt;
				argvsize = 8;
			}
				
			// strtok initcialize!
			if ( buffer[0]!='[' )
			{
				if (!(newargv[argvsize] = strtok(buffer, " \t\n")))
					goto ImLaMeR;
					//break;
				argvsize++;
			}

			/* strtok: a function only a coder could love */
			for (i = argvsize; i < sizeof(newargv)/sizeof(char *); 
					i++) {
				if (!(newargv[i] = strtok(NULL, " \t\n")))
					break;
				ptr = NULL;
			}
ImLaMeR:		if (i == sizeof(newargv)/sizeof(char *)) {
				fprintf(stderr,
					"%s: line %u too many arguments\n",
					program_name, line);
				exit(1);
			}

			DEBUGP("===>calling do_command6(%u, argv, &%s, handle):\n",
					i, curtable);

			for (a = 0; a <= i; a++)
				DEBUGP("argv[%u]: %s\n", a, newargv[a]);

			ret = do_command6(i, newargv, &newargv[2], &handle);
		}
		if (!ret) {
			fprintf(stderr, "%s: line %u failed\n",
					program_name, line);
			exit(1);
		}
	}

	return 0;
}
