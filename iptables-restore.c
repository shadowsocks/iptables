/* Code to restore the iptables state, from file by iptables-save. */
#include <getopt.h>
#include <sys/errno.h>
#include <string.h>
#include <stdio.h>
#include "packet-filter/userspace/iptables.h"
#include "packet-filter/userspace/libiptc/libiptc.h"

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

static int clean_slate(iptc_handle_t *handle)
{
	/* Skip over builtins. */
	const char *i, *last = IPTC_LABEL_OUTPUT;

	/* Be careful iterating: it isn't safe during delete. */
	/* Re-iterate after each delete successful */
	while ((i = iptc_next_chain(last, handle)) != NULL) {
		if (!iptc_flush_entries(i, handle)
		    || !iptc_delete_chain(i, handle))
			return 0;
	}
	return 1;
}

int main(int argc, char *argv[])
{
	iptc_handle_t handle;
	char buffer[10240];
	int counters = 0, binary = 0, verbose = 0;
	unsigned int line = 0;
	int c;
	const char *chain;
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

	handle = iptc_init();
	if (!handle)
		exit_error(VERSION_PROBLEM,
			   "can't initialize iptables-restore: %s",
			   iptc_strerror(errno));

	if (!clean_slate(&handle))
		exit_error(OTHER_PROBLEM, "Deleting old chains: %s",
			   iptc_strerror(errno));

	/* Grab standard input. */
	while (fgets(buffer, sizeof(buffer), in)) {
		int ret;

		line++;
		if (buffer[0] == '\n') continue;
		else if (buffer[0] == '#') {
			if (verbose) fputs(buffer, stdout);
			continue;
		} else if (strcmp(buffer, "COMMIT\n") == 0)
			ret = iptc_commit(&handle);
		else if (buffer[0] == ':') {
			/* New chain. */
			char *chain, *policy;

			/* FIXME: Don't ignore counters. */
			chain = strtok(buffer+1, " \t\n");
			if (!chain) {
				exit_error(PARAMETER_PROBLEM,
					   "%s: line %u chain name invalid\n",
					   program_name, line);
				exit(1);
			}
			policy = strtok(NULL, " \t\n");
			if (!policy) {
				exit_error(PARAMETER_PROBLEM,
					   "%s: line %u policy invalid\n",
					   program_name, line);
				exit(1);
			}
			if (strcmp(policy, "-") != 0
			    && !iptc_set_policy(chain, policy, &handle))
				exit_error(OTHER_PROBLEM,
					   "Can't set policy `%s'"
					   " on `%s' line %u: %s\n",
					   chain, policy, line,
					   iptc_strerror(errno));
		} else {
			char *newargv[1024];
			int i;
			char *ptr = buffer;

			/* FIXME: Don't ignore counters. */
			if (buffer[0] == '[') {
				ptr = strchr(buffer, ']');
				if (!ptr)
					exit_error(PARAMETER_PROBLEM,
						   "Bad line %u: need ]\n",
						   line);
			}

			/* strtok: a function only a coder could love */
			newargv[0] = argv[0];
			for (i = 1; i < sizeof(newargv)/sizeof(char *); i++) {
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

			ret = do_command(i, newargv, &handle);
		}
		if (!ret) {
			fprintf(stderr, "%s: line %u failed\n",
					program_name, line);
			exit(1);
		}
	}

	return 0;
}
