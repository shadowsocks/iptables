/* Code to save the iptables state, in human readable-form. */
#include <getopt.h>
#include <sys/errno.h>
#include <stdio.h>
#include <dlfcn.h>
#include <time.h>
#include "packet-match/userspace/libiptc/libiptc.h"
#include "packet-match/userspace/iptables.h"

static int binary = 0, counters = 0;

static struct option options[] = {
	{ "binary", 0, 0, 'b' },
	{ "counters", 0, 0, 'c' },
	{ "dump", 0, 0, 'd' },
	{ "table", 1, 0, 't' },
	{ 0 }
};

#define IP_PARTS_NATIVE(n)			\
(unsigned int)((n)>>24)&0xFF,			\
(unsigned int)((n)>>16)&0xFF,			\
(unsigned int)((n)>>8)&0xFF,			\
(unsigned int)((n)&0xFF)

#define IP_PARTS(n) IP_PARTS_NATIVE(ntohl(n))

/* This assumes that mask is contiguous, and byte-bounded. */
static void
print_iface(char letter, const char *iface, const unsigned char *mask,
	    int invert)
{
	unsigned int i;

	if (mask[0] == 0)
		return;

	printf("-%c %s", letter, invert ? "! " : "");

	for (i = 0; i < IFNAMSIZ; i++) {
		if (mask[i] != 0) {
			if (iface[i] != '\0')
				printf("%c", iface[i]);
		} else {
			if (iface[i] != '\0')
				printf("+");
			break;
		}
	}
}

/* These are hardcoded backups in iptables.c, so they are safe */
struct pprot {
	char *name;
	u_int8_t num;
};

static const struct pprot chain_protos[] = {
	{ "tcp", IPPROTO_TCP },
	{ "udp", IPPROTO_UDP },
	{ "icmp", IPPROTO_ICMP },
};

static void print_proto(u_int16_t proto, int invert)
{
	if (proto) {
		unsigned int i;
		const char *invertstr = invert ? "! " : "";

		for (i = 0; i < sizeof(chain_protos)/sizeof(struct pprot); i++)
			if (chain_protos[i].num == proto) {
				printf("-p %s%s ",
				       invertstr, chain_protos[i].name);
				return;
			}

		printf("-p %s%u ", invertstr, proto);
	}
}

static int non_zero(const void *ptr, size_t size)
{
	unsigned int i;

	for (i = 0; i < size; i++)
		if (((char *)ptr)[i])
			return 0;

	return 1;
}

/* We want this to be readable, so only print out neccessary fields.
 * Because that's the kind of world I want to live in.  */
static void print_rule(const struct ipt_entry *e, int counters)
{
	if (counters)
		printf("[%llu,%llu] ", e->counters.pcnt, e->counters.bcnt);

	/* Print IP part. */
	if (e->ip.smsk.s_addr)
		printf("-s %s%u.%u.%u.%u/%u.%u.%u.%u ",
		       e->ip.invflags & IPT_INV_SRCIP ? "! " : "",
		       IP_PARTS(e->ip.src.s_addr),
		       IP_PARTS(e->ip.smsk.s_addr));
	if (e->ip.dmsk.s_addr)
		printf("-d %s%u.%u.%u.%u/%u.%u.%u.%u ",
		       e->ip.invflags & IPT_INV_SRCIP ? "! " : "",
		       IP_PARTS(e->ip.dst.s_addr),
		       IP_PARTS(e->ip.dmsk.s_addr));

	print_iface('i', e->ip.iniface, e->ip.iniface_mask,
		    e->ip.invflags & IPT_INV_VIA_IN);
	print_iface('o', e->ip.outiface, e->ip.outiface_mask,
		    e->ip.invflags & IPT_INV_VIA_OUT);
	print_proto(e->ip.proto, e->ip.invflags & IPT_INV_PROTO);

	if (e->ip.flags & IPT_F_FRAG)
		printf("%s-f ",
		       e->ip.invflags & IPT_INV_FRAG ? "! " : "");

	if (e->ip.flags & IPT_F_TOS)
		printf("-t %s0x%02X ",
		       e->ip.invflags & IPT_INV_TOS ? "! " : "",
		       e->ip.tos);

	/* Print matchinfo part */
	if (e->match_name[0]) {
		struct iptables_match *match
			= find_match(e->match_name, TRY_LOAD);

		if (match)
			match->save(e);
		else {
			/* If some bits are non-zero, it implies we *need*
			   to understand it */
			if (non_zero(&e->matchinfo, sizeof(e->matchinfo))) {
				fprintf(stderr,
					"Can't find library for match `%s'\n",
					e->match_name);
				exit(1);
			}
		}
	}

	/* Print targinfo part */
	if (e->target_name[0]) {
		struct iptables_target *target
			= find_target(e->target_name, TRY_LOAD);

		if (target)
			target->save(e);
		else {
			/* If some bits are non-zero, it implies we *need*
			   to understand it */
			if (non_zero(&e->targinfo, sizeof(e->targinfo))) {
				fprintf(stderr,
					"Can't find library for target `%s'\n",
					e->target_name);
				exit(1);
			}
		}
	}
	printf("\n");
}

/* Debugging prototype. */
extern void dump_entries(iptc_handle_t handle);

static int for_each_table(int (*func)(const char *tablename))
{
        int ret = 1;
	FILE *procfile;
	char tablename[IPT_TABLE_MAXNAMELEN+1];

	procfile = fopen("/proc/net/ip_tables_names", O_RDONLY);
	if (!procfile)
		return 0;

	while (fgets(tablename, sizeof(tablename), procfile)) {
		if (tablename[strlen(tablename) - 1] != '\n')
			exit_error(OTHER_PROBLEM, 
				   "Badly formed tablename `%s'\n",
				   tablename);
		tablename[strlen(tablename) - 1] = '\0';
		ret &= func(tablename);
	}

	return ret;
}
	

static int dump_table(const char *tablename)
{
	iptc_handle_t h;

	if (!tablename)
		return for_each_table(&dump_table);

	/* Debugging dump. */
	h = iptc_init(tablename);
	if (!h)
		exit_error(OTHER_PROBLEM, "iptc_init: %s\n",
			   iptc_strerror(errno));
	dump_entries(h);
}
	
static int do_output(const char *tablename)
{
	iptc_handle_t h;
	const char *chain = NULL;

	if (!tablename)
		return for_each_table(&do_output);

	h = iptc_init(tablename);
	if (!h)
 		exit_error(OTHER_PROBLEM, "Can't initialize: %s\n",
			   iptc_strerror(errno));

	if (!binary) {
		time_t now = time(NULL);

		printf("# Generated by iptables-save v%s on %s",
		       NETFILTER_VERSION, ctime(&now));

		/* Dump out chain names */
		for (chain = iptc_first_chain(&h);
		     chain;
		     chain = iptc_next_chain(&h)) {
			printf(":%s ", chain);
			if (iptc_builtin(chain, &h)) {
				struct ipt_counters count;
				printf("%s ",
				       iptc_get_policy(chain, &count, &h));
				printf("%llu %llu\n", count.pcnt, count.bcnt);
			} else {
				printf("- 0 0\n");
			}
		}

		/* Dump out rules */
		for (chain = iptc_first_chain(&h);
		     chain;
		     chain = iptc_next_chain(&h)) {
			unsigned int i;

			for (i = 0; i < iptc_num_rules(chain, &h); i++) {
				const struct ipt_entry *e
					= iptc_get_rule(chain, i, &h);

				if (!e)
					exit_error(OTHER_PROBLEM,
						   "Can't read rule %u"
						   " of chain %s: %s\n",
						   i, chain,
						   iptc_strerror(errno));
				print_rule(e, counters);
			}
		}

		now = time(NULL);
		printf("COMMIT\n");
		printf("# Completed on %s", ctime(&now));
	} else {
		/* Binary, huh?  OK. */
		exit_error(OTHER_PROBLEM, "Binary NYI\n");
	}

	return 1;
}

/* Format:
 * :Chain name POLICY packets bytes
 * rule
 */
int main(int argc, char *argv[])
{
	const char *tablename = NULL;
	int c;

	program_name = "iptables-save";
	program_version = NETFILTER_VERSION;

	while ((c = getopt_long(argc, argv, "bc", options, NULL)) != -1) {
		switch (c) {
		case 'b':
			binary = 1;
			break;

		case 'c':
			counters = 1;
			break;

		case 't':
			/* Select specific table. */
			tablename = optarg;
			break;
		case 'd':
			dump_table(tablename);
			exit(0);
		}
	}

	if (optind < argc) {
		fprintf(stderr, "Unknown arguments found on commandline");
		exit(1);
	}

	return !do_output(tablename);
}
