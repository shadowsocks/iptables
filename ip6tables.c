/* Code to take an ip6tables-style command line and do it. */

/*
 * Author: Paul.Russell@rustcorp.com.au and mneuling@radlogic.com.au
 *
 * (C) 2000-2002 by the netfilter coreteam <coreteam@netfilter.org>:
 * 		    Paul 'Rusty' Russell <rusty@rustcorp.com.au>
 * 		    Marc Boucher <marc+nf@mbsi.ca>
 * 		    James Morris <jmorris@intercode.com.au>
 * 		    Harald Welte <laforge@gnumonks.org>
 * 		    Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
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

#include <getopt.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <limits.h>
#include <ip6tables.h>
#include <xtables.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "ip6tables-multi.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define FMT_NUMERIC	0x0001
#define FMT_NOCOUNTS	0x0002
#define FMT_KILOMEGAGIGA 0x0004
#define FMT_OPTIONS	0x0008
#define FMT_NOTABLE	0x0010
#define FMT_NOTARGET	0x0020
#define FMT_VIA		0x0040
#define FMT_NONEWLINE	0x0080
#define FMT_LINENUMBERS 0x0100

#define FMT_PRINT_RULE (FMT_NOCOUNTS | FMT_OPTIONS | FMT_VIA \
			| FMT_NUMERIC | FMT_NOTABLE)
#define FMT(tab,notab) ((format) & FMT_NOTABLE ? (notab) : (tab))


#define CMD_NONE		0x0000U
#define CMD_INSERT		0x0001U
#define CMD_DELETE		0x0002U
#define CMD_DELETE_NUM		0x0004U
#define CMD_REPLACE		0x0008U
#define CMD_APPEND		0x0010U
#define CMD_LIST		0x0020U
#define CMD_FLUSH		0x0040U
#define CMD_ZERO		0x0080U
#define CMD_NEW_CHAIN		0x0100U
#define CMD_DELETE_CHAIN	0x0200U
#define CMD_SET_POLICY		0x0400U
#define CMD_RENAME_CHAIN	0x0800U
#define NUMBER_OF_CMD	13
static const char cmdflags[] = { 'I', 'D', 'D', 'R', 'A', 'L', 'F', 'Z',
				 'N', 'X', 'P', 'E' };

#define OPTION_OFFSET 256

#define OPT_NONE	0x00000U
#define OPT_NUMERIC	0x00001U
#define OPT_SOURCE	0x00002U
#define OPT_DESTINATION	0x00004U
#define OPT_PROTOCOL	0x00008U
#define OPT_JUMP	0x00010U
#define OPT_VERBOSE	0x00020U
#define OPT_EXPANDED	0x00040U
#define OPT_VIANAMEIN	0x00080U
#define OPT_VIANAMEOUT	0x00100U
#define OPT_LINENUMBERS 0x00200U
#define OPT_COUNTERS	0x00400U
#define NUMBER_OF_OPT	11
static const char optflags[NUMBER_OF_OPT]
= { 'n', 's', 'd', 'p', 'j', 'v', 'x', 'i', 'o', '0', 'c'};

static struct option original_opts[] = {
	{.name = "append",        .has_arg = 1, .val = 'A'},
	{.name = "delete",        .has_arg = 1, .val = 'D'},
	{.name = "insert",        .has_arg = 1, .val = 'I'},
	{.name = "replace",       .has_arg = 1, .val = 'R'},
	{.name = "list",          .has_arg = 2, .val = 'L'},
	{.name = "flush",         .has_arg = 2, .val = 'F'},
	{.name = "zero",          .has_arg = 2, .val = 'Z'},
	{.name = "new-chain",     .has_arg = 1, .val = 'N'},
	{.name = "delete-chain",  .has_arg = 2, .val = 'X'},
	{.name = "rename-chain",  .has_arg = 1, .val = 'E'},
	{.name = "policy",        .has_arg = 1, .val = 'P'},
	{.name = "source",        .has_arg = 1, .val = 's'},
	{.name = "destination",   .has_arg = 1, .val = 'd'},
	{.name = "src",           .has_arg = 1, .val = 's'}, /* synonym */
	{.name = "dst",           .has_arg = 1, .val = 'd'}, /* synonym */
	{.name = "protocol",      .has_arg = 1, .val = 'p'},
	{.name = "in-interface",  .has_arg = 1, .val = 'i'},
	{.name = "jump",          .has_arg = 1, .val = 'j'},
	{.name = "table",         .has_arg = 1, .val = 't'},
	{.name = "match",         .has_arg = 1, .val = 'm'},
	{.name = "numeric",       .has_arg = 0, .val = 'n'},
	{.name = "out-interface", .has_arg = 1, .val = 'o'},
	{.name = "verbose",       .has_arg = 0, .val = 'v'},
	{.name = "exact",         .has_arg = 0, .val = 'x'},
	{.name = "version",       .has_arg = 0, .val = 'V'},
	{.name = "help",          .has_arg = 2, .val = 'h'},
	{.name = "line-numbers",  .has_arg = 0, .val = '0'},
	{.name = "modprobe",      .has_arg = 1, .val = 'M'},
	{.name = "set-counters",  .has_arg = 1, .val = 'c'},
	{NULL},
};

/* we need this for ip6tables-restore. ip6tables-restore.c sets line to the
 * current line of the input file, in order to give a more precise error
 * message. ip6tables itself doesn't need this, so it is initialized to the
 * magic number of -1 */
int line = -1;

static struct option *opts = original_opts;
static unsigned int global_option_offset = 0;

/* Table of legal combinations of commands and options.  If any of the
 * given commands make an option legal, that option is legal (applies to
 * CMD_LIST and CMD_ZERO only).
 * Key:
 *  +  compulsory
 *  x  illegal
 *     optional
 */

static char commands_v_options[NUMBER_OF_CMD][NUMBER_OF_OPT] =
/* Well, it's better than "Re: Linux vs FreeBSD" */
{
	/*     -n  -s  -d  -p  -j  -v  -x  -i  -o  --line -c */
/*INSERT*/    {'x',' ',' ',' ',' ',' ','x',' ',' ','x',' '},
/*DELETE*/    {'x',' ',' ',' ',' ',' ','x',' ',' ','x','x'},
/*DELETE_NUM*/{'x','x','x','x','x',' ','x','x','x','x','x'},
/*REPLACE*/   {'x',' ',' ',' ',' ',' ','x',' ',' ','x',' '},
/*APPEND*/    {'x',' ',' ',' ',' ',' ','x',' ',' ','x',' '},
/*LIST*/      {' ','x','x','x','x',' ',' ','x','x',' ','x'},
/*FLUSH*/     {'x','x','x','x','x',' ','x','x','x','x','x'},
/*ZERO*/      {'x','x','x','x','x',' ','x','x','x','x','x'},
/*NEW_CHAIN*/ {'x','x','x','x','x',' ','x','x','x','x','x'},
/*DEL_CHAIN*/ {'x','x','x','x','x',' ','x','x','x','x','x'},
/*SET_POLICY*/{'x','x','x','x','x',' ','x','x','x','x','x'},
/*RENAME*/    {'x','x','x','x','x',' ','x','x','x','x','x'}
};

static int inverse_for_options[NUMBER_OF_OPT] =
{
/* -n */ 0,
/* -s */ IP6T_INV_SRCIP,
/* -d */ IP6T_INV_DSTIP,
/* -p */ IP6T_INV_PROTO,
/* -j */ 0,
/* -v */ 0,
/* -x */ 0,
/* -i */ IP6T_INV_VIA_IN,
/* -o */ IP6T_INV_VIA_OUT,
/*--line*/ 0,
/* -c */ 0,
};

const char *program_version;
const char *program_name;

/* A few hardcoded protocols for 'all' and in case the user has no
   /etc/protocols */
struct pprot {
	char *name;
	u_int8_t num;
};

struct afinfo afinfo = {
	.family		= AF_INET6,
	.libprefix	= "libip6t_",
	.ipproto	= IPPROTO_IPV6,
	.kmod		= "ip6_tables",
	.so_rev_match	= IP6T_SO_GET_REVISION_MATCH,
	.so_rev_target	= IP6T_SO_GET_REVISION_TARGET,
};

/* Primitive headers... */
/* defined in netinet/in.h */
#if 0
#ifndef IPPROTO_ESP
#define IPPROTO_ESP 50
#endif
#ifndef IPPROTO_AH
#define IPPROTO_AH 51
#endif
#endif
#ifndef IPPROTO_MH
#define IPPROTO_MH 135
#endif

static const struct pprot chain_protos[] = {
	{ "tcp", IPPROTO_TCP },
	{ "udp", IPPROTO_UDP },
	{ "udplite", IPPROTO_UDPLITE },
	{ "icmpv6", IPPROTO_ICMPV6 },
	{ "ipv6-icmp", IPPROTO_ICMPV6 },
	{ "esp", IPPROTO_ESP },
	{ "ah", IPPROTO_AH },
	{ "ipv6-mh", IPPROTO_MH },
	{ "mh", IPPROTO_MH },
	{ "all", 0 },
};

static char *
proto_to_name(u_int8_t proto, int nolookup)
{
	unsigned int i;

	if (proto && !nolookup) {
		struct protoent *pent = getprotobynumber(proto);
		if (pent)
			return pent->p_name;
	}

	for (i = 0; i < sizeof(chain_protos)/sizeof(struct pprot); i++)
		if (chain_protos[i].num == proto)
			return chain_protos[i].name;

	return NULL;
}

static void free_opts(int reset_offset)
{
	if (opts != original_opts) {
		free(opts);
		opts = original_opts;
		if (reset_offset)
			global_option_offset = 0;
	}
}

static void
exit_tryhelp(int status)
{
	if (line != -1)
		fprintf(stderr, "Error occurred at line: %d\n", line);
	fprintf(stderr, "Try `%s -h' or '%s --help' for more information.\n",
			program_name, program_name );
	free_opts(1);
	exit(status);
}

static void
exit_printhelp(struct ip6tables_rule_match *matches)
{
	struct ip6tables_rule_match *matchp = NULL;
	struct ip6tables_target *t = NULL;

	printf("%s v%s\n\n"
"Usage: %s -[AD] chain rule-specification [options]\n"
"       %s -[RI] chain rulenum rule-specification [options]\n"
"       %s -D chain rulenum [options]\n"
"       %s -[LFZ] [chain] [options]\n"
"       %s -[NX] chain\n"
"       %s -E old-chain-name new-chain-name\n"
"       %s -P chain target [options]\n"
"       %s -h (print this help information)\n\n",
	       program_name, program_version, program_name, program_name,
	       program_name, program_name, program_name, program_name,
	       program_name, program_name);

	printf(
"Commands:\n"
"Either long or short options are allowed.\n"
"  --append  -A chain		Append to chain\n"
"  --delete  -D chain		Delete matching rule from chain\n"
"  --delete  -D chain rulenum\n"
"				Delete rule rulenum (1 = first) from chain\n"
"  --insert  -I chain [rulenum]\n"
"				Insert in chain as rulenum (default 1=first)\n"
"  --replace -R chain rulenum\n"
"				Replace rule rulenum (1 = first) in chain\n"
"  --list    -L [chain]		List the rules in a chain or all chains\n"
"  --flush   -F [chain]		Delete all rules in  chain or all chains\n"
"  --zero    -Z [chain]		Zero counters in chain or all chains\n"
"  --new     -N chain		Create a new user-defined chain\n"
"  --delete-chain\n"
"            -X [chain]		Delete a user-defined chain\n"
"  --policy  -P chain target\n"
"				Change policy on chain to target\n"
"  --rename-chain\n"
"            -E old-chain new-chain\n"
"				Change chain name, (moving any references)\n"

"Options:\n"
"  --proto	-p [!] proto	protocol: by number or name, eg. `tcp'\n"
"  --source	-s [!] address[/mask]\n"
"				source specification\n"
"  --destination -d [!] address[/mask]\n"
"				destination specification\n"
"  --in-interface -i [!] input name[+]\n"
"				network interface name ([+] for wildcard)\n"
"  --jump	-j target\n"
"				target for rule (may load target extension)\n"
"  --match	-m match\n"
"				extended match (may load extension)\n"
"  --numeric	-n		numeric output of addresses and ports\n"
"  --out-interface -o [!] output name[+]\n"
"				network interface name ([+] for wildcard)\n"
"  --table	-t table	table to manipulate (default: `filter')\n"
"  --verbose	-v		verbose mode\n"
"  --line-numbers		print line numbers when listing\n"
"  --exact	-x		expand numbers (display exact values)\n"
/*"[!] --fragment	-f		match second or further fragments only\n"*/
"  --modprobe=<command>		try to insert modules using this command\n"
"  --set-counters PKTS BYTES	set the counter during insert/append\n"
"[!] --version	-V		print package version.\n");

	/* Print out any special helps. A user might like to be able to add a --help
	   to the commandline, and see expected results. So we call help for all
	   specified matches & targets */
	for (t = xtables_targets; t; t = t->next) {
		if (t->used) {
			printf("\n");
			t->help();
		}
	}
	for (matchp = matches; matchp; matchp = matchp->next) {
		printf("\n");
		matchp->match->help();
	}
	exit(0);
}

void
exit_error(enum exittype status, const char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	fprintf(stderr, "%s v%s: ", program_name, program_version);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, "\n");
	if (status == PARAMETER_PROBLEM)
		exit_tryhelp(status);
	if (status == VERSION_PROBLEM)
		fprintf(stderr,
			"Perhaps ip6tables or your kernel needs to be upgraded.\n");
	/* On error paths, make sure that we don't leak memory */
	free_opts(1);
	exit(status);
}

static void
generic_opt_check(int command, int options)
{
	int i, j, legal = 0;

	/* Check that commands are valid with options.  Complicated by the
	 * fact that if an option is legal with *any* command given, it is
	 * legal overall (ie. -z and -l).
	 */
	for (i = 0; i < NUMBER_OF_OPT; i++) {
		legal = 0; /* -1 => illegal, 1 => legal, 0 => undecided. */

		for (j = 0; j < NUMBER_OF_CMD; j++) {
			if (!(command & (1<<j)))
				continue;

			if (!(options & (1<<i))) {
				if (commands_v_options[j][i] == '+')
					exit_error(PARAMETER_PROBLEM,
						   "You need to supply the `-%c' "
						   "option for this command\n",
						   optflags[i]);
			} else {
				if (commands_v_options[j][i] != 'x')
					legal = 1;
				else if (legal == 0)
					legal = -1;
			}
		}
		if (legal == -1)
			exit_error(PARAMETER_PROBLEM,
				   "Illegal option `-%c' with this command\n",
				   optflags[i]);
	}
}

static char
opt2char(int option)
{
	const char *ptr;
	for (ptr = optflags; option > 1; option >>= 1, ptr++);

	return *ptr;
}

static char
cmd2char(int option)
{
	const char *ptr;
	for (ptr = cmdflags; option > 1; option >>= 1, ptr++);

	return *ptr;
}

static void
add_command(unsigned int *cmd, const int newcmd, const int othercmds,
	    int invert)
{
	if (invert)
		exit_error(PARAMETER_PROBLEM, "unexpected ! flag");
	if (*cmd & (~othercmds))
		exit_error(PARAMETER_PROBLEM, "Can't use -%c with -%c\n",
			   cmd2char(newcmd), cmd2char(*cmd & (~othercmds)));
	*cmd |= newcmd;
}

int
check_inverse(const char option[], int *invert, int *my_optind, int argc)
{
	if (option && strcmp(option, "!") == 0) {
		if (*invert)
			exit_error(PARAMETER_PROBLEM,
				   "Multiple `!' flags not allowed");
		*invert = TRUE;
		if (my_optind != NULL) {
			++*my_optind;
			if (argc && *my_optind > argc)
				exit_error(PARAMETER_PROBLEM,
					   "no argument following `!'");
		}

		return TRUE;
	}
	return FALSE;
}

/*
 *	All functions starting with "parse" should succeed, otherwise
 *	the program fails.
 *	Most routines return pointers to static data that may change
 *	between calls to the same or other routines with a few exceptions:
 *	"host_to_addr", "parse_hostnetwork", and "parse_hostnetworkmask"
 *	return global static data.
*/

/* Christophe Burki wants `-p 6' to imply `-m tcp'.  */
static struct ip6tables_match *
find_proto(const char *pname, enum ip6t_tryload tryload, int nolookup, struct ip6tables_rule_match **matches)
{
	unsigned int proto;

	if (string_to_number(pname, 0, 255, &proto) != -1) {
		char *protoname = proto_to_name(proto, nolookup);

		if (protoname)
			return find_match(protoname, tryload, matches);
	} else
		return find_match(pname, tryload, matches);

	return NULL;
}

u_int16_t
parse_protocol(const char *s)
{
	unsigned int proto;

	if (string_to_number(s, 0, 255, &proto) == -1) {
		struct protoent *pent;

		/* first deal with the special case of 'all' to prevent
		 * people from being able to redefine 'all' in nsswitch
		 * and/or provoke expensive [not working] ldap/nis/...
		 * lookups */
		if (!strcmp(s, "all"))
			return 0;

		if ((pent = getprotobyname(s)))
			proto = pent->p_proto;
		else {
			unsigned int i;
			for (i = 0;
			     i < sizeof(chain_protos)/sizeof(struct pprot);
			     i++) {
				if (strcmp(s, chain_protos[i].name) == 0) {
					proto = chain_protos[i].num;
					break;
				}
			}
			if (i == sizeof(chain_protos)/sizeof(struct pprot))
				exit_error(PARAMETER_PROBLEM,
					   "unknown protocol `%s' specified",
					   s);
		}
	}

	return (u_int16_t)proto;
}

/* These are invalid numbers as upper layer protocol */
static int is_exthdr(u_int16_t proto)
{
	return (proto == IPPROTO_ROUTING ||
		proto == IPPROTO_FRAGMENT ||
		proto == IPPROTO_AH ||
		proto == IPPROTO_DSTOPTS);
}

/* Can't be zero. */
static int
parse_rulenumber(const char *rule)
{
	unsigned int rulenum;

	if (string_to_number(rule, 1, INT_MAX, &rulenum) == -1)
		exit_error(PARAMETER_PROBLEM,
			   "Invalid rule number `%s'", rule);

	return rulenum;
}

static const char *
parse_target(const char *targetname)
{
	const char *ptr;

	if (strlen(targetname) < 1)
		exit_error(PARAMETER_PROBLEM,
			   "Invalid target name (too short)");

	if (strlen(targetname)+1 > sizeof(ip6t_chainlabel))
		exit_error(PARAMETER_PROBLEM,
			   "Invalid target name `%s' (%u chars max)",
			   targetname, (unsigned int)sizeof(ip6t_chainlabel)-1);

	for (ptr = targetname; *ptr; ptr++)
		if (isspace(*ptr))
			exit_error(PARAMETER_PROBLEM,
				   "Invalid target name `%s'", targetname);
	return targetname;
}

static void
set_option(unsigned int *options, unsigned int option, u_int8_t *invflg,
	   int invert)
{
	if (*options & option)
		exit_error(PARAMETER_PROBLEM, "multiple -%c flags not allowed",
			   opt2char(option));
	*options |= option;

	if (invert) {
		unsigned int i;
		for (i = 0; 1 << i != option; i++);

		if (!inverse_for_options[i])
			exit_error(PARAMETER_PROBLEM,
				   "cannot have ! before -%c",
				   opt2char(option));
		*invflg |= inverse_for_options[i];
	}
}

static struct option *
merge_options(struct option *oldopts, const struct option *newopts,
	      unsigned int *option_offset)
{
	unsigned int num_old, num_new, i;
	struct option *merge;

	if (newopts == NULL)
		return oldopts;

	for (num_old = 0; oldopts[num_old].name; num_old++);
	for (num_new = 0; newopts[num_new].name; num_new++);

	global_option_offset += OPTION_OFFSET;
	*option_offset = global_option_offset;

	merge = malloc(sizeof(struct option) * (num_new + num_old + 1));
	memcpy(merge, oldopts, num_old * sizeof(struct option));
	free_opts(0); /* Release previous options merged if any */
	for (i = 0; i < num_new; i++) {
		merge[num_old + i] = newopts[i];
		merge[num_old + i].val += *option_offset;
	}
	memset(merge + num_old + num_new, 0, sizeof(struct option));

	return merge;
}

void register_match6(struct ip6tables_match *me)
{
	me->family = AF_INET6;
	xtables_register_match(me);
}

void register_target6(struct ip6tables_target *me)
{
	me->family = AF_INET6;
	xtables_register_target(me);
}

static void
print_num(u_int64_t number, unsigned int format)
{
	if (format & FMT_KILOMEGAGIGA) {
		if (number > 99999) {
			number = (number + 500) / 1000;
			if (number > 9999) {
				number = (number + 500) / 1000;
				if (number > 9999) {
					number = (number + 500) / 1000;
					if (number > 9999) {
						number = (number + 500) / 1000;
						printf(FMT("%4lluT ","%lluT "), (unsigned long long)number);
					}
					else printf(FMT("%4lluG ","%lluG "), (unsigned long long)number);
				}
				else printf(FMT("%4lluM ","%lluM "), (unsigned long long)number);
			} else
				printf(FMT("%4lluK ","%lluK "), (unsigned long long)number);
		} else
			printf(FMT("%5llu ","%llu "), (unsigned long long)number);
	} else
		printf(FMT("%8llu ","%llu "), (unsigned long long)number);
}


static void
print_header(unsigned int format, const char *chain, ip6tc_handle_t *handle)
{
	struct ip6t_counters counters;
	const char *pol = ip6tc_get_policy(chain, &counters, handle);
	printf("Chain %s", chain);
	if (pol) {
		printf(" (policy %s", pol);
		if (!(format & FMT_NOCOUNTS)) {
			fputc(' ', stdout);
			print_num(counters.pcnt, (format|FMT_NOTABLE));
			fputs("packets, ", stdout);
			print_num(counters.bcnt, (format|FMT_NOTABLE));
			fputs("bytes", stdout);
		}
		printf(")\n");
	} else {
		unsigned int refs;
		if (!ip6tc_get_references(&refs, chain, handle))
			printf(" (ERROR obtaining refs)\n");
		else
			printf(" (%u references)\n", refs);
	}

	if (format & FMT_LINENUMBERS)
		printf(FMT("%-4s ", "%s "), "num");
	if (!(format & FMT_NOCOUNTS)) {
		if (format & FMT_KILOMEGAGIGA) {
			printf(FMT("%5s ","%s "), "pkts");
			printf(FMT("%5s ","%s "), "bytes");
		} else {
			printf(FMT("%8s ","%s "), "pkts");
			printf(FMT("%10s ","%s "), "bytes");
		}
	}
	if (!(format & FMT_NOTARGET))
		printf(FMT("%-9s ","%s "), "target");
	fputs(" prot ", stdout);
	if (format & FMT_OPTIONS)
		fputs("opt", stdout);
	if (format & FMT_VIA) {
		printf(FMT(" %-6s ","%s "), "in");
		printf(FMT("%-6s ","%s "), "out");
	}
	printf(FMT(" %-19s ","%s "), "source");
	printf(FMT(" %-19s "," %s "), "destination");
	printf("\n");
}


static int
print_match(const struct ip6t_entry_match *m,
	    const struct ip6t_ip6 *ip,
	    int numeric)
{
	struct ip6tables_match *match = find_match(m->u.user.name, TRY_LOAD, NULL);

	if (match) {
		if (match->print)
			match->print(ip, m, numeric);
		else
			printf("%s ", match->name);
	} else {
		if (m->u.user.name[0])
			printf("UNKNOWN match `%s' ", m->u.user.name);
	}
	/* Don't stop iterating. */
	return 0;
}

/* e is called `fw' here for historical reasons */
static void
print_firewall(const struct ip6t_entry *fw,
	       const char *targname,
	       unsigned int num,
	       unsigned int format,
	       const ip6tc_handle_t handle)
{
	struct ip6tables_target *target = NULL;
	const struct ip6t_entry_target *t;
	u_int8_t flags;
	char buf[BUFSIZ];

	if (!ip6tc_is_chain(targname, handle))
		target = find_target(targname, TRY_LOAD);
	else
		target = find_target(IP6T_STANDARD_TARGET, LOAD_MUST_SUCCEED);

	t = ip6t_get_target((struct ip6t_entry *)fw);
	flags = fw->ipv6.flags;

	if (format & FMT_LINENUMBERS)
		printf(FMT("%-4u ", "%u "), num+1);

	if (!(format & FMT_NOCOUNTS)) {
		print_num(fw->counters.pcnt, format);
		print_num(fw->counters.bcnt, format);
	}

	if (!(format & FMT_NOTARGET))
		printf(FMT("%-9s ", "%s "), targname);

	fputc(fw->ipv6.invflags & IP6T_INV_PROTO ? '!' : ' ', stdout);
	{
		char *pname = proto_to_name(fw->ipv6.proto, format&FMT_NUMERIC);
		if (pname)
			printf(FMT("%-5s", "%s "), pname);
		else
			printf(FMT("%-5hu", "%hu "), fw->ipv6.proto);
	}

	if (format & FMT_OPTIONS) {
		if (format & FMT_NOTABLE)
			fputs("opt ", stdout);
		fputc(' ', stdout); /* Invert flag of FRAG */
		fputc(' ', stdout); /* -f */
		fputc(' ', stdout);
	}

	if (format & FMT_VIA) {
		char iface[IFNAMSIZ+2];

		if (fw->ipv6.invflags & IP6T_INV_VIA_IN) {
			iface[0] = '!';
			iface[1] = '\0';
		}
		else iface[0] = '\0';

		if (fw->ipv6.iniface[0] != '\0') {
			strcat(iface, fw->ipv6.iniface);
		}
		else if (format & FMT_NUMERIC) strcat(iface, "*");
		else strcat(iface, "any");
		printf(FMT(" %-6s ","in %s "), iface);

		if (fw->ipv6.invflags & IP6T_INV_VIA_OUT) {
			iface[0] = '!';
			iface[1] = '\0';
		}
		else iface[0] = '\0';

		if (fw->ipv6.outiface[0] != '\0') {
			strcat(iface, fw->ipv6.outiface);
		}
		else if (format & FMT_NUMERIC) strcat(iface, "*");
		else strcat(iface, "any");
		printf(FMT("%-6s ","out %s "), iface);
	}

	fputc(fw->ipv6.invflags & IP6T_INV_SRCIP ? '!' : ' ', stdout);
	if (!memcmp(&fw->ipv6.smsk, &in6addr_any, sizeof in6addr_any)
	    && !(format & FMT_NUMERIC))
		printf(FMT("%-19s ","%s "), "anywhere");
	else {
		if (format & FMT_NUMERIC)
			sprintf(buf, "%s", ip6addr_to_numeric(&fw->ipv6.src));
		else
			sprintf(buf, "%s", ip6addr_to_anyname(&fw->ipv6.src));
		strcat(buf, ip6mask_to_numeric(&fw->ipv6.smsk));
		printf(FMT("%-19s ","%s "), buf);
	}

	fputc(fw->ipv6.invflags & IP6T_INV_DSTIP ? '!' : ' ', stdout);
	if (!memcmp(&fw->ipv6.dmsk, &in6addr_any, sizeof in6addr_any)
	    && !(format & FMT_NUMERIC))
		printf(FMT("%-19s","-> %s"), "anywhere");
	else {
		if (format & FMT_NUMERIC)
			sprintf(buf, "%s", ip6addr_to_numeric(&fw->ipv6.dst));
		else
			sprintf(buf, "%s", ip6addr_to_anyname(&fw->ipv6.dst));
		strcat(buf, ip6mask_to_numeric(&fw->ipv6.dmsk));
		printf(FMT("%-19s","-> %s"), buf);
	}

	if (format & FMT_NOTABLE)
		fputs("  ", stdout);

	IP6T_MATCH_ITERATE(fw, print_match, &fw->ipv6, format & FMT_NUMERIC);

	if (target) {
		if (target->print)
			/* Print the target information. */
			target->print(&fw->ipv6, t, format & FMT_NUMERIC);
	} else if (t->u.target_size != sizeof(*t))
		printf("[%u bytes of unknown target data] ",
		       (unsigned int)(t->u.target_size - sizeof(*t)));

	if (!(format & FMT_NONEWLINE))
		fputc('\n', stdout);
}

static void
print_firewall_line(const struct ip6t_entry *fw,
		    const ip6tc_handle_t h)
{
	struct ip6t_entry_target *t;

	t = ip6t_get_target((struct ip6t_entry *)fw);
	print_firewall(fw, t->u.user.name, 0, FMT_PRINT_RULE, h);
}

static int
append_entry(const ip6t_chainlabel chain,
	     struct ip6t_entry *fw,
	     unsigned int nsaddrs,
	     const struct in6_addr saddrs[],
	     unsigned int ndaddrs,
	     const struct in6_addr daddrs[],
	     int verbose,
	     ip6tc_handle_t *handle)
{
	unsigned int i, j;
	int ret = 1;

	for (i = 0; i < nsaddrs; i++) {
		fw->ipv6.src = saddrs[i];
		for (j = 0; j < ndaddrs; j++) {
			fw->ipv6.dst = daddrs[j];
			if (verbose)
				print_firewall_line(fw, *handle);
			ret &= ip6tc_append_entry(chain, fw, handle);
		}
	}

	return ret;
}

static int
replace_entry(const ip6t_chainlabel chain,
	      struct ip6t_entry *fw,
	      unsigned int rulenum,
	      const struct in6_addr *saddr,
	      const struct in6_addr *daddr,
	      int verbose,
	      ip6tc_handle_t *handle)
{
	fw->ipv6.src = *saddr;
	fw->ipv6.dst = *daddr;

	if (verbose)
		print_firewall_line(fw, *handle);
	return ip6tc_replace_entry(chain, fw, rulenum, handle);
}

static int
insert_entry(const ip6t_chainlabel chain,
	     struct ip6t_entry *fw,
	     unsigned int rulenum,
	     unsigned int nsaddrs,
	     const struct in6_addr saddrs[],
	     unsigned int ndaddrs,
	     const struct in6_addr daddrs[],
	     int verbose,
	     ip6tc_handle_t *handle)
{
	unsigned int i, j;
	int ret = 1;

	for (i = 0; i < nsaddrs; i++) {
		fw->ipv6.src = saddrs[i];
		for (j = 0; j < ndaddrs; j++) {
			fw->ipv6.dst = daddrs[j];
			if (verbose)
				print_firewall_line(fw, *handle);
			ret &= ip6tc_insert_entry(chain, fw, rulenum, handle);
		}
	}

	return ret;
}

static unsigned char *
make_delete_mask(struct ip6t_entry *fw, struct ip6tables_rule_match *matches)
{
	/* Establish mask for comparison */
	unsigned int size;
	struct ip6tables_rule_match *matchp;
	unsigned char *mask, *mptr;

	size = sizeof(struct ip6t_entry);
	for (matchp = matches; matchp; matchp = matchp->next)
		size += IP6T_ALIGN(sizeof(struct ip6t_entry_match)) + matchp->match->size;

	mask = fw_calloc(1, size
			 + IP6T_ALIGN(sizeof(struct ip6t_entry_target))
			 + xtables_targets->size);

	memset(mask, 0xFF, sizeof(struct ip6t_entry));
	mptr = mask + sizeof(struct ip6t_entry);

	for (matchp = matches; matchp; matchp = matchp->next) {
		memset(mptr, 0xFF,
		       IP6T_ALIGN(sizeof(struct ip6t_entry_match))
		       + matchp->match->userspacesize);
		mptr += IP6T_ALIGN(sizeof(struct ip6t_entry_match)) + matchp->match->size;
	}

	memset(mptr, 0xFF,
	       IP6T_ALIGN(sizeof(struct ip6t_entry_target))
	       + xtables_targets->userspacesize);

	return mask;
}

static int
delete_entry(const ip6t_chainlabel chain,
	     struct ip6t_entry *fw,
	     unsigned int nsaddrs,
	     const struct in6_addr saddrs[],
	     unsigned int ndaddrs,
	     const struct in6_addr daddrs[],
	     int verbose,
	     ip6tc_handle_t *handle,
	     struct ip6tables_rule_match *matches)
{
	unsigned int i, j;
	int ret = 1;
	unsigned char *mask;

	mask = make_delete_mask(fw, matches);
	for (i = 0; i < nsaddrs; i++) {
		fw->ipv6.src = saddrs[i];
		for (j = 0; j < ndaddrs; j++) {
			fw->ipv6.dst = daddrs[j];
			if (verbose)
				print_firewall_line(fw, *handle);
			ret &= ip6tc_delete_entry(chain, fw, mask, handle);
		}
	}
	free(mask);

	return ret;
}

int
for_each_chain(int (*fn)(const ip6t_chainlabel, int, ip6tc_handle_t *),
	       int verbose, int builtinstoo, ip6tc_handle_t *handle)
{
	int ret = 1;
	const char *chain;
	char *chains;
	unsigned int i, chaincount = 0;

	chain = ip6tc_first_chain(handle);
	while (chain) {
		chaincount++;
		chain = ip6tc_next_chain(handle);
	}

	chains = fw_malloc(sizeof(ip6t_chainlabel) * chaincount);
	i = 0;
	chain = ip6tc_first_chain(handle);
	while (chain) {
		strcpy(chains + i*sizeof(ip6t_chainlabel), chain);
		i++;
		chain = ip6tc_next_chain(handle);
	}

	for (i = 0; i < chaincount; i++) {
		if (!builtinstoo
		    && ip6tc_builtin(chains + i*sizeof(ip6t_chainlabel),
				    *handle) == 1)
			continue;
		ret &= fn(chains + i*sizeof(ip6t_chainlabel), verbose, handle);
	}

	free(chains);
	return ret;
}

int
flush_entries(const ip6t_chainlabel chain, int verbose,
	      ip6tc_handle_t *handle)
{
	if (!chain)
		return for_each_chain(flush_entries, verbose, 1, handle);

	if (verbose)
		fprintf(stdout, "Flushing chain `%s'\n", chain);
	return ip6tc_flush_entries(chain, handle);
}

static int
zero_entries(const ip6t_chainlabel chain, int verbose,
	     ip6tc_handle_t *handle)
{
	if (!chain)
		return for_each_chain(zero_entries, verbose, 1, handle);

	if (verbose)
		fprintf(stdout, "Zeroing chain `%s'\n", chain);
	return ip6tc_zero_entries(chain, handle);
}

int
delete_chain(const ip6t_chainlabel chain, int verbose,
	     ip6tc_handle_t *handle)
{
	if (!chain)
		return for_each_chain(delete_chain, verbose, 0, handle);

	if (verbose)
		fprintf(stdout, "Deleting chain `%s'\n", chain);
	return ip6tc_delete_chain(chain, handle);
}

static int
list_entries(const ip6t_chainlabel chain, int verbose, int numeric,
	     int expanded, int linenumbers, ip6tc_handle_t *handle)
{
	int found = 0;
	unsigned int format;
	const char *this;

	format = FMT_OPTIONS;
	if (!verbose)
		format |= FMT_NOCOUNTS;
	else
		format |= FMT_VIA;

	if (numeric)
		format |= FMT_NUMERIC;

	if (!expanded)
		format |= FMT_KILOMEGAGIGA;

	if (linenumbers)
		format |= FMT_LINENUMBERS;

	for (this = ip6tc_first_chain(handle);
	     this;
	     this = ip6tc_next_chain(handle)) {
		const struct ip6t_entry *i;
		unsigned int num;

		if (chain && strcmp(chain, this) != 0)
			continue;

		if (found) printf("\n");

		print_header(format, this, handle);
		i = ip6tc_first_rule(this, handle);

		num = 0;
		while (i) {
			print_firewall(i,
				       ip6tc_get_target(i, handle),
				       num++,
				       format,
				       *handle);
			i = ip6tc_next_rule(i, handle);
		}
		found = 1;
	}

	errno = ENOENT;
	return found;
}

static struct ip6t_entry *
generate_entry(const struct ip6t_entry *fw,
	       struct ip6tables_rule_match *matches,
	       struct ip6t_entry_target *target)
{
	unsigned int size;
	struct ip6tables_rule_match *matchp;
	struct ip6t_entry *e;

	size = sizeof(struct ip6t_entry);
	for (matchp = matches; matchp; matchp = matchp->next)
		size += matchp->match->m->u.match_size;

	e = fw_malloc(size + target->u.target_size);
	*e = *fw;
	e->target_offset = size;
	e->next_offset = size + target->u.target_size;

	size = 0;
	for (matchp = matches; matchp; matchp = matchp->next) {
		memcpy(e->elems + size, matchp->match->m, matchp->match->m->u.match_size);
		size += matchp->match->m->u.match_size;
	}
	memcpy(e->elems + size, target, target->u.target_size);

	return e;
}

static void clear_rule_matches(struct ip6tables_rule_match **matches)
{
	struct ip6tables_rule_match *matchp, *tmp;

	for (matchp = *matches; matchp;) {
		tmp = matchp->next;
		if (matchp->match->m) {
			free(matchp->match->m);
			matchp->match->m = NULL;
		}
		if (matchp->match == matchp->match->next) {
			free(matchp->match);
			matchp->match = NULL;
		}
		free(matchp);
		matchp = tmp;
	}

	*matches = NULL;
}

static void set_revision(char *name, u_int8_t revision)
{
	/* Old kernel sources don't have ".revision" field,
	   but we stole a byte from name. */
	name[IP6T_FUNCTION_MAXNAMELEN - 2] = '\0';
	name[IP6T_FUNCTION_MAXNAMELEN - 1] = revision;
}

int do_command6(int argc, char *argv[], char **table, ip6tc_handle_t *handle)
{
	struct ip6t_entry fw, *e = NULL;
	int invert = 0;
	unsigned int nsaddrs = 0, ndaddrs = 0;
	struct in6_addr *saddrs = NULL, *daddrs = NULL;

	int c, verbose = 0;
	unsigned i;
	const char *chain = NULL;
	const char *shostnetworkmask = NULL, *dhostnetworkmask = NULL;
	const char *policy = NULL, *newname = NULL;
	unsigned int rulenum = 0, options = 0, command = 0;
	const char *pcnt = NULL, *bcnt = NULL;
	int ret = 1;
	struct ip6tables_match *m;
	struct ip6tables_rule_match *matches = NULL;
	struct ip6tables_rule_match *matchp;
	struct ip6tables_target *target = NULL;
	struct ip6tables_target *t;
	const char *jumpto = "";
	char *protocol = NULL;
	int proto_used = 0;
	unsigned long long cnt;

	memset(&fw, 0, sizeof(fw));

	/* re-set optind to 0 in case do_command gets called
	 * a second time */
	optind = 0;

	/* clear mflags in case do_command gets called a second time
	 * (we clear the global list of all matches for security)*/
	for (m = xtables_matches; m; m = m->next)
		m->mflags = 0;

	for (t = xtables_targets; t; t = t->next) {
		t->tflags = 0;
		t->used = 0;
	}

	/* Suppress error messages: we may add new options if we
           demand-load a protocol. */
	opterr = 0;

	while ((c = getopt_long(argc, argv,
	   "-A:D:R:I:L::M:F::Z::N:X::E:P:Vh::o:p:s:d:j:i:bvnt:m:xc:",
					   opts, NULL)) != -1) {
		switch (c) {
			/*
			 * Command selection
			 */
		case 'A':
			add_command(&command, CMD_APPEND, CMD_NONE,
				    invert);
			chain = optarg;
			break;

		case 'D':
			add_command(&command, CMD_DELETE, CMD_NONE,
				    invert);
			chain = optarg;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!') {
				rulenum = parse_rulenumber(argv[optind++]);
				command = CMD_DELETE_NUM;
			}
			break;

		case 'R':
			add_command(&command, CMD_REPLACE, CMD_NONE,
				    invert);
			chain = optarg;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!')
				rulenum = parse_rulenumber(argv[optind++]);
			else
				exit_error(PARAMETER_PROBLEM,
					   "-%c requires a rule number",
					   cmd2char(CMD_REPLACE));
			break;

		case 'I':
			add_command(&command, CMD_INSERT, CMD_NONE,
				    invert);
			chain = optarg;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!')
				rulenum = parse_rulenumber(argv[optind++]);
			else rulenum = 1;
			break;

		case 'L':
			add_command(&command, CMD_LIST, CMD_ZERO,
				    invert);
			if (optarg) chain = optarg;
			else if (optind < argc && argv[optind][0] != '-'
				 && argv[optind][0] != '!')
				chain = argv[optind++];
			break;

		case 'F':
			add_command(&command, CMD_FLUSH, CMD_NONE,
				    invert);
			if (optarg) chain = optarg;
			else if (optind < argc && argv[optind][0] != '-'
				 && argv[optind][0] != '!')
				chain = argv[optind++];
			break;

		case 'Z':
			add_command(&command, CMD_ZERO, CMD_LIST,
				    invert);
			if (optarg) chain = optarg;
			else if (optind < argc && argv[optind][0] != '-'
				&& argv[optind][0] != '!')
				chain = argv[optind++];
			break;

		case 'N':
			if (optarg && (*optarg == '-' || *optarg == '!'))
				exit_error(PARAMETER_PROBLEM,
					   "chain name not allowed to start "
					   "with `%c'\n", *optarg);
			if (find_target(optarg, TRY_LOAD))
				exit_error(PARAMETER_PROBLEM,
					   "chain name may not clash "
					   "with target name\n");
			add_command(&command, CMD_NEW_CHAIN, CMD_NONE,
				    invert);
			chain = optarg;
			break;

		case 'X':
			add_command(&command, CMD_DELETE_CHAIN, CMD_NONE,
				    invert);
			if (optarg) chain = optarg;
			else if (optind < argc && argv[optind][0] != '-'
				 && argv[optind][0] != '!')
				chain = argv[optind++];
			break;

		case 'E':
			add_command(&command, CMD_RENAME_CHAIN, CMD_NONE,
				    invert);
			chain = optarg;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!')
				newname = argv[optind++];
			else
				exit_error(PARAMETER_PROBLEM,
					   "-%c requires old-chain-name and "
					   "new-chain-name",
					    cmd2char(CMD_RENAME_CHAIN));
			break;

		case 'P':
			add_command(&command, CMD_SET_POLICY, CMD_NONE,
				    invert);
			chain = optarg;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!')
				policy = argv[optind++];
			else
				exit_error(PARAMETER_PROBLEM,
					   "-%c requires a chain and a policy",
					   cmd2char(CMD_SET_POLICY));
			break;

		case 'h':
			if (!optarg)
				optarg = argv[optind];

			/* ip6tables -p icmp -h */
			if (!matches && protocol)
				find_match(protocol, TRY_LOAD, &matches);

			exit_printhelp(matches);

			/*
			 * Option selection
			 */
		case 'p':
			check_inverse(optarg, &invert, &optind, argc);
			set_option(&options, OPT_PROTOCOL, &fw.ipv6.invflags,
				   invert);

			/* Canonicalize into lower case */
			for (protocol = argv[optind-1]; *protocol; protocol++)
				*protocol = tolower(*protocol);

			protocol = argv[optind-1];
			fw.ipv6.proto = parse_protocol(protocol);
			fw.ipv6.flags |= IP6T_F_PROTO;

			if (fw.ipv6.proto == 0
			    && (fw.ipv6.invflags & IP6T_INV_PROTO))
				exit_error(PARAMETER_PROBLEM,
					   "rule would never match protocol");

			if (is_exthdr(fw.ipv6.proto)
			    && (fw.ipv6.invflags & IP6T_INV_PROTO) == 0)
				fprintf(stderr,
					"Warning: never matched protocol: %s. "
					"use extension match instead.\n",
					protocol);
			break;

		case 's':
			check_inverse(optarg, &invert, &optind, argc);
			set_option(&options, OPT_SOURCE, &fw.ipv6.invflags,
				   invert);
			shostnetworkmask = argv[optind-1];
			break;

		case 'd':
			check_inverse(optarg, &invert, &optind, argc);
			set_option(&options, OPT_DESTINATION, &fw.ipv6.invflags,
				   invert);
			dhostnetworkmask = argv[optind-1];
			break;

		case 'j':
			set_option(&options, OPT_JUMP, &fw.ipv6.invflags,
				   invert);
			jumpto = parse_target(optarg);
			/* TRY_LOAD (may be chain name) */
			target = find_target(jumpto, TRY_LOAD);

			if (target) {
				size_t size;

				size = IP6T_ALIGN(sizeof(struct ip6t_entry_target))
					+ target->size;

				target->t = fw_calloc(1, size);
				target->t->u.target_size = size;
				strcpy(target->t->u.user.name, jumpto);
				if (target->init != NULL)
					target->init(target->t);
				opts = merge_options(opts, target->extra_opts, &target->option_offset);
			}
			break;


		case 'i':
			check_inverse(optarg, &invert, &optind, argc);
			set_option(&options, OPT_VIANAMEIN, &fw.ipv6.invflags,
				   invert);
			parse_interface(argv[optind-1],
					fw.ipv6.iniface,
					fw.ipv6.iniface_mask);
			break;

		case 'o':
			check_inverse(optarg, &invert, &optind, argc);
			set_option(&options, OPT_VIANAMEOUT, &fw.ipv6.invflags,
				   invert);
			parse_interface(argv[optind-1],
					fw.ipv6.outiface,
					fw.ipv6.outiface_mask);
			break;

		case 'v':
			if (!verbose)
				set_option(&options, OPT_VERBOSE,
					   &fw.ipv6.invflags, invert);
			verbose++;
			break;

		case 'm': {
			size_t size;

			if (invert)
				exit_error(PARAMETER_PROBLEM,
					   "unexpected ! flag before --match");

			m = find_match(optarg, LOAD_MUST_SUCCEED, &matches);
			size = IP6T_ALIGN(sizeof(struct ip6t_entry_match))
					 + m->size;
			m->m = fw_calloc(1, size);
			m->m->u.match_size = size;
			strcpy(m->m->u.user.name, m->name);
			set_revision(m->m->u.user.name, m->revision);
			if (m->init != NULL)
				m->init(m->m);
			if (m != m->next)
				/* Merge options for non-cloned matches */
				opts = merge_options(opts, m->extra_opts, &m->option_offset);
		}
		break;

		case 'n':
			set_option(&options, OPT_NUMERIC, &fw.ipv6.invflags,
				   invert);
			break;

		case 't':
			if (invert)
				exit_error(PARAMETER_PROBLEM,
					   "unexpected ! flag before --table");
			*table = argv[optind-1];
			break;

		case 'x':
			set_option(&options, OPT_EXPANDED, &fw.ipv6.invflags,
				   invert);
			break;

		case 'V':
			if (invert)
				printf("Not %s ;-)\n", program_version);
			else
				printf("%s v%s\n",
				       program_name, program_version);
			exit(0);

		case '0':
			set_option(&options, OPT_LINENUMBERS, &fw.ipv6.invflags,
				   invert);
			break;

		case 'M':
			modprobe_program = optarg;
			break;

		case 'c':

			set_option(&options, OPT_COUNTERS, &fw.ipv6.invflags,
				   invert);
			pcnt = optarg;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!')
				bcnt = argv[optind++];
			else
				exit_error(PARAMETER_PROBLEM,
					"-%c requires packet and byte counter",
					opt2char(OPT_COUNTERS));

			if (sscanf(pcnt, "%llu", (unsigned long long *)&cnt) != 1)
				exit_error(PARAMETER_PROBLEM,
					"-%c packet counter not numeric",
					opt2char(OPT_COUNTERS));
			fw.counters.pcnt = cnt;

			if (sscanf(bcnt, "%llu", (unsigned long long *)&cnt) != 1)
				exit_error(PARAMETER_PROBLEM,
					"-%c byte counter not numeric",
					opt2char(OPT_COUNTERS));
			fw.counters.bcnt = cnt;

			break;


		case 1: /* non option */
			if (optarg[0] == '!' && optarg[1] == '\0') {
				if (invert)
					exit_error(PARAMETER_PROBLEM,
						   "multiple consecutive ! not"
						   " allowed");
				invert = TRUE;
				optarg[0] = '\0';
				continue;
			}
			fprintf(stderr, "Bad argument `%s'\n", optarg);
			exit_tryhelp(2);

		default:
			if (!target
			    || !(target->parse(c - target->option_offset,
					       argv, invert,
					       &target->tflags,
					       &fw, &target->t))) {
				for (matchp = matches; matchp; matchp = matchp->next) {
					if (matchp->completed)
						continue;
					if (matchp->match->parse(c - matchp->match->option_offset,
						     argv, invert,
						     &matchp->match->mflags,
						     &fw,
						     &matchp->match->m))
						break;
				}
				m = matchp ? matchp->match : NULL;

				/* If you listen carefully, you can
				   actually hear this code suck. */

				/* some explanations (after four different bugs
				 * in 3 different releases): If we encounter a
				 * parameter, that has not been parsed yet,
				 * it's not an option of an explicitly loaded
				 * match or a target.  However, we support
				 * implicit loading of the protocol match
				 * extension.  '-p tcp' means 'l4 proto 6' and
				 * at the same time 'load tcp protocol match on
				 * demand if we specify --dport'.
				 *
				 * To make this work, we need to make sure:
				 * - the parameter has not been parsed by
				 *   a match (m above)
				 * - a protocol has been specified
				 * - the protocol extension has not been
				 *   loaded yet, or is loaded and unused
				 *   [think of ip6tables-restore!]
				 * - the protocol extension can be successively
				 *   loaded
				 */
				if (m == NULL
				    && protocol
				    && (!find_proto(protocol, DONT_LOAD,
						   options&OPT_NUMERIC, NULL)
					|| (find_proto(protocol, DONT_LOAD,
							options&OPT_NUMERIC, NULL)
					    && (proto_used == 0))
				       )
				    && (m = find_proto(protocol, TRY_LOAD,
						       options&OPT_NUMERIC, &matches))) {
					/* Try loading protocol */
					size_t size;

					proto_used = 1;

					size = IP6T_ALIGN(sizeof(struct ip6t_entry_match))
							 + m->size;

					m->m = fw_calloc(1, size);
					m->m->u.match_size = size;
					strcpy(m->m->u.user.name, m->name);
					set_revision(m->m->u.user.name,
						     m->revision);
					if (m->init != NULL)
						m->init(m->m);

					opts = merge_options(opts,
					    m->extra_opts, &m->option_offset);

					optind--;
					continue;
				}

				if (!m)
					exit_error(PARAMETER_PROBLEM,
						   "Unknown arg `%s'",
						   argv[optind-1]);
			}
		}
		invert = FALSE;
	}

	for (matchp = matches; matchp; matchp = matchp->next)
		if (matchp->match->final_check != NULL)
			matchp->match->final_check(matchp->match->mflags);

	if (target != NULL && target->final_check != NULL)
		target->final_check(target->tflags);

	/* Fix me: must put inverse options checking here --MN */

	if (optind < argc)
		exit_error(PARAMETER_PROBLEM,
			   "unknown arguments found on commandline");
	if (!command)
		exit_error(PARAMETER_PROBLEM, "no command specified");
	if (invert)
		exit_error(PARAMETER_PROBLEM,
			   "nothing appropriate following !");

	if (command & (CMD_REPLACE | CMD_INSERT | CMD_DELETE | CMD_APPEND)) {
		if (!(options & OPT_DESTINATION))
			dhostnetworkmask = "::0/0";
		if (!(options & OPT_SOURCE))
			shostnetworkmask = "::0/0";
	}

	if (shostnetworkmask)
		ip6parse_hostnetworkmask(shostnetworkmask, &saddrs,
		                         &fw.ipv6.smsk, &nsaddrs);

	if (dhostnetworkmask)
		ip6parse_hostnetworkmask(dhostnetworkmask, &daddrs,
		                         &fw.ipv6.dmsk, &ndaddrs);

	if ((nsaddrs > 1 || ndaddrs > 1) &&
	    (fw.ipv6.invflags & (IP6T_INV_SRCIP | IP6T_INV_DSTIP)))
		exit_error(PARAMETER_PROBLEM, "! not allowed with multiple"
			   " source or destination IP addresses");

	if (command == CMD_REPLACE && (nsaddrs != 1 || ndaddrs != 1))
		exit_error(PARAMETER_PROBLEM, "Replacement rule does not "
			   "specify a unique address");

	generic_opt_check(command, options);

	if (chain && strlen(chain) > IP6T_FUNCTION_MAXNAMELEN)
		exit_error(PARAMETER_PROBLEM,
			   "chain name `%s' too long (must be under %i chars)",
			   chain, IP6T_FUNCTION_MAXNAMELEN);

	/* only allocate handle if we weren't called with a handle */
	if (!*handle)
		*handle = ip6tc_init(*table);

	/* try to insmod the module if iptc_init failed */
	if (!*handle && load_xtables_ko(modprobe_program, 0) != -1)
		*handle = ip6tc_init(*table);

	if (!*handle)
		exit_error(VERSION_PROBLEM,
			"can't initialize ip6tables table `%s': %s",
			*table, ip6tc_strerror(errno));

	if (command == CMD_APPEND
	    || command == CMD_DELETE
	    || command == CMD_INSERT
	    || command == CMD_REPLACE) {
		if (strcmp(chain, "PREROUTING") == 0
		    || strcmp(chain, "INPUT") == 0) {
			/* -o not valid with incoming packets. */
			if (options & OPT_VIANAMEOUT)
				exit_error(PARAMETER_PROBLEM,
					   "Can't use -%c with %s\n",
					   opt2char(OPT_VIANAMEOUT),
					   chain);
		}

		if (strcmp(chain, "POSTROUTING") == 0
		    || strcmp(chain, "OUTPUT") == 0) {
			/* -i not valid with outgoing packets */
			if (options & OPT_VIANAMEIN)
				exit_error(PARAMETER_PROBLEM,
					   "Can't use -%c with %s\n",
					   opt2char(OPT_VIANAMEIN),
					   chain);
		}

		if (target && ip6tc_is_chain(jumpto, *handle)) {
			fprintf(stderr,
				"Warning: using chain %s, not extension\n",
				jumpto);

			if (target->t)
				free(target->t);

			target = NULL;
		}

		/* If they didn't specify a target, or it's a chain
		   name, use standard. */
		if (!target
		    && (strlen(jumpto) == 0
			|| ip6tc_is_chain(jumpto, *handle))) {
			size_t size;

			target = find_target(IP6T_STANDARD_TARGET,
					     LOAD_MUST_SUCCEED);

			size = sizeof(struct ip6t_entry_target)
				+ target->size;
			target->t = fw_calloc(1, size);
			target->t->u.target_size = size;
			strcpy(target->t->u.user.name, jumpto);
			if (target->init != NULL)
				target->init(target->t);
		}

		if (!target) {
			/* it is no chain, and we can't load a plugin.
			 * We cannot know if the plugin is corrupt, non
			 * existant OR if the user just misspelled a
			 * chain. */
			find_target(jumpto, LOAD_MUST_SUCCEED);
		} else {
			e = generate_entry(&fw, matches, target->t);
			free(target->t);
		}
	}

	switch (command) {
	case CMD_APPEND:
		ret = append_entry(chain, e,
				   nsaddrs, saddrs, ndaddrs, daddrs,
				   options&OPT_VERBOSE,
				   handle);
		break;
	case CMD_DELETE:
		ret = delete_entry(chain, e,
				   nsaddrs, saddrs, ndaddrs, daddrs,
				   options&OPT_VERBOSE,
				   handle, matches);
		break;
	case CMD_DELETE_NUM:
		ret = ip6tc_delete_num_entry(chain, rulenum - 1, handle);
		break;
	case CMD_REPLACE:
		ret = replace_entry(chain, e, rulenum - 1,
				    saddrs, daddrs, options&OPT_VERBOSE,
				    handle);
		break;
	case CMD_INSERT:
		ret = insert_entry(chain, e, rulenum - 1,
				   nsaddrs, saddrs, ndaddrs, daddrs,
				   options&OPT_VERBOSE,
				   handle);
		break;
	case CMD_LIST:
		ret = list_entries(chain,
				   options&OPT_VERBOSE,
				   options&OPT_NUMERIC,
				   options&OPT_EXPANDED,
				   options&OPT_LINENUMBERS,
				   handle);
		break;
	case CMD_FLUSH:
		ret = flush_entries(chain, options&OPT_VERBOSE, handle);
		break;
	case CMD_ZERO:
		ret = zero_entries(chain, options&OPT_VERBOSE, handle);
		break;
	case CMD_LIST|CMD_ZERO:
		ret = list_entries(chain,
				   options&OPT_VERBOSE,
				   options&OPT_NUMERIC,
				   options&OPT_EXPANDED,
				   options&OPT_LINENUMBERS,
				   handle);
		if (ret)
			ret = zero_entries(chain,
					   options&OPT_VERBOSE, handle);
		break;
	case CMD_NEW_CHAIN:
		ret = ip6tc_create_chain(chain, handle);
		break;
	case CMD_DELETE_CHAIN:
		ret = delete_chain(chain, options&OPT_VERBOSE, handle);
		break;
	case CMD_RENAME_CHAIN:
		ret = ip6tc_rename_chain(chain, newname,	handle);
		break;
	case CMD_SET_POLICY:
		ret = ip6tc_set_policy(chain, policy, NULL, handle);
		break;
	default:
		/* We should never reach this... */
		exit_tryhelp(2);
	}

	if (verbose > 1)
		dump_entries6(*handle);

	clear_rule_matches(&matches);

	if (e != NULL) {
		free(e);
		e = NULL;
	}

	for (i = 0; i < nsaddrs; i++)
		free(&saddrs[i]);

	for (i = 0; i < ndaddrs; i++)
		free(&daddrs[i]);

	free_opts(1);

	return ret;
}
