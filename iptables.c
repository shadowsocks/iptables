/* Code to take an iptables-style command line and do it. */

/*
 * Author: Paul.Russell@rustcorp.com.au and mneuling@radlogic.com.au
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
#include <dlfcn.h>
#include <ctype.h>
#include <stdarg.h>
#include <limits.h>
#include <iptables.h>

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#ifndef IPT_LIB_DIR
#define IPT_LIB_DIR "/usr/local/lib/iptables"
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
#define CMD_CHECK		0x0800U
#define CMD_RENAME_CHAIN	0x1000U
#define NUMBER_OF_CMD	13
static const char cmdflags[] = { 'I', 'D', 'D', 'R', 'A', 'L', 'F', 'Z',
				 'N', 'X', 'P', 'C', 'E' };

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
#define OPT_FRAGMENT    0x00200U
#define OPT_LINENUMBERS 0x00400U
#define NUMBER_OF_OPT	11
static const char optflags[NUMBER_OF_OPT]
= { 'n', 's', 'd', 'p', 'j', 'v', 'x', 'i', 'o', 'f', '3'};

static struct option original_opts[] = {
	{ "append", 1, 0, 'A' },
	{ "delete", 1, 0,  'D' },
	{ "insert", 1, 0,  'I' },
	{ "replace", 1, 0,  'R' },
	{ "list", 2, 0,  'L' },
	{ "flush", 2, 0,  'F' },
	{ "zero", 2, 0,  'Z' },
	{ "check", 1, 0,  'C' },
	{ "new-chain", 1, 0,  'N' },
	{ "delete-chain", 2, 0,  'X' },
	{ "rename-chain", 2, 0,  'E' },
	{ "policy", 1, 0,  'P' },
	{ "source", 1, 0, 's' },
	{ "destination", 1, 0,  'd' },
	{ "src", 1, 0,  's' }, /* synonym */
	{ "dst", 1, 0,  'd' }, /* synonym */
	{ "protocol", 1, 0,  'p' },
	{ "in-interface", 1, 0, 'i' },
	{ "jump", 1, 0, 'j' },
	{ "table", 1, 0, 't' },
	{ "match", 1, 0, 'm' },
	{ "numeric", 0, 0, 'n' },
	{ "out-interface", 1, 0, 'o' },
	{ "verbose", 0, 0, 'v' },
	{ "exact", 0, 0, 'x' },
	{ "fragments", 0, 0, 'f' },
	{ "version", 0, 0, 'V' },
	{ "help", 2, 0, 'h' },
	{ "line-numbers", 0, 0, '0' },
	{ 0 }
};

#if 0
static struct ipt_entry_target *
ipt_get_target(struct ipt_entry *e)
{
	return (void *)e + e->target_offset;
}
#endif

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
	/*     -n  -s  -d  -p  -j  -v  -x  -i  -o  -f  --line */
/*INSERT*/    {'x',' ',' ',' ',' ',' ','x',' ',' ',' ','x'},
/*DELETE*/    {'x',' ',' ',' ',' ',' ','x',' ',' ',' ','x'},
/*DELETE_NUM*/{'x','x','x','x','x',' ','x','x','x','x','x'},
/*REPLACE*/   {'x',' ',' ',' ',' ',' ','x',' ',' ',' ','x'},
/*APPEND*/    {'x',' ',' ',' ',' ',' ','x',' ',' ',' ','x'},
/*LIST*/      {' ','x','x','x','x',' ',' ','x','x','x',' '},
/*FLUSH*/     {'x','x','x','x','x',' ','x','x','x','x','x'},
/*ZERO*/      {'x','x','x','x','x',' ','x','x','x','x','x'},
/*NEW_CHAIN*/ {'x','x','x','x','x',' ','x','x','x','x','x'},
/*DEL_CHAIN*/ {'x','x','x','x','x',' ','x','x','x','x','x'},
/*SET_POLICY*/{'x','x','x','x','x',' ','x','x','x','x','x'},
/*CHECK*/     {'x','+','+','+','x',' ','x','+','+',' ','x'},
/*RENAME*/    {'x','x','x','x','x',' ','x','x','x','x','x'}
};

static int inverse_for_options[NUMBER_OF_OPT] =
{
/* -n */ 0,
/* -s */ IPT_INV_SRCIP,
/* -d */ IPT_INV_DSTIP,
/* -p */ IPT_INV_PROTO,
/* -j */ 0,
/* -v */ 0,
/* -x */ 0,
/* -i */ IPT_INV_VIA_IN,
/* -o */ IPT_INV_VIA_OUT,
/* -f */ IPT_INV_FRAG,
/*--line*/ 0
};

const char *program_version;
const char *program_name;

/* Keeping track of external matches and targets: linked lists.  */
struct iptables_match *iptables_matches = NULL;
struct iptables_target *iptables_targets = NULL;

/* Extra debugging from libiptc */
extern void dump_entries(const iptc_handle_t handle);

/* A few hardcoded protocols for 'all' and in case the user has no
   /etc/protocols */
struct pprot {
	char *name;
	u_int8_t num;
};

static const struct pprot chain_protos[] = {
	{ "tcp", IPPROTO_TCP },
	{ "udp", IPPROTO_UDP },
	{ "icmp", IPPROTO_ICMP },
	{ "all", 0 },
};

static char *
proto_to_name(u_int8_t proto)
{
	unsigned int i;

	if (proto) {
		struct protoent *pent = getprotobynumber(proto);
		if (pent)
			return pent->p_name;
	}

	for (i = 0; i < sizeof(chain_protos)/sizeof(struct pprot); i++)
		if (chain_protos[i].num == proto)
			return chain_protos[i].name;

	return NULL;
}

struct in_addr *
dotted_to_addr(const char *dotted)
{
	static struct in_addr addr;
	unsigned char *addrp;
	char *p, *q;
	int onebyte, i;
	char buf[20];

	/* copy dotted string, because we need to modify it */
	strncpy(buf, dotted, sizeof(buf) - 1);
	addrp = (unsigned char *) &(addr.s_addr);

	p = buf;
	for (i = 0; i < 3; i++) {
		if ((q = strchr(p, '.')) == NULL)
			return (struct in_addr *) NULL;

		*q = '\0';
		if ((onebyte = string_to_number(p, 0, 255)) == -1)
			return (struct in_addr *) NULL;

		addrp[i] = (unsigned char) onebyte;
		p = q + 1;
	}

	/* we've checked 3 bytes, now we check the last one */
	if ((onebyte = string_to_number(p, 0, 255)) == -1)
		return (struct in_addr *) NULL;

	addrp[3] = (unsigned char) onebyte;

	return &addr;
}

static struct in_addr *
network_to_addr(const char *name)
{
	struct netent *net;
	static struct in_addr addr;

	if ((net = getnetbyname(name)) != NULL) {
		if (net->n_addrtype != AF_INET)
			return (struct in_addr *) NULL;
		addr.s_addr = htonl((unsigned long) net->n_net);
		return &addr;
	}

	return (struct in_addr *) NULL;
}

static void
inaddrcpy(struct in_addr *dst, struct in_addr *src)
{
	/* memcpy(dst, src, sizeof(struct in_addr)); */
	dst->s_addr = src->s_addr;
}

void
exit_error(enum exittype status, char *msg, ...)
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
			"Perhaps iptables or your kernel needs to be upgraded.\n");
	exit(status);
}

void
exit_tryhelp(int status)
{
	fprintf(stderr, "Try `%s -h' or '%s --help' for more information.\n",
			program_name, program_name );
	exit(status);
}

void
exit_printhelp(void)
{
	struct iptables_match *m = NULL;
	struct iptables_target *t = NULL;

	printf("%s v%s\n\n"
"Usage: %s -[ADC] chain rule-specification [options]\n"
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
"  --check   -C chain		Test this packet on chain\n"
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
"				target for rule\n"
"  --numeric	-n		numeric output of addresses and ports\n"
"  --out-interface -o [!] output name[+]\n"
"				network interface name ([+] for wildcard)\n"
"  --table	-t table	table to manipulate (default: `filter')\n"
"  --verbose	-v		verbose mode\n"
"  --exact	-x		expand numbers (display exact values)\n"
"[!] --fragment	-f		match second or further fragments only\n"
"[!] --version	-V		print package version.\n");

	/* Print out any special helps. A user might like to be able to add a --help 
	   to the commandline, and see expected results. So we call help for all 
	   matches & targets */
	for (t=iptables_targets;t;t=t->next) {
		printf("\n");
		t->help();
	}
	for (m=iptables_matches;m;m=m->next) {
		printf("\n");
		m->help();
	}
	exit(0);
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
add_command(int *cmd, const int newcmd, const int othercmds, int invert)
{
	if (invert)
		exit_error(PARAMETER_PROBLEM, "unexpected ! flag");
	if (*cmd & (~othercmds))
		exit_error(PARAMETER_PROBLEM, "Can't use -%c with -%c\n",
			   cmd2char(newcmd), cmd2char(*cmd & (~othercmds)));
	*cmd |= newcmd;
}

int
check_inverse(const char option[], int *invert)
{
	if (option && strcmp(option, "!") == 0) {
		if (*invert)
			exit_error(PARAMETER_PROBLEM,
				   "Multiple `!' flags not allowed");

		*invert = TRUE;
		return TRUE;
	}
	return FALSE;
}

static void *
fw_calloc(size_t count, size_t size)
{
	void *p;

	if ((p = calloc(count, size)) == NULL) {
		perror("iptables: calloc failed");
		exit(1);
	}
	return p;
}

static void *
fw_malloc(size_t size)
{
	void *p;

	if ((p = malloc(size)) == NULL) {
		perror("iptables: malloc failed");
		exit(1);
	}
	return p;
}

static struct in_addr *
host_to_addr(const char *name, unsigned int *naddr)
{
	struct hostent *host;
	struct in_addr *addr;
	unsigned int i;

	*naddr = 0;
	if ((host = gethostbyname(name)) != NULL) {
		if (host->h_addrtype != AF_INET ||
		    host->h_length != sizeof(struct in_addr))
			return (struct in_addr *) NULL;

		while (host->h_addr_list[*naddr] != (char *) NULL)
			(*naddr)++;
		addr = fw_calloc(*naddr, sizeof(struct in_addr));
		for (i = 0; i < *naddr; i++)
			inaddrcpy(&(addr[i]),
				  (struct in_addr *) host->h_addr_list[i]);
		return addr;
	}

	return (struct in_addr *) NULL;
}

static char *
addr_to_host(const struct in_addr *addr)
{
	struct hostent *host;

	if ((host = gethostbyaddr((char *) addr,
				  sizeof(struct in_addr), AF_INET)) != NULL)
		return (char *) host->h_name;

	return (char *) NULL;
}

/*
 *	All functions starting with "parse" should succeed, otherwise
 *	the program fails.
 *	Most routines return pointers to static data that may change
 *	between calls to the same or other routines with a few exceptions:
 *	"host_to_addr", "parse_hostnetwork", and "parse_hostnetworkmask"
 *	return global static data.
*/

static struct in_addr *
parse_hostnetwork(const char *name, unsigned int *naddrs)
{
	struct in_addr *addrp, *addrptmp;

	if ((addrptmp = dotted_to_addr(name)) != NULL ||
	    (addrptmp = network_to_addr(name)) != NULL) {
		addrp = fw_malloc(sizeof(struct in_addr));
		inaddrcpy(addrp, addrptmp);
		*naddrs = 1;
		return addrp;
	}
	if ((addrp = host_to_addr(name, naddrs)) != NULL)
		return addrp;

	exit_error(PARAMETER_PROBLEM, "host/network `%s' not found", name);
}

static struct in_addr *
parse_mask(char *mask)
{
	static struct in_addr maskaddr;
	struct in_addr *addrp;
	int bits;

	if (mask == NULL) {
		/* no mask at all defaults to 32 bits */
		maskaddr.s_addr = 0xFFFFFFFF;
		return &maskaddr;
	}
	if ((addrp = dotted_to_addr(mask)) != NULL)
		/* dotted_to_addr already returns a network byte order addr */
		return addrp;
	if ((bits = string_to_number(mask, 0, 32)) == -1)
		exit_error(PARAMETER_PROBLEM,
			   "invalid mask `%s' specified", mask);
	if (bits != 0) {
		maskaddr.s_addr = htonl(0xFFFFFFFF << (32 - bits));
		return &maskaddr;
	}

	maskaddr.s_addr = 0L;
	return &maskaddr;
}

static void
parse_hostnetworkmask(const char *name, struct in_addr **addrpp,
		      struct in_addr *maskp, unsigned int *naddrs)
{
	struct in_addr *addrp;
	char buf[256];
	char *p;
	int i, j, k, n;

	strncpy(buf, name, sizeof(buf) - 1);
	if ((p = strrchr(buf, '/')) != NULL) {
		*p = '\0';
		addrp = parse_mask(p + 1);
	} else
		addrp = parse_mask(NULL);
	inaddrcpy(maskp, addrp);

	/* if a null mask is given, the name is ignored, like in "any/0" */
	if (maskp->s_addr == 0L)
		strcpy(buf, "0.0.0.0");

	addrp = *addrpp = parse_hostnetwork(buf, naddrs);
	n = *naddrs;
	for (i = 0, j = 0; i < n; i++) {
		addrp[j++].s_addr &= maskp->s_addr;
		for (k = 0; k < j - 1; k++) {
			if (addrp[k].s_addr == addrp[j - 1].s_addr) {
				(*naddrs)--;
				j--;
				break;
			}
		}
	}
}

struct iptables_match *
find_match(const char *name, int tryload)
{
	struct iptables_match *ptr;

	for (ptr = iptables_matches; ptr; ptr = ptr->next) {
		if (strcmp(name, ptr->name) == 0)
			break;
	}

	if (!ptr && tryload) {
		char path[sizeof(IPT_LIB_DIR) + sizeof("/libipt_.so")
			 + strlen(name)];
		sprintf(path, IPT_LIB_DIR "/libipt_%s.so", name);
		if (dlopen(path, RTLD_NOW)) {
			/* Found library.  If it didn't register itself,
			   maybe they specified target as match. */
			ptr = find_match(name, 0);
			if (!ptr)
				exit_error(PARAMETER_PROBLEM,
					   "Couldn't load match `%s'\n",
					   name);
		}
	}

	return ptr;
}

static u_int16_t
parse_protocol(const char *s)
{
	int proto = string_to_number(s, 0, 65535);

	if (proto == -1) {
		struct protoent *pent;

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

static void
parse_interface(const char *arg, char *vianame, unsigned char *mask)
{
	int vialen = strlen(arg);
	unsigned int i;

	memset(mask, 0, IFNAMSIZ);
	memset(vianame, 0, IFNAMSIZ);

	if (vialen + 1 > IFNAMSIZ)
		exit_error(PARAMETER_PROBLEM,
			   "interface name `%s' must be shorter than IFNAMSIZ"
			   " (%i)", arg, IFNAMSIZ-1);

	strcpy(vianame, arg);
	if (vialen == 0)
		memset(mask, 0, IFNAMSIZ);
	else if (vianame[vialen - 1] == '+') {
		memset(mask, 0xFF, vialen - 1);
		memset(mask + vialen - 1, 0, IFNAMSIZ - vialen + 1);
		/* Remove `+' */
		vianame[vialen - 1] = '\0';
	} else {
		/* Include nul-terminator in match */
		memset(mask, 0xFF, vialen + 1);
		memset(mask + vialen + 1, 0, IFNAMSIZ - vialen - 1);
	}
	for (i = 0; vianame[i]; i++) {
		if (!isalnum(vianame[i])) {
			printf("Warning: wierd character in interface"
			       " `%s' (No aliases, :, ! or *).\n",
			       vianame);
			break;
		}
	}
}

/* Can't be zero. */
static int
parse_rulenumber(const char *rule)
{
	int rulenum = string_to_number(rule, 1, INT_MAX);

	if (rulenum == -1)
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

	if (strlen(targetname)+1 > sizeof(ipt_chainlabel))
		exit_error(PARAMETER_PROBLEM,
			   "Invalid target name `%s' (%i chars max)",
			   targetname, sizeof(ipt_chainlabel)-1);

	for (ptr = targetname; *ptr; ptr++)
		if (isspace(*ptr))
			exit_error(PARAMETER_PROBLEM,
				   "Invalid target name `%s'", targetname);
	return targetname;
}

static char *
addr_to_network(const struct in_addr *addr)
{
	struct netent *net;

	if ((net = getnetbyaddr((long) ntohl(addr->s_addr), AF_INET)) != NULL)
		return (char *) net->n_name;

	return (char *) NULL;
}

char *
addr_to_dotted(const struct in_addr *addrp)
{
	static char buf[20];
	const unsigned char *bytep;

	bytep = (const unsigned char *) &(addrp->s_addr);
	sprintf(buf, "%d.%d.%d.%d", bytep[0], bytep[1], bytep[2], bytep[3]);
	return buf;
}
static char *
addr_to_anyname(const struct in_addr *addr)
{
	char *name;

	if ((name = addr_to_host(addr)) != NULL ||
	    (name = addr_to_network(addr)) != NULL)
		return name;

	return addr_to_dotted(addr);
}

static char *
mask_to_dotted(const struct in_addr *mask)
{
	int i;
	static char buf[20];
	u_int32_t maskaddr, bits;

	maskaddr = ntohl(mask->s_addr);

	if (maskaddr == 0xFFFFFFFFL)
		/* we don't want to see "/32" */
		return "";

	i = 32;
	bits = 0xFFFFFFFEL;
	while (--i >= 0 && maskaddr != bits)
		bits <<= 1;
	if (i >= 0)
		sprintf(buf, "/%d", i);
	else
		/* mask was not a decent combination of 1's and 0's */
		sprintf(buf, "/%s", addr_to_dotted(mask));

	return buf;
}

int
string_to_number(const char *s, int min, int max)
{
	int number;
	char *end;

	/* Handle hex, octal, etc. */
	number = (int)strtol(s, &end, 0);
	if (*end == '\0' && end != s) {
		/* we parsed a number, let's see if we want this */
		if (min <= number && number <= max)
			return number;
	}
	return -1;
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

struct iptables_target *
find_target(const char *name, int tryload)
{
	struct iptables_target *ptr;

	/* Standard target? */
	if (strcmp(name, "") == 0
	    || strcmp(name, IPTC_LABEL_ACCEPT) == 0
	    || strcmp(name, IPTC_LABEL_DROP) == 0
	    || strcmp(name, IPTC_LABEL_QUEUE) == 0
	    || strcmp(name, IPTC_LABEL_RETURN) == 0)
		name = "standard";

	for (ptr = iptables_targets; ptr; ptr = ptr->next) {
		if (strcmp(name, ptr->name) == 0)
			break;
	}

	if (!ptr && tryload) {
		char path[sizeof(IPT_LIB_DIR) + sizeof("/libipt_.so")
			 + strlen(name)];
		sprintf(path, IPT_LIB_DIR "/libipt_%s.so", name);
		if (dlopen(path, RTLD_NOW)) {
			/* Found library.  If it didn't register itself,
			   maybe they specified match as a target. */
			ptr = find_target(name, 0);
			if (!ptr)
				exit_error(PARAMETER_PROBLEM,
					   "Couldn't load target `%s'\n",
					   name);
		}
	}

	return ptr;
}

static struct option *
merge_options(struct option *oldopts, struct option *newopts,
	      unsigned int *option_offset)
{
	unsigned int num_old, num_new, i;
	struct option *merge;

	for (num_old = 0; oldopts[num_old].name; num_old++);
	for (num_new = 0; newopts[num_new].name; num_new++);

	global_option_offset += OPTION_OFFSET;
	*option_offset = global_option_offset;

	merge = malloc(sizeof(struct option) * (num_new + num_old + 1));
	memcpy(merge, oldopts, num_old * sizeof(struct option));
	for (i = 0; i < num_new; i++) {
		merge[num_old + i] = newopts[i];
		merge[num_old + i].val += *option_offset;
	}
	memset(merge + num_old + num_new, 0, sizeof(struct option));

	return merge;
}

void
register_match(struct iptables_match *me)
{
	if (strcmp(me->version, program_version) != 0) {
		fprintf(stderr, "%s: match `%s' v%s (I'm v%s).\n",
			program_name, me->name, me->version, program_version);
		exit(1);
	}

	if (find_match(me->name, 0)) {
		fprintf(stderr, "%s: match `%s' already registered.\n",
			program_name, me->name);
		exit(1);
	}

	/* Prepend to list. */
	me->next = iptables_matches;
	iptables_matches = me;
	me->m = NULL;
	me->mflags = 0;

	opts = merge_options(opts, me->extra_opts, &me->option_offset);
}

void
register_target(struct iptables_target *me)
{
	if (strcmp(me->version, program_version) != 0) {
		fprintf(stderr, "%s: target `%s' v%s (I'm v%s).\n",
			program_name, me->name, me->version, program_version);
		exit(1);
	}

	if (find_target(me->name, 0)) {
		fprintf(stderr, "%s: target `%s' already registered.\n",
			program_name, me->name);
		exit(1);
	}

	/* Prepend to list. */
	me->next = iptables_targets;
	iptables_targets = me;
	me->t = NULL;
	me->tflags = 0;

	opts = merge_options(opts, me->extra_opts, &me->option_offset);
}

static void
print_header(unsigned int format, const char *chain, iptc_handle_t *handle)
{
	struct ipt_counters counters;
	const char *pol = iptc_get_policy(chain, &counters, handle);
	printf("Chain %s", chain);
	if (pol) {
		printf(" (policy %s", pol);
		if (!(format & FMT_NOCOUNTS))
			printf(" %llu packets, %llu bytes",
			       counters.pcnt, counters.bcnt);
		printf(")\n");
	} else {
		unsigned int refs;
		if (!iptc_get_references(&refs, chain, handle))
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
					printf(FMT("%4lluG ","%lluG "),number);
				}
				else printf(FMT("%4lluM ","%lluM "), number);
			} else
				printf(FMT("%4lluK ","%lluK "), number);
		} else
			printf(FMT("%5llu ","%llu "), number);
	} else
		printf(FMT("%8llu ","%llu "), number);
}

static int
print_match(const struct ipt_entry_match *m,
	    const struct ipt_ip *ip,
	    int numeric)
{
	struct iptables_match *match = find_match(m->u.name, 1);

	if (match) {
		if (match->print)
			match->print(ip, m, numeric);
	} else {
		if (m->u.name[0])
			printf("UNKNOWN match `%s' ", m->u.name);
	}
	/* Don't stop iterating. */
	return 0;
}

/* e is called `fw' here for hysterical raisins */
static void
print_firewall(const struct ipt_entry *fw,
	       const char *targname,
	       unsigned int num,
	       unsigned int format,
	       const iptc_handle_t handle)
{
	struct iptables_target *target = NULL;
	const struct ipt_entry_target *t;
	u_int8_t flags;
	char buf[BUFSIZ];

	/* User creates a chain called "REJECT": this overrides the
	   `REJECT' target module.  Keep feeding them rope until the
	   revolution... Bwahahahahah */
	if (!iptc_is_chain(targname, handle))
		target = find_target(targname, 1);
	else
		target = find_target(IPT_STANDARD_TARGET, 1);

	t = ipt_get_target((struct ipt_entry *)fw);
	flags = fw->ip.flags;

	if (format & FMT_LINENUMBERS)
		printf(FMT("%-4u ", "%u "), num+1);

	if (!(format & FMT_NOCOUNTS)) {
		print_num(fw->counters.pcnt, format);
		print_num(fw->counters.bcnt, format);
	}

	if (!(format & FMT_NOTARGET))
		printf(FMT("%-9s ", "%s "), targname);

	fputc(fw->ip.invflags & IPT_INV_PROTO ? '!' : ' ', stdout);
	{
		char *pname = proto_to_name(fw->ip.proto);
		if (pname)
			printf(FMT("%-5s", "%s "), pname);
		else
			printf(FMT("%-5hu", "%hu "), fw->ip.proto);
	}

	if (format & FMT_OPTIONS) {
		if (format & FMT_NOTABLE)
			fputs("opt ", stdout);
		fputc(fw->ip.invflags & IPT_INV_FRAG ? '!' : '-', stdout);
		fputc(flags & IPT_F_FRAG ? 'f' : '-', stdout);
		fputc(' ', stdout);
	}

	if (format & FMT_VIA) {
		char iface[IFNAMSIZ+2];

		if (fw->ip.invflags & IPT_INV_VIA_IN) {
			iface[0] = '!';
			iface[1] = '\0';
		}
		else iface[0] = '\0';

		if (fw->ip.iniface[0] != '\0') {
			strcat(iface, fw->ip.iniface);
			/* If it doesn't compare the nul-term, it's a
			   wildcard. */
			if (fw->ip.iniface_mask[strlen(fw->ip.iniface)] == 0)
				strcat(iface, "+");
		}
		else if (format & FMT_NUMERIC) strcat(iface, "*");
		else strcat(iface, "any");
		printf(FMT(" %-6s ","in %s "), iface);

		if (fw->ip.invflags & IPT_INV_VIA_OUT) {
			iface[0] = '!';
			iface[1] = '\0';
		}
		else iface[0] = '\0';

		if (fw->ip.outiface[0] != '\0') {
			strcat(iface, fw->ip.outiface);
			/* If it doesn't compare the nul-term, it's a
			   wildcard. */
			if (fw->ip.outiface_mask[strlen(fw->ip.outiface)] == 0)
				strcat(iface, "+");
		}
		else if (format & FMT_NUMERIC) strcat(iface, "*");
		else strcat(iface, "any");
		printf(FMT("%-6s ","out %s "), iface);
	}

	fputc(fw->ip.invflags & IPT_INV_SRCIP ? '!' : ' ', stdout);
	if (fw->ip.smsk.s_addr == 0L && !(format & FMT_NUMERIC))
		printf(FMT("%-19s ","%s "), "anywhere");
	else {
		if (format & FMT_NUMERIC)
			sprintf(buf, "%s", addr_to_dotted(&(fw->ip.src)));
		else
			sprintf(buf, "%s", addr_to_anyname(&(fw->ip.src)));
		strcat(buf, mask_to_dotted(&(fw->ip.smsk)));
		printf(FMT("%-19s ","%s "), buf);
	}

	fputc(fw->ip.invflags & IPT_INV_DSTIP ? '!' : ' ', stdout);
	if (fw->ip.dmsk.s_addr == 0L && !(format & FMT_NUMERIC))
		printf(FMT("%-19s","-> %s"), "anywhere");
	else {
		if (format & FMT_NUMERIC)
			sprintf(buf, "%s", addr_to_dotted(&(fw->ip.dst)));
		else
			sprintf(buf, "%s", addr_to_anyname(&(fw->ip.dst)));
		strcat(buf, mask_to_dotted(&(fw->ip.dmsk)));
		printf(FMT("%-19s","-> %s"), buf);
	}

	if (format & FMT_NOTABLE)
		fputs("  ", stdout);

	IPT_MATCH_ITERATE(fw, print_match, &fw->ip, format & FMT_NUMERIC);

	if (target) {
		if (target->print)
			/* Print the target information. */
			target->print(&fw->ip, t, format & FMT_NUMERIC);
	} else if (t->target_size != sizeof(*t))
		printf("[%u bytes of unknown target data] ",
		       t->target_size - sizeof(*t));

	if (!(format & FMT_NONEWLINE))
		fputc('\n', stdout);
}

static void
print_firewall_line(const struct ipt_entry *fw,
		    const iptc_handle_t h)
{
	struct ipt_entry_target *t;

	t = ipt_get_target((struct ipt_entry *)fw);
	print_firewall(fw, t->u.name, 0, FMT_PRINT_RULE, h);
}

static int
append_entry(const ipt_chainlabel chain,
	     struct ipt_entry *fw,
	     unsigned int nsaddrs,
	     const struct in_addr saddrs[],
	     unsigned int ndaddrs,
	     const struct in_addr daddrs[],
	     int verbose,
	     iptc_handle_t *handle)
{
	unsigned int i, j;
	int ret = 1;

	for (i = 0; i < nsaddrs; i++) {
		fw->ip.src.s_addr = saddrs[i].s_addr;
		for (j = 0; j < ndaddrs; j++) {
			fw->ip.dst.s_addr = daddrs[j].s_addr;
			if (verbose)
				print_firewall_line(fw, *handle);
			ret &= iptc_append_entry(chain, fw, handle);
		}
	}

	return ret;
}

static int
replace_entry(const ipt_chainlabel chain,
	      struct ipt_entry *fw,
	      unsigned int rulenum,
	      const struct in_addr *saddr,
	      const struct in_addr *daddr,
	      int verbose,
	      iptc_handle_t *handle)
{
	fw->ip.src.s_addr = saddr->s_addr;
	fw->ip.dst.s_addr = daddr->s_addr;

	if (verbose)
		print_firewall_line(fw, *handle);
	return iptc_replace_entry(chain, fw, rulenum, handle);
}

static int
insert_entry(const ipt_chainlabel chain,
	     struct ipt_entry *fw,
	     unsigned int rulenum,
	     unsigned int nsaddrs,
	     const struct in_addr saddrs[],
	     unsigned int ndaddrs,
	     const struct in_addr daddrs[],
	     int verbose,
	     iptc_handle_t *handle)
{
	unsigned int i, j;
	int ret = 1;

	for (i = 0; i < nsaddrs; i++) {
		fw->ip.src.s_addr = saddrs[i].s_addr;
		for (j = 0; j < ndaddrs; j++) {
			fw->ip.dst.s_addr = daddrs[j].s_addr;
			if (verbose)
				print_firewall_line(fw, *handle);
			ret &= iptc_insert_entry(chain, fw, rulenum, handle);
		}
	}

	return ret;
}

static unsigned char *
make_delete_mask(struct ipt_entry *fw)
{
	/* Establish mask for comparison */
	unsigned int size;
	struct iptables_match *m;
	unsigned char *mask, *mptr;

	size = sizeof(struct ipt_entry);
	for (m = iptables_matches; m; m = m->next)
		size += sizeof(struct ipt_entry_match) + m->size;

	mask = fw_calloc(1, size
			 + sizeof(struct ipt_entry_target)
			 + iptables_targets->size);

	memset(mask, 0xFF, sizeof(struct ipt_entry));
	mptr = mask + sizeof(struct ipt_entry);

	for (m = iptables_matches; m; m = m->next) {
		memset(mptr, 0xFF,
		       sizeof(struct ipt_entry_match) + m->userspacesize);
		mptr += sizeof(struct ipt_entry_match) + m->size;
	}

	memset(mptr, 0xFF, sizeof(struct ipt_entry_target));
	mptr += sizeof(struct ipt_entry_target);
	memset(mptr, 0xFF, iptables_targets->userspacesize);

	return mask;
}

static int
delete_entry(const ipt_chainlabel chain,
	     struct ipt_entry *fw,
	     unsigned int nsaddrs,
	     const struct in_addr saddrs[],
	     unsigned int ndaddrs,
	     const struct in_addr daddrs[],
	     int verbose,
	     iptc_handle_t *handle)
{
	unsigned int i, j;
	int ret = 1;
	unsigned char *mask;

	mask = make_delete_mask(fw);
	for (i = 0; i < nsaddrs; i++) {
		fw->ip.src.s_addr = saddrs[i].s_addr;
		for (j = 0; j < ndaddrs; j++) {
			fw->ip.dst.s_addr = daddrs[j].s_addr;
			if (verbose)
				print_firewall_line(fw, *handle);
			ret &= iptc_delete_entry(chain, fw, mask, handle);
		}
	}
	return ret;
}

static int
check_packet(const ipt_chainlabel chain,
	     struct ipt_entry *fw,
	     unsigned int nsaddrs,
	     const struct in_addr saddrs[],
	     unsigned int ndaddrs,
	     const struct in_addr daddrs[],
	     int verbose,
	     iptc_handle_t *handle)
{
	int ret = 1;
	unsigned int i, j;
	const char *msg;

	for (i = 0; i < nsaddrs; i++) {
		fw->ip.src.s_addr = saddrs[i].s_addr;
		for (j = 0; j < ndaddrs; j++) {
			fw->ip.dst.s_addr = daddrs[j].s_addr;
			if (verbose)
				print_firewall_line(fw, *handle);
			msg = iptc_check_packet(chain, fw, handle);
			if (!msg) ret = 0;
			else printf("%s\n", msg);
		}
	}

	return ret;
}

static int
for_each_chain(int (*fn)(const ipt_chainlabel, int, iptc_handle_t *),
	       int verbose, int builtinstoo, iptc_handle_t *handle)
{
        int ret = 1;
	const char *chain;
	char *chains;
	unsigned int i, chaincount = 0;

	chain = iptc_first_chain(handle);
	while (chain) {
		chaincount++;
		chain = iptc_next_chain(handle);
        }

	chains = fw_malloc(sizeof(ipt_chainlabel) * chaincount);
	i = 0;
	chain = iptc_first_chain(handle);
	while (chain) {
		strcpy(chains + i*sizeof(ipt_chainlabel), chain);
		i++;
		chain = iptc_next_chain(handle);
        }

	for (i = 0; i < chaincount; i++) {
		if (!builtinstoo
		    && iptc_builtin(chains + i*sizeof(ipt_chainlabel),
				    *handle))
			continue;
	        ret &= fn(chains + i*sizeof(ipt_chainlabel), verbose, handle);
	}

	free(chains);
        return ret;
}

static int
flush_entries(const ipt_chainlabel chain, int verbose,
	      iptc_handle_t *handle)
{
	if (!chain)
		return for_each_chain(flush_entries, verbose, 1, handle);

	if (verbose)
		fprintf(stdout, "Flushing chain `%s'\n", chain);
	return iptc_flush_entries(chain, handle);
}

static int
zero_entries(const ipt_chainlabel chain, int verbose,
	     iptc_handle_t *handle)
{
	if (!chain)
		return for_each_chain(zero_entries, verbose, 1, handle);

	if (verbose)
		fprintf(stdout, "Zeroing chain `%s'\n", chain);
	return iptc_zero_entries(chain, handle);
}

static int
delete_chain(const ipt_chainlabel chain, int verbose,
	     iptc_handle_t *handle)
{
	if (!chain)
		return for_each_chain(delete_chain, verbose, 0, handle);

	if (verbose)
	        fprintf(stdout, "Deleting chain `%s'\n", chain);
	return iptc_delete_chain(chain, handle);
}

static int
list_entries(const ipt_chainlabel chain, int verbose, int numeric,
	     int expanded, int linenumbers, iptc_handle_t *handle)
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

	for (this = iptc_first_chain(handle);
	     this;
	     this = iptc_next_chain(handle)) {
		const struct ipt_entry *i;
		unsigned int num;

		if (chain && strcmp(chain, this) != 0)
			continue;

		if (found) printf("\n");

		print_header(format, this, handle);
		i = iptc_first_rule(this, handle);

		num = 0;
		while (i) {
			print_firewall(i,
				       iptc_get_target(i, handle),
				       num++,
				       format,
				       *handle);
			i = iptc_next_rule(i, handle);
		}
		found = 1;
	}

	errno = ENOENT;
	return found;
}

static struct ipt_entry *
generate_entry(const struct ipt_entry *fw,
	       struct iptables_match *matches,
	       struct ipt_entry_target *target)
{
	unsigned int size;
	struct iptables_match *m;
	struct ipt_entry *e;

	size = sizeof(struct ipt_entry);
	for (m = matches; m; m = m->next)
		size += m->m->match_size;

	e = fw_malloc(size + target->target_size);
	*e = *fw;
	e->target_offset = size;
	e->next_offset = size + target->target_size;

	size = 0;
	for (m = matches; m; m = m->next) {
		memcpy(e->elems + size, m->m, m->m->match_size);
		size += m->m->match_size;
	}
	memcpy(e->elems + size, target, target->target_size);

	return e;
}

int do_command(int argc, char *argv[], char **table, iptc_handle_t *handle)
{
	struct ipt_entry fw, *e = NULL;
	int invert = 0;
	unsigned int nsaddrs = 0, ndaddrs = 0;
	struct in_addr *saddrs = NULL, *daddrs = NULL;

	int c, verbose = 0;
	const char *chain = NULL;
	const char *shostnetworkmask = NULL, *dhostnetworkmask = NULL;
	const char *policy = NULL, *newname = NULL;
	unsigned int rulenum = 0, options = 0, command = 0;
	int ret = 1;
	struct iptables_match *m;
	struct iptables_target *target = NULL;
	const char *jumpto = "";
	char *protocol = NULL;

	memset(&fw, 0, sizeof(fw));

	/* Suppress error messages: we may add new options if we
           demand-load a protocol. */
	opterr = 0;

	while ((c = getopt_long(argc, argv,
	   "-A:C:D:R:I:L::F::Z::N:X::E:P:Vh::o:p:s:d:j:i:fbvnt:m:x",
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

		case 'C':
			add_command(&command, CMD_CHECK, CMD_NONE,
				    invert);
			chain = optarg;
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

			/* iptables -p icmp -h */
			if (!iptables_matches && protocol)
			    find_match(protocol, 1);

			exit_printhelp();

			/*
			 * Option selection
			 */
		case 'p':
			if (check_inverse(optarg, &invert))
				optind++;
			set_option(&options, OPT_PROTOCOL, &fw.ip.invflags,
				   invert);

			/* Canonicalize into lower case */
			for (protocol = argv[optind-1]; *protocol; protocol++)
				*protocol = tolower(*protocol);

			protocol = argv[optind-1];
			fw.ip.proto = parse_protocol(protocol);

			if (fw.ip.proto == 0
			    && (fw.ip.invflags & IPT_INV_PROTO))
				exit_error(PARAMETER_PROBLEM,
					   "rule would never match protocol");
			fw.nfcache |= NFC_IP_PROTO;
			break;

		case 's':
			if (check_inverse(optarg, &invert))
				optind++;
			set_option(&options, OPT_SOURCE, &fw.ip.invflags,
				   invert);
			shostnetworkmask = argv[optind-1];
			fw.nfcache |= NFC_IP_SRC;
			break;

		case 'd':
			if (check_inverse(optarg, &invert))
				optind++;
			set_option(&options, OPT_DESTINATION, &fw.ip.invflags,
				   invert);
			dhostnetworkmask = argv[optind-1];
			fw.nfcache |= NFC_IP_DST;
			break;

		case 'j':
			set_option(&options, OPT_JUMP, &fw.ip.invflags,
				   invert);
			jumpto = parse_target(optarg);
			target = find_target(jumpto, 1);

			if (target) {
				size_t size = sizeof(struct ipt_entry_target)
					+ IPT_ALIGN(target->size);

				target->t = fw_calloc(1, size);
				target->t->target_size = size;
				strcpy(target->t->u.name, jumpto);
				target->init(target->t, &fw.nfcache);
			}
			break;


		case 'i':
			if (check_inverse(optarg, &invert))
				optind++;
			set_option(&options, OPT_VIANAMEIN, &fw.ip.invflags,
				   invert);
			parse_interface(argv[optind-1],
					fw.ip.iniface,
					fw.ip.iniface_mask);
			fw.nfcache |= NFC_IP_IF_IN;
			break;

		case 'o':
			if (check_inverse(optarg, &invert))
				optind++;
			set_option(&options, OPT_VIANAMEOUT, &fw.ip.invflags,
				   invert);
			parse_interface(argv[optind-1],
					fw.ip.outiface,
					fw.ip.outiface_mask);
			fw.nfcache |= NFC_IP_IF_OUT;
			break;

		case 'f':
			set_option(&options, OPT_FRAGMENT, &fw.ip.invflags,
				   invert);
			fw.ip.flags |= IPT_F_FRAG;
			fw.nfcache |= NFC_IP_FRAG;
			break;

		case 'v':
			if (!verbose)
				set_option(&options, OPT_VERBOSE,
					   &fw.ip.invflags, invert);
			verbose++;
			break;

		case 'm':
			if (invert)
				exit_error(PARAMETER_PROBLEM,
					   "unexpected ! flag before --match");

			m = find_match(optarg, 1);
			if (!m)
				exit_error(PARAMETER_PROBLEM,
					   "Couldn't load match `%s'", optarg);
			else {
				size_t size = sizeof(struct ipt_entry_match)
					+ IPT_ALIGN(m->size);
				m->m = fw_calloc(1, size);
				m->m->match_size = size;
				strcpy(m->m->u.name, optarg);
				m->init(m->m, &fw.nfcache);
			}
			break;

		case 'n':
			set_option(&options, OPT_NUMERIC, &fw.ip.invflags,
				   invert);
			break;

		case 't':
			if (invert)
				exit_error(PARAMETER_PROBLEM,
					   "unexpected ! flag before --table");
			*table = argv[optind-1];
			break;

		case 'x':
			set_option(&options, OPT_EXPANDED, &fw.ip.invflags,
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
			set_option(&options, OPT_LINENUMBERS, &fw.ip.invflags,
				   invert);
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
			printf("Bad argument `%s'\n", optarg);
			exit_tryhelp(2);

		default:
			/* FIXME: This scheme doesn't allow two of the same
			   matches --RR */
			if (!target
			    || !(target->parse(c - target->option_offset,
					       argv, invert,
					       &target->tflags,
					       &fw, &target->t))) {
				for (m = iptables_matches; m; m = m->next) {
					if (m->parse(c - m->option_offset,
						     argv, invert,
						     &m->mflags,
						     &fw,
						     &fw.nfcache,
						     &m->m))
						break;
				}

				/* If you listen carefully, you can
				   acually hear this code suck. */
				if (m == NULL
				    && protocol
				    && !find_match(protocol, 0)
				    && (m = find_match(protocol, 1))) {
					/* Try loading protocol */
					size_t size = sizeof(struct ipt_entry_match)
						+ IPT_ALIGN(m->size);

					m->m = fw_calloc(1, size);
					m->m->match_size = size;
					strcpy(m->m->u.name, protocol);
					m->init(m->m, &fw.nfcache);

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

	for (m = iptables_matches; m; m = m->next)
		m->final_check(m->mflags);
	if (target)
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

	if (command & (CMD_REPLACE | CMD_INSERT | CMD_DELETE | CMD_APPEND |
	    CMD_CHECK)) {
		if (!(options & OPT_DESTINATION))
			dhostnetworkmask = "0.0.0.0/0";
		if (!(options & OPT_SOURCE))
			shostnetworkmask = "0.0.0.0/0";
	}

	if (shostnetworkmask)
		parse_hostnetworkmask(shostnetworkmask, &saddrs,
				      &(fw.ip.smsk), &nsaddrs);

	if (dhostnetworkmask)
		parse_hostnetworkmask(dhostnetworkmask, &daddrs,
				      &(fw.ip.dmsk), &ndaddrs);

	if ((nsaddrs > 1 || ndaddrs > 1) &&
	    (fw.ip.invflags & (IPT_INV_SRCIP | IPT_INV_DSTIP)))
		exit_error(PARAMETER_PROBLEM, "! not allowed with multiple"
			   " source or destination IP addresses");

	if (command == CMD_CHECK && fw.ip.invflags != 0)
		exit_error(PARAMETER_PROBLEM, "! not allowed with -%c",
			   cmd2char(CMD_CHECK));

	if (command == CMD_REPLACE && (nsaddrs != 1 || ndaddrs != 1))
		exit_error(PARAMETER_PROBLEM, "Replacement rule does not "
			   "specify a unique address");

	generic_opt_check(command, options);

	if (chain && strlen(chain) > IPT_FUNCTION_MAXNAMELEN)
		exit_error(PARAMETER_PROBLEM,
			   "chain name `%s' too long (must be under %i chars)",
			   chain, IPT_FUNCTION_MAXNAMELEN);

	*handle = iptc_init(*table);
	if (!*handle)
		exit_error(VERSION_PROBLEM,
			   "can't initialize iptables table `%s': %s",
			   *table, iptc_strerror(errno));

	if (command == CMD_CHECK
	    || command == CMD_APPEND
	    || command == CMD_DELETE
	    || command == CMD_INSERT
	    || command == CMD_REPLACE) {
		/* -o not valid with incoming packets. */
		if (options & OPT_VIANAMEOUT)
			if (strcmp(chain, "PREROUTING") == 0
		    	    || strcmp(chain, "INPUT") == 0) {
				exit_error(PARAMETER_PROBLEM,
					   "Can't use -%c with %s\n",
					   opt2char(OPT_VIANAMEOUT),
					   chain);
		}

		/* -i not valid with outgoing packets */
		if (options & OPT_VIANAMEIN)
			if (strcmp(chain, "POSTROUTING") == 0
			    || strcmp(chain, "OUTPUT") == 0) {
				exit_error(PARAMETER_PROBLEM,
					   "Can't use -%c with %s\n",
					   opt2char(OPT_VIANAMEIN),
					   chain);
		}

		if (target && iptc_is_chain(jumpto, *handle)) {
			printf("Warning: using chain %s, not extension\n",
			       jumpto);

			target = NULL;
		}

		/* If they didn't specify a target, or it's a chain
		   name, use standard. */
		if (!target
		    && (strlen(jumpto) == 0
			|| iptc_is_chain(jumpto, *handle))) {
			size_t size;
			target = find_target(IPT_STANDARD_TARGET, 1);

			if (!target)
				exit_error(OTHER_PROBLEM,
					   "Can't find standard target\n");

			size = sizeof(struct ipt_entry_target)
				+ IPT_ALIGN(target->size);
			target->t = fw_calloc(1, size);
			target->t->target_size = size;
			strcpy(target->t->u.name, jumpto);
			target->init(target->t, &fw.nfcache);
		}

		if (!target) {
			struct ipt_entry_target unknown_target;

			/* Don't know it.  Must be extension with no
                           options? */
			unknown_target.target_size = sizeof(unknown_target);
			strcpy(unknown_target.u.name, jumpto);

			e = generate_entry(&fw, iptables_matches,
					   &unknown_target);
		} else {
			e = generate_entry(&fw, iptables_matches, target->t);
		}
	}

	switch (command) {
	case CMD_APPEND:
		ret = append_entry(chain, e,
				   nsaddrs, saddrs, ndaddrs, daddrs,
				   options&OPT_VERBOSE,
				   handle);
		break;
	case CMD_CHECK:
		ret = check_packet(chain, e,
				   nsaddrs, saddrs, ndaddrs, daddrs,
				   options&OPT_VERBOSE, handle);
		break;
	case CMD_DELETE:
		ret = delete_entry(chain, e,
				   nsaddrs, saddrs, ndaddrs, daddrs,
				   options&OPT_VERBOSE,
				   handle);
		break;
	case CMD_DELETE_NUM:
		ret = iptc_delete_num_entry(chain, rulenum - 1, handle);
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
		ret = iptc_create_chain(chain, handle);
		break;
	case CMD_DELETE_CHAIN:
		ret = delete_chain(chain, options&OPT_VERBOSE, handle);
		break;
	case CMD_RENAME_CHAIN:
		ret = iptc_rename_chain(chain, newname,	handle);
		break;
	case CMD_SET_POLICY:
		ret = iptc_set_policy(chain, policy, handle);
		break;
	default:
		/* We should never reach this... */
		exit_tryhelp(2);
	}

	if (verbose > 1)
		dump_entries(*handle);

	return ret;
}
