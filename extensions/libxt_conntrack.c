/* Shared library add-on to iptables for conntrack matching support.
 * GPL (C) 2001  Marc Boucher (marc@mbsi.ca).
 */

#include <ctype.h>
#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iptables.h>
#include <xtables.h>
#include <linux/netfilter.h>
#include <linux/netfilter/xt_conntrack.h>
#include <linux/netfilter/nf_conntrack_common.h>

/* Function which prints out usage message. */
static void conntrack_mt_help(void)
{
	printf(
"conntrack match options:\n"
"[!] --ctstate {INVALID|ESTABLISHED|NEW|RELATED|UNTRACKED|SNAT|DNAT}[,...]\n"
"                               State(s) to match\n"
"[!] --ctproto proto            Protocol to match; by number or name, e.g. \"tcp\"\n"
"[!] --ctorigsrc address[/mask]\n"
"[!] --ctorigdst address[/mask]\n"
"[!] --ctreplsrc address[/mask]\n"
"[!] --ctrepldst address[/mask]\n"
"                               Original/Reply source/destination address\n"
"[!] --ctstatus {NONE|EXPECTED|SEEN_REPLY|ASSURED|CONFIRMED}[,...]\n"
"                               Status(es) to match\n"
"[!] --ctexpire time[:time]     Match remaining lifetime in seconds against\n"
"                               value or range of values (inclusive)\n"
"\n");
}

static const struct option conntrack_mt_opts[] = {
	{.name = "ctstate",   .has_arg = true, .val = '1'},
	{.name = "ctproto",   .has_arg = true, .val = '2'},
	{.name = "ctorigsrc", .has_arg = true, .val = '3'},
	{.name = "ctorigdst", .has_arg = true, .val = '4'},
	{.name = "ctreplsrc", .has_arg = true, .val = '5'},
	{.name = "ctrepldst", .has_arg = true, .val = '6'},
	{.name = "ctstatus",  .has_arg = true, .val = '7'},
	{.name = "ctexpire",  .has_arg = true, .val = '8'},
	{},
};

static int
parse_state(const char *state, size_t strlen, struct xt_conntrack_info *sinfo)
{
	if (strncasecmp(state, "INVALID", strlen) == 0)
		sinfo->statemask |= XT_CONNTRACK_STATE_INVALID;
	else if (strncasecmp(state, "NEW", strlen) == 0)
		sinfo->statemask |= XT_CONNTRACK_STATE_BIT(IP_CT_NEW);
	else if (strncasecmp(state, "ESTABLISHED", strlen) == 0)
		sinfo->statemask |= XT_CONNTRACK_STATE_BIT(IP_CT_ESTABLISHED);
	else if (strncasecmp(state, "RELATED", strlen) == 0)
		sinfo->statemask |= XT_CONNTRACK_STATE_BIT(IP_CT_RELATED);
	else if (strncasecmp(state, "UNTRACKED", strlen) == 0)
		sinfo->statemask |= XT_CONNTRACK_STATE_UNTRACKED;
	else if (strncasecmp(state, "SNAT", strlen) == 0)
		sinfo->statemask |= XT_CONNTRACK_STATE_SNAT;
	else if (strncasecmp(state, "DNAT", strlen) == 0)
		sinfo->statemask |= XT_CONNTRACK_STATE_DNAT;
	else
		return 0;
	return 1;
}

static void
parse_states(const char *arg, struct xt_conntrack_info *sinfo)
{
	const char *comma;

	while ((comma = strchr(arg, ',')) != NULL) {
		if (comma == arg || !parse_state(arg, comma-arg, sinfo))
			exit_error(PARAMETER_PROBLEM, "Bad ctstate `%s'", arg);
		arg = comma+1;
	}

	if (strlen(arg) == 0 || !parse_state(arg, strlen(arg), sinfo))
		exit_error(PARAMETER_PROBLEM, "Bad ctstate `%s'", arg);
}

static int
parse_status(const char *status, size_t strlen, struct xt_conntrack_info *sinfo)
{
	if (strncasecmp(status, "NONE", strlen) == 0)
		sinfo->statusmask |= 0;
	else if (strncasecmp(status, "EXPECTED", strlen) == 0)
		sinfo->statusmask |= IPS_EXPECTED;
	else if (strncasecmp(status, "SEEN_REPLY", strlen) == 0)
		sinfo->statusmask |= IPS_SEEN_REPLY;
	else if (strncasecmp(status, "ASSURED", strlen) == 0)
		sinfo->statusmask |= IPS_ASSURED;
#ifdef IPS_CONFIRMED
	else if (strncasecmp(status, "CONFIRMED", strlen) == 0)
		sinfo->stausmask |= IPS_CONFIRMED;
#endif
	else
		return 0;
	return 1;
}

static void
parse_statuses(const char *arg, struct xt_conntrack_info *sinfo)
{
	const char *comma;

	while ((comma = strchr(arg, ',')) != NULL) {
		if (comma == arg || !parse_status(arg, comma-arg, sinfo))
			exit_error(PARAMETER_PROBLEM, "Bad ctstatus `%s'", arg);
		arg = comma+1;
	}

	if (strlen(arg) == 0 || !parse_status(arg, strlen(arg), sinfo))
		exit_error(PARAMETER_PROBLEM, "Bad ctstatus `%s'", arg);
}

static unsigned long
parse_expire(const char *s)
{
	unsigned int len;

	if (string_to_number(s, 0, 0, &len) == -1)
		exit_error(PARAMETER_PROBLEM, "expire value invalid: `%s'\n", s);
	else
		return len;
}

/* If a single value is provided, min and max are both set to the value */
static void
parse_expires(const char *s, struct xt_conntrack_info *sinfo)
{
	char *buffer;
	char *cp;

	buffer = strdup(s);
	if ((cp = strchr(buffer, ':')) == NULL)
		sinfo->expires_min = sinfo->expires_max = parse_expire(buffer);
	else {
		*cp = '\0';
		cp++;

		sinfo->expires_min = buffer[0] ? parse_expire(buffer) : 0;
		sinfo->expires_max = cp[0] ? parse_expire(cp) : -1;
	}
	free(buffer);

	if (sinfo->expires_min > sinfo->expires_max)
		exit_error(PARAMETER_PROBLEM,
		           "expire min. range value `%lu' greater than max. "
		           "range value `%lu'", sinfo->expires_min, sinfo->expires_max);
}

/* Function which parses command options; returns true if it
   ate an option */
static int conntrack_parse(int c, char **argv, int invert, unsigned int *flags,
                           const void *entry, struct xt_entry_match **match)
{
	struct xt_conntrack_info *sinfo = (void *)(*match)->data;
	char *protocol = NULL;
	unsigned int naddrs = 0;
	struct in_addr *addrs = NULL;


	switch (c) {
	case '1':
		check_inverse(optarg, &invert, &optind, 0);

		parse_states(argv[optind-1], sinfo);
		if (invert) {
			sinfo->invflags |= XT_CONNTRACK_STATE;
		}
		sinfo->flags |= XT_CONNTRACK_STATE;
		break;

	case '2':
		check_inverse(optarg, &invert, &optind, 0);

		if(invert)
			sinfo->invflags |= XT_CONNTRACK_PROTO;

		/* Canonicalize into lower case */
		for (protocol = argv[optind-1]; *protocol; protocol++)
			*protocol = tolower(*protocol);

		protocol = argv[optind-1];
		sinfo->tuple[IP_CT_DIR_ORIGINAL].dst.protonum = parse_protocol(protocol);

		if (sinfo->tuple[IP_CT_DIR_ORIGINAL].dst.protonum == 0
		    && (sinfo->invflags & XT_INV_PROTO))
			exit_error(PARAMETER_PROBLEM,
				   "rule would never match protocol");

		sinfo->flags |= XT_CONNTRACK_PROTO;
		break;

	case '3':
		check_inverse(optarg, &invert, &optind, 0);

		if (invert)
			sinfo->invflags |= XT_CONNTRACK_ORIGSRC;

		parse_hostnetworkmask(argv[optind-1], &addrs,
					&sinfo->sipmsk[IP_CT_DIR_ORIGINAL],
					&naddrs);
		if(naddrs > 1)
			exit_error(PARAMETER_PROBLEM,
				"multiple IP addresses not allowed");

		if(naddrs == 1) {
			sinfo->tuple[IP_CT_DIR_ORIGINAL].src.ip = addrs[0].s_addr;
		}

		sinfo->flags |= XT_CONNTRACK_ORIGSRC;
		break;

	case '4':
		check_inverse(optarg, &invert, &optind, 0);

		if (invert)
			sinfo->invflags |= XT_CONNTRACK_ORIGDST;

		parse_hostnetworkmask(argv[optind-1], &addrs,
					&sinfo->dipmsk[IP_CT_DIR_ORIGINAL],
					&naddrs);
		if(naddrs > 1)
			exit_error(PARAMETER_PROBLEM,
				"multiple IP addresses not allowed");

		if(naddrs == 1) {
			sinfo->tuple[IP_CT_DIR_ORIGINAL].dst.ip = addrs[0].s_addr;
		}

		sinfo->flags |= XT_CONNTRACK_ORIGDST;
		break;

	case '5':
		check_inverse(optarg, &invert, &optind, 0);

		if (invert)
			sinfo->invflags |= XT_CONNTRACK_REPLSRC;

		parse_hostnetworkmask(argv[optind-1], &addrs,
					&sinfo->sipmsk[IP_CT_DIR_REPLY],
					&naddrs);
		if(naddrs > 1)
			exit_error(PARAMETER_PROBLEM,
				"multiple IP addresses not allowed");

		if(naddrs == 1) {
			sinfo->tuple[IP_CT_DIR_REPLY].src.ip = addrs[0].s_addr;
		}

		sinfo->flags |= XT_CONNTRACK_REPLSRC;
		break;

	case '6':
		check_inverse(optarg, &invert, &optind, 0);

		if (invert)
			sinfo->invflags |= XT_CONNTRACK_REPLDST;

		parse_hostnetworkmask(argv[optind-1], &addrs,
					&sinfo->dipmsk[IP_CT_DIR_REPLY],
					&naddrs);
		if(naddrs > 1)
			exit_error(PARAMETER_PROBLEM,
				"multiple IP addresses not allowed");

		if(naddrs == 1) {
			sinfo->tuple[IP_CT_DIR_REPLY].dst.ip = addrs[0].s_addr;
		}

		sinfo->flags |= XT_CONNTRACK_REPLDST;
		break;

	case '7':
		check_inverse(optarg, &invert, &optind, 0);

		parse_statuses(argv[optind-1], sinfo);
		if (invert) {
			sinfo->invflags |= XT_CONNTRACK_STATUS;
		}
		sinfo->flags |= XT_CONNTRACK_STATUS;
		break;

	case '8':
		check_inverse(optarg, &invert, &optind, 0);

		parse_expires(argv[optind-1], sinfo);
		if (invert) {
			sinfo->invflags |= XT_CONNTRACK_EXPIRES;
		}
		sinfo->flags |= XT_CONNTRACK_EXPIRES;
		break;

	default:
		return 0;
	}

	*flags = sinfo->flags;
	return 1;
}

static void conntrack_mt_check(unsigned int flags)
{
	if (flags == 0)
		exit_error(PARAMETER_PROBLEM, "You must specify one or more options");
}

static void
print_state(unsigned int statemask)
{
	const char *sep = "";

	if (statemask & XT_CONNTRACK_STATE_INVALID) {
		printf("%sINVALID", sep);
		sep = ",";
	}
	if (statemask & XT_CONNTRACK_STATE_BIT(IP_CT_NEW)) {
		printf("%sNEW", sep);
		sep = ",";
	}
	if (statemask & XT_CONNTRACK_STATE_BIT(IP_CT_RELATED)) {
		printf("%sRELATED", sep);
		sep = ",";
	}
	if (statemask & XT_CONNTRACK_STATE_BIT(IP_CT_ESTABLISHED)) {
		printf("%sESTABLISHED", sep);
		sep = ",";
	}
	if (statemask & XT_CONNTRACK_STATE_UNTRACKED) {
		printf("%sUNTRACKED", sep);
		sep = ",";
	}
	if (statemask & XT_CONNTRACK_STATE_SNAT) {
		printf("%sSNAT", sep);
		sep = ",";
	}
	if (statemask & XT_CONNTRACK_STATE_DNAT) {
		printf("%sDNAT", sep);
		sep = ",";
	}
	printf(" ");
}

static void
print_status(unsigned int statusmask)
{
	const char *sep = "";

	if (statusmask & IPS_EXPECTED) {
		printf("%sEXPECTED", sep);
		sep = ",";
	}
	if (statusmask & IPS_SEEN_REPLY) {
		printf("%sSEEN_REPLY", sep);
		sep = ",";
	}
	if (statusmask & IPS_ASSURED) {
		printf("%sASSURED", sep);
		sep = ",";
	}
#ifdef IPS_CONFIRMED
	if (statusmask & IPS_CONFIRMED) {
		printf("%sCONFIRMED", sep);
		sep =",";
	}
#endif
	if (statusmask == 0) {
		printf("%sNONE", sep);
		sep = ",";
	}
	printf(" ");
}

static void
print_addr(struct in_addr *addr, struct in_addr *mask, int inv, int numeric)
{
	char buf[BUFSIZ];

	if (inv)
	       	printf("! ");

	if (mask->s_addr == 0L && !numeric)
		printf("%s ", "anywhere");
	else {
		if (numeric)
			sprintf(buf, "%s", ipaddr_to_numeric(addr));
		else
			sprintf(buf, "%s", ipaddr_to_anyname(addr));
		strcat(buf, ipmask_to_numeric(mask));
		printf("%s ", buf);
	}
}

/* Saves the matchinfo in parsable form to stdout. */
static void
matchinfo_print(const void *ip, const struct xt_entry_match *match, int numeric, const char *optpfx)
{
	struct xt_conntrack_info *sinfo = (void *)match->data;

	if(sinfo->flags & XT_CONNTRACK_STATE) {
        	if (sinfo->invflags & XT_CONNTRACK_STATE)
                	printf("! ");
		printf("%sctstate ", optpfx);
		print_state(sinfo->statemask);
	}

	if(sinfo->flags & XT_CONNTRACK_PROTO) {
        	if (sinfo->invflags & XT_CONNTRACK_PROTO)
                	printf("! ");
		printf("%sctproto ", optpfx);
		printf("%u ", sinfo->tuple[IP_CT_DIR_ORIGINAL].dst.protonum);
	}

	if(sinfo->flags & XT_CONNTRACK_ORIGSRC) {
		if (sinfo->invflags & XT_CONNTRACK_ORIGSRC)
			printf("! ");
		printf("%sctorigsrc ", optpfx);

		print_addr(
		    (struct in_addr *)&sinfo->tuple[IP_CT_DIR_ORIGINAL].src.ip,
		    &sinfo->sipmsk[IP_CT_DIR_ORIGINAL],
		    false,
		    numeric);
	}

	if(sinfo->flags & XT_CONNTRACK_ORIGDST) {
		if (sinfo->invflags & XT_CONNTRACK_ORIGDST)
			printf("! ");
		printf("%sctorigdst ", optpfx);

		print_addr(
		    (struct in_addr *)&sinfo->tuple[IP_CT_DIR_ORIGINAL].dst.ip,
		    &sinfo->dipmsk[IP_CT_DIR_ORIGINAL],
		    false,
		    numeric);
	}

	if(sinfo->flags & XT_CONNTRACK_REPLSRC) {
		if (sinfo->invflags & XT_CONNTRACK_REPLSRC)
			printf("! ");
		printf("%sctreplsrc ", optpfx);

		print_addr(
		    (struct in_addr *)&sinfo->tuple[IP_CT_DIR_REPLY].src.ip,
		    &sinfo->sipmsk[IP_CT_DIR_REPLY],
		    false,
		    numeric);
	}

	if(sinfo->flags & XT_CONNTRACK_REPLDST) {
		if (sinfo->invflags & XT_CONNTRACK_REPLDST)
			printf("! ");
		printf("%sctrepldst ", optpfx);

		print_addr(
		    (struct in_addr *)&sinfo->tuple[IP_CT_DIR_REPLY].dst.ip,
		    &sinfo->dipmsk[IP_CT_DIR_REPLY],
		    false,
		    numeric);
	}

	if(sinfo->flags & XT_CONNTRACK_STATUS) {
        	if (sinfo->invflags & XT_CONNTRACK_STATUS)
                	printf("! ");
		printf("%sctstatus ", optpfx);
		print_status(sinfo->statusmask);
	}

	if(sinfo->flags & XT_CONNTRACK_EXPIRES) {
        	if (sinfo->invflags & XT_CONNTRACK_EXPIRES)
                	printf("! ");
		printf("%sctexpire ", optpfx);

        	if (sinfo->expires_max == sinfo->expires_min)
                	printf("%lu ", sinfo->expires_min);
        	else
                	printf("%lu:%lu ", sinfo->expires_min, sinfo->expires_max);
	}
}

/* Prints out the matchinfo. */
static void conntrack_print(const void *ip, const struct xt_entry_match *match,
                            int numeric)
{
	matchinfo_print(ip, match, numeric, "");
}

/* Saves the matchinfo in parsable form to stdout. */
static void conntrack_save(const void *ip, const struct xt_entry_match *match)
{
	matchinfo_print(ip, match, 1, "--");
}

static struct xtables_match conntrack_match = {
	.version       = IPTABLES_VERSION,
	.name          = "conntrack",
	.revision      = 0,
	.family        = AF_INET,
	.size          = XT_ALIGN(sizeof(struct xt_conntrack_info)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_conntrack_info)),
	.help          = conntrack_mt_help,
	.parse         = conntrack_parse,
	.final_check   = conntrack_mt_check,
	.print         = conntrack_print,
	.save          = conntrack_save,
	.extra_opts    = conntrack_mt_opts,
};

void _init(void)
{
	xtables_register_match(&conntrack_match);
}
