/* Shared library add-on to iptables to add ICMP support. */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <ip6tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

struct icmp_names {
	const char *name;
	u_int8_t type;
	u_int8_t code_min, code_max;
};

static const struct icmp_names icmp_codes[] = {
	{ "destination-unreachable", 1, 0, 0xFF },
	{   "no-route", 1, 0, 0 },
	{   "communication-prohibited", 1, 1, 1 },
	{   "address-unreachable", 1, 3, 3 },
	{   "port-unreachable", 1, 4, 4 },

	{ "packet-too-big", 2, 0, 0xFF },

	{ "time-exceeded", 3, 0, 0xFF },
	/* Alias */ { "ttl-exceeded", 3, 0, 0xFF },
	{   "ttl-zero-during-transit", 3, 0, 0 },
	{   "ttl-zero-during-reassembly", 3, 1, 1 },

	{ "parameter-problem", 4, 0, 0xFF },
	{   "bad-header", 4, 0, 0 },
	{   "unknown-header-type", 4, 1, 1 },
	{   "unknown-option", 4, 2, 2 },

	{ "echo-request", 128, 0, 0xFF },
	/* Alias */ { "ping", 128, 0, 0xFF },

	{ "echo-reply", 129, 0, 0xFF },
	/* Alias */ { "pong", 129, 0, 0xFF },

	{ "router-solicitation", 133, 0, 0xFF },

	{ "router-advertisement", 134, 0, 0xFF },

	{ "neighbour-solicitation", 135, 0, 0xFF },
	/* Alias */ { "neighbor-solicitation", 135, 0, 0xFF },

	{ "neighbour-advertisement", 136, 0, 0xFF },
	/* Alias */ { "neighbor-advertisement", 136, 0, 0xFF },

	{ "redirect", 137, 0, 0xFF },

};

static void
print_icmptypes()
{
	unsigned int i;
	printf("Valid ICMPv6 Types:");

	for (i = 0; i < sizeof(icmp_codes)/sizeof(struct icmp_names); i++) {
		if (i && icmp_codes[i].type == icmp_codes[i-1].type) {
			if (icmp_codes[i].code_min == icmp_codes[i-1].code_min
			    && (icmp_codes[i].code_max
				== icmp_codes[i-1].code_max))
				printf(" (%s)", icmp_codes[i].name);
			else
				printf("\n   %s", icmp_codes[i].name);
		}
		else
			printf("\n%s", icmp_codes[i].name);
	}
	printf("\n");
}

/* Function which prints out usage message. */
static void
help(void)
{
	printf(
"ICMPv6 v%s options:\n"
" --icmp-type [!] typename	match icmp type\n"
"				(or numeric type or type/code)\n"
"\n", NETFILTER_VERSION);
	print_icmptypes();
}

static struct option opts[] = {
	{ "icmp-type", 1, 0, '1' },
	{0}
};

static unsigned int
parse_icmp(const char *icmptype, u_int8_t *type, u_int8_t code[])
{
	unsigned int limit = sizeof(icmp_codes)/sizeof(struct icmp_names);
	unsigned int match = limit;
	unsigned int i;

	for (i = 0; i < limit; i++) {
		if (strncasecmp(icmp_codes[i].name, icmptype, strlen(icmptype))
		    == 0) {
			if (match != limit)
				exit_error(PARAMETER_PROBLEM,
					   "Ambiguous ICMPv6 type `%s':"
					   " `%s' or `%s'?",
					   icmptype,
					   icmp_codes[match].name,
					   icmp_codes[i].name);
			match = i;
		}
	}

	if (match != limit) {
		*type = icmp_codes[match].type;
		code[0] = icmp_codes[match].code_min;
		code[1] = icmp_codes[match].code_max;
	} else {
		char *slash;
		char buffer[strlen(icmptype) + 1];
		int number;

		strcpy(buffer, icmptype);
		slash = strchr(buffer, '/');

		if (slash)
			*slash = '\0';

		number = string_to_number(buffer, 0, 255);
		if (number == -1)
			exit_error(PARAMETER_PROBLEM,
				   "Invalid ICMPv6 type `%s'\n", buffer);
		*type = number;
		if (slash) {
			number = string_to_number(slash+1, 0, 255);
			if (number == -1)
				exit_error(PARAMETER_PROBLEM,
					   "Invalid ICMPv6 code `%s'\n",
					   slash+1);
			code[0] = code[1] = number;
		} else {
			code[0] = 0;
			code[1] = 0xFF;
		}
	}

	if (code[0] == 0 && code[1] == 0xFF)
		return NFC_IP6_SRC_PT;
	else return NFC_IP6_SRC_PT | NFC_IP6_DST_PT;
}

/* Initialize the match. */
static void
init(struct ip6t_entry_match *m, unsigned int *nfcache)
{
	struct ip6t_icmp *icmpinfo = (struct ip6t_icmp *)m->data;

	icmpinfo->code[1] = 0xFF;
}

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ip6t_entry *entry,
      unsigned int *nfcache,
      struct ip6t_entry_match **match)
{
	struct ip6t_icmp *icmpinfo = (struct ip6t_icmp *)(*match)->data;

	switch (c) {
	case '1':
		if (check_inverse(optarg, &invert))
			optind++;
		*nfcache |= parse_icmp(argv[optind-1],
				       &icmpinfo->type,
				       icmpinfo->code);
		if (invert)
			icmpinfo->invflags |= IP6T_ICMP_INV;
		break;

	default:
		return 0;
	}

	return 1;
}

static void print_icmptype(u_int8_t type,
			   u_int8_t code_min, u_int8_t code_max,
			   int invert,
			   int numeric)
{
	if (!numeric) {
		unsigned int i;

		for (i = 0;
		     i < sizeof(icmp_codes)/sizeof(struct icmp_names);
		     i++) {
			if (icmp_codes[i].type == type
			    && icmp_codes[i].code_min == code_min
			    && icmp_codes[i].code_max == code_max)
				break;
		}

		if (i != sizeof(icmp_codes)/sizeof(struct icmp_names)) {
			printf("%s%s ",
			       invert ? "!" : "",
			       icmp_codes[i].name);
			return;
		}
	}

	if (invert)
		printf("!");

	printf("type %u", type);
	if (code_min == 0 && code_max == 0xFF)
		printf(" ");
	else if (code_min == code_max)
		printf(" code %u ", code_min);
	else
		printf(" codes %u-%u ", code_min, code_max);
}

/* Prints out the union ipt_matchinfo. */
static void
print(const struct ip6t_ip6 *ip,
      const struct ip6t_entry_match *match,
      int numeric)
{
	const struct ip6t_icmp *icmp = (struct ip6t_icmp *)match->data;

	printf("icmp ");
	print_icmptype(icmp->type, icmp->code[0], icmp->code[1],
		       icmp->invflags & IP6T_ICMP_INV,
		       numeric);

	if (icmp->invflags & ~IP6T_ICMP_INV)
		printf("Unknown invflags: 0x%X ",
		       icmp->invflags & ~IP6T_ICMP_INV);
}

/* Saves the match in parsable form to stdout. */
static void save(const struct ip6t_ip6 *ip, const struct ip6t_entry_match *match)
{
	const struct ip6t_icmp *icmp = (struct ip6t_icmp *)match->data;

	if (icmp->invflags & IP6T_ICMP_INV)
		printf("! ");

	printf("--icmp-type %u", icmp->type);
	if (icmp->code[0] != 0 || icmp->code[1] != 0xFF)
		printf("/%u", icmp->code[0]);
	printf(" ");
}

/* Final check; we don't care. */
static void final_check(unsigned int flags)
{
}

struct ip6tables_match icmp
= { NULL,
    "icmp",
    NETFILTER_VERSION,
    sizeof(struct ip6t_icmp),
    sizeof(struct ip6t_icmp),
    &help,
    &init,
    &parse,
    &final_check,
    &print,
    &save,
    opts
};

void _init(void)
{
	register_match6(&icmp);
}
