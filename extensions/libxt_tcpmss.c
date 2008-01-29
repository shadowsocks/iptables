/* Shared library add-on to iptables to add tcp MSS matching support. */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <xtables.h>
#include <linux/netfilter/xt_tcpmss.h>

/* Function which prints out usage message. */
static void tcpmss_help(void)
{
	printf(
"tcpmss match v%s options:\n"
"[!] --mss value[:value]	Match TCP MSS range.\n"
"				(only valid for TCP SYN or SYN/ACK packets)\n",
IPTABLES_VERSION);
}

static const struct option tcpmss_opts[] = {
	{ "mss", 1, NULL, '1' },
	{ .name = NULL }
};

static u_int16_t
parse_tcp_mssvalue(const char *mssvalue)
{
	unsigned int mssvaluenum;

	if (string_to_number(mssvalue, 0, 65535, &mssvaluenum) != -1)
		return (u_int16_t)mssvaluenum;

	exit_error(PARAMETER_PROBLEM,
		   "Invalid mss `%s' specified", mssvalue);
}

static void
parse_tcp_mssvalues(const char *mssvaluestring,
		    u_int16_t *mss_min, u_int16_t *mss_max)
{
	char *buffer;
	char *cp;

	buffer = strdup(mssvaluestring);
	if ((cp = strchr(buffer, ':')) == NULL)
		*mss_min = *mss_max = parse_tcp_mssvalue(buffer);
	else {
		*cp = '\0';
		cp++;

		*mss_min = buffer[0] ? parse_tcp_mssvalue(buffer) : 0;
		*mss_max = cp[0] ? parse_tcp_mssvalue(cp) : 0xFFFF;
	}
	free(buffer);
}

/* Function which parses command options; returns true if it
   ate an option */
static int
tcpmss_parse(int c, char **argv, int invert, unsigned int *flags,
             const void *entry, struct xt_entry_match **match)
{
	struct xt_tcpmss_match_info *mssinfo =
		(struct xt_tcpmss_match_info *)(*match)->data;

	switch (c) {
	case '1':
		if (*flags)
			exit_error(PARAMETER_PROBLEM,
				   "Only one `--mss' allowed");
		check_inverse(optarg, &invert, &optind, 0);
		parse_tcp_mssvalues(argv[optind-1],
				    &mssinfo->mss_min, &mssinfo->mss_max);
		if (invert)
			mssinfo->invert = 1;
		*flags = 1;
		break;
	default:
		return 0;
	}
	return 1;
}

static void
print_tcpmss(u_int16_t mss_min, u_int16_t mss_max, int invert, int numeric)
{
	if (invert)
		printf("! ");

	if (mss_min == mss_max)
		printf("%u ", mss_min);
	else
		printf("%u:%u ", mss_min, mss_max);
}

/* Final check; must have specified --mss. */
static void tcpmss_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM,
			   "tcpmss match: You must specify `--mss'");
}

/* Prints out the matchinfo. */
static void
tcpmss_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_tcpmss_match_info *mssinfo =
		(const struct xt_tcpmss_match_info *)match->data;

	printf("tcpmss match ");
	print_tcpmss(mssinfo->mss_min, mssinfo->mss_max,
		     mssinfo->invert, numeric);
}

/* Saves the union ipt_matchinfo in parsable form to stdout. */
static void tcpmss_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_tcpmss_match_info *mssinfo =
		(const struct xt_tcpmss_match_info *)match->data;

	printf("--mss ");
	print_tcpmss(mssinfo->mss_min, mssinfo->mss_max,
		     mssinfo->invert, 0);
}

static struct xtables_match tcpmss_match = {
	.family		= AF_INET,
	.name		= "tcpmss",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_tcpmss_match_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_tcpmss_match_info)),
	.help		= tcpmss_help,
	.parse		= tcpmss_parse,
	.final_check	= tcpmss_check,
	.print		= tcpmss_print,
	.save		= tcpmss_save,
	.extra_opts	= tcpmss_opts,
};

static struct xtables_match tcpmss_match6 = {
	.family		= AF_INET6,
	.name		= "tcpmss",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_tcpmss_match_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_tcpmss_match_info)),
	.help		= tcpmss_help,
	.parse		= tcpmss_parse,
	.final_check	= tcpmss_check,
	.print		= tcpmss_print,
	.save		= tcpmss_save,
	.extra_opts	= tcpmss_opts,
};

void _init(void)
{
	xtables_register_match(&tcpmss_match);
	xtables_register_match(&tcpmss_match6);
}
