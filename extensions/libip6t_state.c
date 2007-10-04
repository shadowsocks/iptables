/* Ugly hack to make state matching for ipv6 work before iptables-1.4.x is finished */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <ip6tables.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter_ipv4/ipt_state.h>

#ifndef IPT_STATE_UNTRACKED
#define IPT_STATE_UNTRACKED (1 << (IP_CT_NUMBER + 1))
#endif

/* Function which prints out usage message. */
static void state_help(void)
{
	printf(
"state v%s options:\n"
" [!] --state [INVALID|ESTABLISHED|NEW|RELATED|UNTRACKED][,...]\n"
"				State(s) to match\n"
"\n", IPTABLES_VERSION);
}

static const struct option state_opts[] = {
	{ "state", 1, 0, '1' },
	{0}
};

static int
parse_state(const char *state, size_t strlen, struct ipt_state_info *sinfo)
{
	if (strncasecmp(state, "INVALID", strlen) == 0)
		sinfo->statemask |= IPT_STATE_INVALID;
	else if (strncasecmp(state, "NEW", strlen) == 0)
		sinfo->statemask |= IPT_STATE_BIT(IP_CT_NEW);
	else if (strncasecmp(state, "ESTABLISHED", strlen) == 0)
		sinfo->statemask |= IPT_STATE_BIT(IP_CT_ESTABLISHED);
	else if (strncasecmp(state, "RELATED", strlen) == 0)
		sinfo->statemask |= IPT_STATE_BIT(IP_CT_RELATED);
	else if (strncasecmp(state, "UNTRACKED", strlen) == 0)
		sinfo->statemask |= IPT_STATE_UNTRACKED;
	else
		return 0;
	return 1;
}

static void
parse_states(const char *arg, struct ipt_state_info *sinfo)
{
	const char *comma;

	while ((comma = strchr(arg, ',')) != NULL) {
		if (comma == arg || !parse_state(arg, comma-arg, sinfo))
			exit_error(PARAMETER_PROBLEM, "Bad state `%s'", arg);
		arg = comma+1;
	}

	if (strlen(arg) == 0 || !parse_state(arg, strlen(arg), sinfo))
		exit_error(PARAMETER_PROBLEM, "Bad state `%s'", arg);
}

/* Function which parses command options; returns true if it
   ate an option */
static int state_parse(int c, char **argv, int invert, unsigned int *flags,
                       const void *entry, struct xt_entry_match **match)
{
	struct ipt_state_info *sinfo = (struct ipt_state_info *)(*match)->data;

	switch (c) {
	case '1':
		check_inverse(optarg, &invert, &optind, 0);

		parse_states(argv[optind-1], sinfo);
		if (invert)
			sinfo->statemask = ~sinfo->statemask;
		*flags = 1;
		break;

	default:
		return 0;
	}

	return 1;
}

/* Final check; must have specified --state. */
static void state_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM, "You must specify `--state'");
}

static void print_state(unsigned int statemask)
{
	const char *sep = "";

	if (statemask & IPT_STATE_INVALID) {
		printf("%sINVALID", sep);
		sep = ",";
	}
	if (statemask & IPT_STATE_BIT(IP_CT_NEW)) {
		printf("%sNEW", sep);
		sep = ",";
	}
	if (statemask & IPT_STATE_BIT(IP_CT_RELATED)) {
		printf("%sRELATED", sep);
		sep = ",";
	}
	if (statemask & IPT_STATE_BIT(IP_CT_ESTABLISHED)) {
		printf("%sESTABLISHED", sep);
		sep = ",";
	}
	if (statemask & IPT_STATE_UNTRACKED) {
		printf("%sUNTRACKED", sep);
		sep = ",";
	}
	printf(" ");
}

/* Prints out the matchinfo. */
static void state_print(const void *ip, const struct xt_entry_match *match,
                        int numeric)
{
	struct ipt_state_info *sinfo = (struct ipt_state_info *)match->data;

	printf("state ");
	print_state(sinfo->statemask);
}

/* Saves the matchinfo in parsable form to stdout. */
static void state_save(const void *ip, const struct xt_entry_match *match)
{
	struct ipt_state_info *sinfo = (struct ipt_state_info *)match->data;

	printf("--state ");
	print_state(sinfo->statemask);
}

static struct ip6tables_match state_match6 = {
	.name		= "state",
	.version	= IPTABLES_VERSION,
	.size		= IP6T_ALIGN(sizeof(struct ipt_state_info)),
	.userspacesize	= IP6T_ALIGN(sizeof(struct ipt_state_info)),
	.help		= state_help,
	.parse		= state_parse,
	.final_check	= state_check,
	.print		= state_print,
	.save		= state_save,
	.extra_opts	= state_opts,
};

void _init(void)
{
	register_match6(&state_match6);
}
