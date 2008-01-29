/* Shared library add-on to iptables to add state tracking support. */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/xt_state.h>

#ifndef XT_STATE_UNTRACKED
#define XT_STATE_UNTRACKED (1 << (IP_CT_NUMBER + 1))
#endif

/* Function which prints out usage message. */
static void
state_help(void)
{
	printf(
"state v%s options:\n"
" [!] --state [INVALID|ESTABLISHED|NEW|RELATED|UNTRACKED][,...]\n"
"				State(s) to match\n"
"\n", IPTABLES_VERSION);
}

static const struct option state_opts[] = {
	{ "state", 1, NULL, '1' },
	{ .name = NULL }
};

static int
state_parse_state(const char *state, size_t strlen, struct xt_state_info *sinfo)
{
	if (strncasecmp(state, "INVALID", strlen) == 0)
		sinfo->statemask |= XT_STATE_INVALID;
	else if (strncasecmp(state, "NEW", strlen) == 0)
		sinfo->statemask |= XT_STATE_BIT(IP_CT_NEW);
	else if (strncasecmp(state, "ESTABLISHED", strlen) == 0)
		sinfo->statemask |= XT_STATE_BIT(IP_CT_ESTABLISHED);
	else if (strncasecmp(state, "RELATED", strlen) == 0)
		sinfo->statemask |= XT_STATE_BIT(IP_CT_RELATED);
	else if (strncasecmp(state, "UNTRACKED", strlen) == 0)
		sinfo->statemask |= XT_STATE_UNTRACKED;
	else
		return 0;
	return 1;
}

static void
state_parse_states(const char *arg, struct xt_state_info *sinfo)
{
	const char *comma;

	while ((comma = strchr(arg, ',')) != NULL) {
		if (comma == arg || !state_parse_state(arg, comma-arg, sinfo))
			exit_error(PARAMETER_PROBLEM, "Bad state `%s'", arg);
		arg = comma+1;
	}

	if (strlen(arg) == 0 || !state_parse_state(arg, strlen(arg), sinfo))
		exit_error(PARAMETER_PROBLEM, "Bad state `%s'", arg);
}

/* Function which parses command options; returns true if it
   ate an option */
static int
state_parse(int c, char **argv, int invert, unsigned int *flags,
      const void *entry,
      struct xt_entry_match **match)
{
	struct xt_state_info *sinfo = (struct xt_state_info *)(*match)->data;

	switch (c) {
	case '1':
		check_inverse(optarg, &invert, &optind, 0);

		state_parse_states(argv[optind-1], sinfo);
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
static void state_final_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM, "You must specify `--state'");
}

static void state_print_state(unsigned int statemask)
{
	const char *sep = "";

	if (statemask & XT_STATE_INVALID) {
		printf("%sINVALID", sep);
		sep = ",";
	}
	if (statemask & XT_STATE_BIT(IP_CT_NEW)) {
		printf("%sNEW", sep);
		sep = ",";
	}
	if (statemask & XT_STATE_BIT(IP_CT_RELATED)) {
		printf("%sRELATED", sep);
		sep = ",";
	}
	if (statemask & XT_STATE_BIT(IP_CT_ESTABLISHED)) {
		printf("%sESTABLISHED", sep);
		sep = ",";
	}
	if (statemask & XT_STATE_UNTRACKED) {
		printf("%sUNTRACKED", sep);
		sep = ",";
	}
	printf(" ");
}

/* Prints out the matchinfo. */
static void
state_print(const void *ip,
      const struct xt_entry_match *match,
      int numeric)
{
	struct xt_state_info *sinfo = (struct xt_state_info *)match->data;

	printf("state ");
	state_print_state(sinfo->statemask);
}

/* Saves the matchinfo in parsable form to stdout. */
static void state_save(const void *ip, const struct xt_entry_match *match)
{
	struct xt_state_info *sinfo = (struct xt_state_info *)match->data;

	printf("--state ");
	state_print_state(sinfo->statemask);
}

static struct xtables_match state_match = { 
	.family		= AF_INET,
	.name		= "state",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_state_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_state_info)),
	.help		= state_help,
	.parse		= state_parse,
	.final_check	= state_final_check,
	.print		= state_print,
	.save		= state_save,
	.extra_opts	= state_opts,
};

static struct xtables_match state_match6 = { 
	.family		= AF_INET6,
	.name		= "state",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_state_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_state_info)),
	.help		= state_help,
	.parse		= state_parse,
	.final_check	= state_final_check,
	.print		= state_print,
	.save		= state_save,
	.extra_opts	= state_opts,
};

void _init(void)
{
	xtables_register_match(&state_match);
	xtables_register_match(&state_match6);
}
