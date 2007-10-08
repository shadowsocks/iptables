/* Shared library add-on to iptables to add CLASSIFY target support. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <xtables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_CLASSIFY.h>
#include <linux/types.h>
#include <linux/pkt_sched.h>

/* Function which prints out usage message. */
static void
CLASSIFY_help(void)
{
	printf(
"CLASSIFY target v%s options:\n"
"  --set-class [MAJOR:MINOR]    Set skb->priority value\n"
"\n",
IPTABLES_VERSION);
}

static const struct option CLASSIFY_opts[] = {
	{ "set-class", 1, NULL, '1' },
	{ }
};

static int CLASSIFY_string_to_priority(const char *s, unsigned int *p)
{
	unsigned int i, j;

	if (sscanf(s, "%x:%x", &i, &j) != 2)
		return 1;
	
	*p = TC_H_MAKE(i<<16, j);
	return 0;
}

/* Function which parses command options; returns true if it
   ate an option */
static int
CLASSIFY_parse(int c, char **argv, int invert, unsigned int *flags,
      const void *entry,
      struct xt_entry_target **target)
{
	struct xt_classify_target_info *clinfo
		= (struct xt_classify_target_info *)(*target)->data;

	switch (c) {
	case '1':
		if (CLASSIFY_string_to_priority(optarg, &clinfo->priority))
			exit_error(PARAMETER_PROBLEM,
				   "Bad class value `%s'", optarg);
		if (*flags)
			exit_error(PARAMETER_PROBLEM,
			           "CLASSIFY: Can't specify --set-class twice");
		*flags = 1;
		break;

	default:
		return 0;
	}

	return 1;
}

static void
CLASSIFY_final_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM,
		           "CLASSIFY: Parameter --set-class is required");
}

static void
CLASSIFY_print_class(unsigned int priority, int numeric)
{
	printf("%x:%x ", TC_H_MAJ(priority)>>16, TC_H_MIN(priority));
}

/* Prints out the targinfo. */
static void
CLASSIFY_print(const void *ip,
      const struct xt_entry_target *target,
      int numeric)
{
	const struct xt_classify_target_info *clinfo =
		(const struct xt_classify_target_info *)target->data;
	printf("CLASSIFY set ");
	CLASSIFY_print_class(clinfo->priority, numeric);
}

/* Saves the union ipt_targinfo in parsable form to stdout. */
static void
CLASSIFY_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_classify_target_info *clinfo =
		(const struct xt_classify_target_info *)target->data;

	printf("--set-class %.4x:%.4x ",
	       TC_H_MAJ(clinfo->priority)>>16, TC_H_MIN(clinfo->priority));
}

static struct xtables_target classify_target = { 
	.family		= AF_INET,
	.name		= "CLASSIFY",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_classify_target_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_classify_target_info)),
	.help		= CLASSIFY_help,
	.parse		= CLASSIFY_parse,
	.final_check	= CLASSIFY_final_check,
	.print		= CLASSIFY_print,
	.save		= CLASSIFY_save,
	.extra_opts	= CLASSIFY_opts,
};

static struct xtables_target classify_target6 = { 
	.family		= AF_INET6,
	.name		= "CLASSIFY",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_classify_target_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_classify_target_info)),
	.help		= CLASSIFY_help,
	.parse		= CLASSIFY_parse,
	.final_check	= CLASSIFY_final_check,
	.print		= CLASSIFY_print,
	.save		= CLASSIFY_save,
	.extra_opts	= CLASSIFY_opts,
};

void _init(void)
{
	xtables_register_target(&classify_target);
	xtables_register_target(&classify_target6);
}
