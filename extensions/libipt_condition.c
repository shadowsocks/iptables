/* Shared library add-on to iptables for condition match */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <iptables.h>

#include<linux/netfilter_ipv4/ip_tables.h>
#include<linux/netfilter_ipv4/ipt_condition.h>

static void condition_help(void)
{
	printf("condition match v%s options:\n"
	       "--condition [!] filename       "
	       "Match on boolean value stored in /proc file\n",
	       IPTABLES_VERSION);
}

static const struct option condition_opts[] = {
	{ .name = "condition", .has_arg = 1, .flag = 0, .val = 'X' },
	{ .name = 0 }
};

static int condition_parse(int c, char **argv, int invert, unsigned int *flags,
                           const void *entry, struct xt_entry_match **match)
{
	struct condition_info *info =
	    (struct condition_info *) (*match)->data;

	if (c == 'X') {
		if (*flags)
			exit_error(PARAMETER_PROBLEM,
				   "Can't specify multiple conditions");

		check_inverse(optarg, &invert, &optind, 0);

		if (strlen(argv[optind - 1]) < CONDITION_NAME_LEN)
			strcpy(info->name, argv[optind - 1]);
		else
			exit_error(PARAMETER_PROBLEM,
				   "File name too long");

		info->invert = invert;
		*flags = 1;
		return 1;
	}

	return 0;
}

static void condition_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM,
			   "Condition match: must specify --condition");
}

static void condition_print(const void *ip, const struct xt_entry_match *match,
                            int numeric)
{
	const struct condition_info *info =
	    (const struct condition_info *) match->data;

	printf("condition %s%s ", (info->invert) ? "!" : "", info->name);
}


static void condition_save(const void *ip, const struct xt_entry_match *match)
{
	const struct condition_info *info =
	    (const struct condition_info *) match->data;

	printf("--condition %s\"%s\" ", (info->invert) ? "! " : "", info->name);
}

static struct iptables_match condition_match = {
	.name 		= "condition",
	.version 	= IPTABLES_VERSION,
	.size 		= IPT_ALIGN(sizeof(struct condition_info)),
	.userspacesize 	= IPT_ALIGN(sizeof(struct condition_info)),
	.help 		= condition_help,
	.parse 		= condition_parse,
	.final_check	= condition_check,
	.print 		= condition_print,
	.save 		= condition_save,
	.extra_opts 	= condition_opts,
};


void
_init(void)
{
	register_match(&condition_match);
}
