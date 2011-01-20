/* Shared library add-on to xtables for AUDIT
 *
 * (C) 2010-2011, Thomas Graf <tgraf@redhat.com>
 * (C) 2010-2011, Red Hat, Inc.
 *
 * This program is distributed under the terms of GNU GPL v2, 1991
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <xtables.h>
#include <linux/netfilter/xt_AUDIT.h>

static void audit_help(void)
{
	printf(
"AUDIT target options\n"
"  --type TYPE		Action type to be recorded.\n");
}

static const struct option audit_opts[] = {
	{.name = "type", .has_arg = true, .val = 't'},
	XT_GETOPT_TABLEEND,
};

static int audit_parse(int c, char **argv, int invert, unsigned int *flags,
                     const void *entry, struct xt_entry_target **target)
{
	struct xt_audit_info *einfo
		= (struct xt_audit_info *)(*target)->data;

	switch (c) {
	case 't':
		if (!strcasecmp(optarg, "accept"))
			einfo->type = XT_AUDIT_TYPE_ACCEPT;
		else if (!strcasecmp(optarg, "drop"))
			einfo->type = XT_AUDIT_TYPE_DROP;
		else if (!strcasecmp(optarg, "reject"))
			einfo->type = XT_AUDIT_TYPE_REJECT;
		else
			xtables_error(PARAMETER_PROBLEM,
				   "Bad action type value `%s'", optarg);

		if (*flags)
			xtables_error(PARAMETER_PROBLEM,
			           "AUDIT: Can't specify --type twice");
		*flags = 1;
		break;
	default:
		return 0;
	}

	return 1;
}

static void audit_final_check(unsigned int flags)
{
	if (!flags)
		xtables_error(PARAMETER_PROBLEM,
		           "AUDIT target: Parameter --type is required");
}

static void audit_print(const void *ip, const struct xt_entry_target *target,
                      int numeric)
{
	const struct xt_audit_info *einfo =
		(const struct xt_audit_info *)target->data;

	printf("AUDIT ");

	switch(einfo->type) {
	case XT_AUDIT_TYPE_ACCEPT:
		printf("accept");
		break;
	case XT_AUDIT_TYPE_DROP:
		printf("drop");
		break;
	case XT_AUDIT_TYPE_REJECT:
		printf("reject");
		break;
	}
}

static void audit_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_audit_info *einfo =
		(const struct xt_audit_info *)target->data;

	switch(einfo->type) {
	case XT_AUDIT_TYPE_ACCEPT:
		printf("--type=accept");
		break;
	case XT_AUDIT_TYPE_DROP:
		printf("--type=drop");
		break;
	case XT_AUDIT_TYPE_REJECT:
		printf("--type=reject");
		break;
	}
}

static struct xtables_target audit_tg_reg = {
	.name		= "AUDIT",
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_UNSPEC,
	.size		= XT_ALIGN(sizeof(struct xt_audit_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_audit_info)),
	.help		= audit_help,
	.parse		= audit_parse,
	.final_check	= audit_final_check,
	.print		= audit_print,
	.save		= audit_save,
	.extra_opts	= audit_opts,
};

void _init(void)
{
	xtables_register_target(&audit_tg_reg);
}
