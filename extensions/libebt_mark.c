/* ebt_mark
 *
 * Authors:
 * Bart De Schuymer <bdschuym@pandora.be>
 *
 * July, 2002, September 2006
 *
 * Adapted by Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>
 * to use libxtables for ebtables-compat in 2015.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <xtables.h>
#include <linux/netfilter_bridge/ebt_mark_t.h>
#include "iptables/nft.h"
#include "iptables/nft-bridge.h"

static int mark_supplied;

#define MARK_TARGET  '1'
#define MARK_SETMARK '2'
#define MARK_ORMARK  '3'
#define MARK_ANDMARK '4'
#define MARK_XORMARK '5'
static struct option brmark_opts[] = {
	{ .name = "mark-target",.has_arg = true,	.val = MARK_TARGET },
	/* an oldtime messup, we should have always used the scheme
	 * <extension-name>-<option> */
	{ .name = "set-mark",	.has_arg = true,	.val = MARK_SETMARK },
	{ .name = "mark-set",	.has_arg = true,	.val = MARK_SETMARK },
	{ .name = "mark-or",	.has_arg = true,	.val = MARK_ORMARK },
	{ .name = "mark-and",	.has_arg = true,	.val = MARK_ANDMARK },
	{ .name = "mark-xor",	.has_arg = true,	.val = MARK_XORMARK },
	XT_GETOPT_TABLEEND,
};

static void brmark_print_help(void)
{
	printf(
	"mark target options:\n"
	" --mark-set value     : Set nfmark value\n"
	" --mark-or  value     : Or nfmark with value (nfmark |= value)\n"
	" --mark-and value     : And nfmark with value (nfmark &= value)\n"
	" --mark-xor value     : Xor nfmark with value (nfmark ^= value)\n"
	" --mark-target target : ACCEPT, DROP, RETURN or CONTINUE\n");
}

static void brmark_init(struct xt_entry_target *target)
{
	struct ebt_mark_t_info *info = (struct ebt_mark_t_info *)target->data;

	info->target = EBT_ACCEPT;
	info->mark = 0;
	mark_supplied = 0;
}

#define OPT_MARK_TARGET   0x01
#define OPT_MARK_SETMARK  0x02
#define OPT_MARK_ORMARK   0x04
#define OPT_MARK_ANDMARK  0x08
#define OPT_MARK_XORMARK  0x10

static int
brmark_parse(int c, char **argv, int invert, unsigned int *flags,
	     const void *entry, struct xt_entry_target **target)
{
	struct ebt_mark_t_info *info = (struct ebt_mark_t_info *)
				       (*target)->data;
	char *end;
	uint32_t mask;

	switch (c) {
	case MARK_TARGET:
		{ unsigned int tmp;
		EBT_CHECK_OPTION(flags, OPT_MARK_TARGET);
		if (ebt_fill_target(optarg, &tmp))
			xtables_error(PARAMETER_PROBLEM,
				      "Illegal --mark-target target");
		/* the 4 lsb are left to designate the target */
		info->target = (info->target & ~EBT_VERDICT_BITS) |
			       (tmp & EBT_VERDICT_BITS);
		}
		return 1;
	case MARK_SETMARK:
		EBT_CHECK_OPTION(flags, OPT_MARK_SETMARK);
		mask = (OPT_MARK_ORMARK|OPT_MARK_ANDMARK|OPT_MARK_XORMARK);
		if (*flags & mask)
			xtables_error(PARAMETER_PROBLEM,
				      "--mark-set cannot be used together with"
				      " specific --mark option");
		info->target = (info->target & EBT_VERDICT_BITS) |
			       MARK_SET_VALUE;
		break;
	case MARK_ORMARK:
		EBT_CHECK_OPTION(flags, OPT_MARK_ORMARK);
		mask = (OPT_MARK_SETMARK|OPT_MARK_ANDMARK|OPT_MARK_XORMARK);
		if (*flags & mask)
			xtables_error(PARAMETER_PROBLEM,
				      "--mark-or cannot be used together with"
				      " specific --mark option");
		info->target = (info->target & EBT_VERDICT_BITS) |
			       MARK_OR_VALUE;
		break;
	case MARK_ANDMARK:
		EBT_CHECK_OPTION(flags, OPT_MARK_ANDMARK);
		mask = (OPT_MARK_SETMARK|OPT_MARK_ORMARK|OPT_MARK_XORMARK);
		if (*flags & mask)
			xtables_error(PARAMETER_PROBLEM,
				      "--mark-and cannot be used together with"
				      " specific --mark option");
		info->target = (info->target & EBT_VERDICT_BITS) |
			       MARK_AND_VALUE;
		break;
	case MARK_XORMARK:
		EBT_CHECK_OPTION(flags, OPT_MARK_XORMARK);
		mask = (OPT_MARK_SETMARK|OPT_MARK_ANDMARK|OPT_MARK_ORMARK);
		if (*flags & mask)
			xtables_error(PARAMETER_PROBLEM,
				      "--mark-xor cannot be used together with"
				      " specific --mark option");
		info->target = (info->target & EBT_VERDICT_BITS) |
			       MARK_XOR_VALUE;
		break;
	default:
		return 0;
	}
	/* mutual code */
	info->mark = strtoul(optarg, &end, 0);
	if (*end != '\0' || end == optarg)
		xtables_error(PARAMETER_PROBLEM, "Bad MARK value '%s'",
			      optarg);

	mark_supplied = 1;
	return 1;
}

static void brmark_print(const void *ip, const struct xt_entry_target *target,
			 int numeric)
{
	struct ebt_mark_t_info *info = (struct ebt_mark_t_info *)target->data;
	int tmp;

	tmp = info->target & ~EBT_VERDICT_BITS;
	if (tmp == MARK_SET_VALUE)
		printf("--mark-set");
	else if (tmp == MARK_OR_VALUE)
		printf("--mark-or");
	else if (tmp == MARK_XOR_VALUE)
		printf("--mark-xor");
	else if (tmp == MARK_AND_VALUE)
		printf("--mark-and");
	else
		xtables_error(PARAMETER_PROBLEM, "Unknown mark action");

	printf(" 0x%lx", info->mark);
	tmp = info->target | ~EBT_VERDICT_BITS;
	printf(" --mark-target %s", ebt_target_name(tmp));
}

static void brmark_final_check(unsigned int flags)
{
	if (mark_supplied == 0)
		xtables_error(PARAMETER_PROBLEM, "No mark value supplied");

	if (!flags)
		xtables_error(PARAMETER_PROBLEM,
			      "You must specify some option");
}

static struct xtables_target brmark_target = {
	.name		= "mark",
	.revision	= 0,
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_BRIDGE,
	.size		= XT_ALIGN(sizeof(struct ebt_mark_t_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct ebt_mark_t_info)),
	.help		= brmark_print_help,
	.init		= brmark_init,
	.parse		= brmark_parse,
	.final_check	= brmark_final_check,
	.print		= brmark_print,
	.extra_opts	= brmark_opts,
};

void _init(void)
{
	xtables_register_target(&brmark_target);
}
