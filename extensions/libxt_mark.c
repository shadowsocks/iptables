/* Shared library add-on to iptables to add NFMARK matching support. */
#include <stdbool.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <xtables.h>
#include <linux/netfilter/xt_mark.h>

enum {
	F_MARK = 1 << 0,
};

static void mark_mt_help(void)
{
	printf(
"mark match options:\n"
"[!] --mark value[/mask]    Match nfmark value with optional mask\n"
"\n");
}

static const struct option mark_mt_opts[] = {
	{.name = "mark", .has_arg = true, .val = '1'},
	{ .name = NULL }
};

static int mark_mt_parse(int c, char **argv, int invert, unsigned int *flags,
                         const void *entry, struct xt_entry_match **match)
{
	struct xt_mark_mtinfo1 *info = (void *)(*match)->data;
	unsigned int mark, mask = ~0U;
	char *end;

	switch (c) {
	case '1': /* --mark */
		param_act(P_ONLY_ONCE, "mark", "--mark", *flags & F_MARK);
		if (!strtonum(optarg, &end, &mark, 0, ~0U))
			param_act(P_BAD_VALUE, "mark", "--mark", optarg);
		if (*end == '/')
			if (!strtonum(end + 1, &end, &mask, 0, ~0U))
				param_act(P_BAD_VALUE, "mark", "--mark", optarg);
		if (*end != '\0')
			param_act(P_BAD_VALUE, "mark", "--mark", optarg);

		if (invert)
			info->invert = true;
		info->mark = mark;
		info->mask = mask;
		*flags    |= F_MARK;
		return true;
	}
	return false;
}

/* Function which parses command options; returns true if it
   ate an option */
static int
mark_parse(int c, char **argv, int invert, unsigned int *flags,
           const void *entry, struct xt_entry_match **match)
{
	struct xt_mark_info *markinfo = (struct xt_mark_info *)(*match)->data;

	switch (c) {
		char *end;
	case '1':
		check_inverse(optarg, &invert, &optind, 0);
		markinfo->mark = strtoul(optarg, &end, 0);
		if (*end == '/') {
			markinfo->mask = strtoul(end+1, &end, 0);
		} else
			markinfo->mask = 0xffffffff;
		if (*end != '\0' || end == optarg)
			exit_error(PARAMETER_PROBLEM, "Bad MARK value `%s'", optarg);
		if (invert)
			markinfo->invert = 1;
		*flags = 1;
		break;

	default:
		return 0;
	}
	return 1;
}

static void print_mark(unsigned int mark, unsigned int mask)
{
	if (mask != 0xffffffffU)
		printf("0x%x/0x%x ", mark, mask);
	else
		printf("0x%x ", mark);
}

static void mark_mt_check(unsigned int flags)
{
	if (flags == 0)
		exit_error(PARAMETER_PROBLEM,
			   "mark match: The --mark option is required");
}

static void
mark_mt_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_mark_mtinfo1 *info = (const void *)match->data;

	printf("mark match ");
	if (info->invert)
		printf("!");
	print_mark(info->mark, info->mask);
}

/* Prints out the matchinfo. */
static void
mark_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	struct xt_mark_info *info = (struct xt_mark_info *)match->data;

	printf("MARK match ");

	if (info->invert)
		printf("!");
	
	print_mark(info->mark, info->mask);
}

static void mark_mt_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_mark_mtinfo1 *info = (const void *)match->data;

	if (info->invert)
		printf("!");

	printf("--mark ");
	print_mark(info->mark, info->mask);
}

/* Saves the union ipt_matchinfo in parsable form to stdout. */
static void
mark_save(const void *ip, const struct xt_entry_match *match)
{
	struct xt_mark_info *info = (struct xt_mark_info *)match->data;

	if (info->invert)
		printf("! ");
	
	printf("--mark ");
	print_mark(info->mark, info->mask);
}

static struct xtables_match mark_match = {
	.family		= AF_INET,
	.name		= "mark",
	.revision	= 0,
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_mark_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_mark_info)),
	.help		= mark_mt_help,
	.parse		= mark_parse,
	.final_check	= mark_mt_check,
	.print		= mark_print,
	.save		= mark_save,
	.extra_opts	= mark_mt_opts,
};

static struct xtables_match mark_match6 = {
	.family		= AF_INET6,
	.name		= "mark",
	.revision	= 0,
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_mark_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_mark_info)),
	.help		= mark_mt_help,
	.parse		= mark_parse,
	.final_check	= mark_mt_check,
	.print		= mark_print,
	.save		= mark_save,
	.extra_opts	= mark_mt_opts,
};

static struct xtables_match mark_mt_reg = {
	.version        = IPTABLES_VERSION,
	.name           = "mark",
	.revision       = 1,
	.family         = AF_INET6,
	.size           = XT_ALIGN(sizeof(struct xt_mark_mtinfo1)),
	.userspacesize  = XT_ALIGN(sizeof(struct xt_mark_mtinfo1)),
	.help           = mark_mt_help,
	.parse          = mark_mt_parse,
	.final_check    = mark_mt_check,
	.print          = mark_mt_print,
	.save           = mark_mt_save,
	.extra_opts     = mark_mt_opts,
};

static struct xtables_match mark_mt6_reg = {
	.version        = IPTABLES_VERSION,
	.name           = "mark",
	.revision       = 1,
	.family         = AF_INET6,
	.size           = XT_ALIGN(sizeof(struct xt_mark_mtinfo1)),
	.userspacesize  = XT_ALIGN(sizeof(struct xt_mark_mtinfo1)),
	.help           = mark_mt_help,
	.parse          = mark_mt_parse,
	.final_check    = mark_mt_check,
	.print          = mark_mt_print,
	.save           = mark_mt_save,
	.extra_opts     = mark_mt_opts,
};

void _init(void)
{
	xtables_register_match(&mark_match);
	xtables_register_match(&mark_match6);
	xtables_register_match(&mark_mt_reg);
	xtables_register_match(&mark_mt6_reg);
}
