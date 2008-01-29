/* Shared library add-on to iptables to add connmark matching support.
 *
 * (C) 2002,2004 MARA Systems AB <http://www.marasystems.com>
 * by Henrik Nordstrom <hno@marasystems.com>
 *
 * Version 1.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <xtables.h>
#include <linux/netfilter/xt_connmark.h>

enum {
	F_MARK = 1 << 0,
};

static void connmark_mt_help(void)
{
	printf(
"connmark match options:\n"
"[!] --mark value[/mask]    Match ctmark value with optional mask\n"
"\n");
}

static const struct option connmark_mt_opts[] = {
	{.name = "mark", .has_arg = true, .val = '1'},
	{ .name = NULL }
};

static int
connmark_mt_parse(int c, char **argv, int invert, unsigned int *flags,
                  const void *entry, struct xt_entry_match **match)
{
	struct xt_connmark_mtinfo1 *info = (void *)(*match)->data;
	unsigned int mark, mask = ~0U;
	char *end;

	switch (c) {
	case '1': /* --mark */
		param_act(P_ONLY_ONCE, "connmark", "--mark", *flags & F_MARK);
		if (!strtonum(optarg, &end, &mark, 0, ~0U))
			param_act(P_BAD_VALUE, "connmark", "--mark", optarg);
		if (*end == '/')
			if (!strtonum(end + 1, &end, &mask, 0, ~0U))
				param_act(P_BAD_VALUE, "connmark", "--mark", optarg);
		if (*end != '\0')
			param_act(P_BAD_VALUE, "connmark", "--mark", optarg);

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
connmark_parse(int c, char **argv, int invert, unsigned int *flags,
               const void *entry, struct xt_entry_match **match)
{
	struct xt_connmark_info *markinfo = (struct xt_connmark_info *)(*match)->data;

	switch (c) {
		char *end;
	case '1':
		check_inverse(optarg, &invert, &optind, 0);

		markinfo->mark = strtoul(optarg, &end, 0);
		markinfo->mask = 0xffffffffUL;
		
		if (*end == '/')
			markinfo->mask = strtoul(end+1, &end, 0);

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

static void connmark_mt_check(unsigned int flags)
{
	if (flags == 0)
		exit_error(PARAMETER_PROBLEM,
		           "connmark: The --mark option is required");
}

/* Prints out the matchinfo. */
static void
connmark_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	struct xt_connmark_info *info = (struct xt_connmark_info *)match->data;

	printf("CONNMARK match ");
	if (info->invert)
		printf("!");
	print_mark(info->mark, info->mask);
}

static void
connmark_mt_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_connmark_mtinfo1 *info = (const void *)match->data;

	printf("connmark match ");
	if (info->invert)
		printf("!");
	print_mark(info->mark, info->mask);
}

/* Saves the matchinfo in parsable form to stdout. */
static void connmark_save(const void *ip, const struct xt_entry_match *match)
{
	struct xt_connmark_info *info = (struct xt_connmark_info *)match->data;

	if (info->invert)
		printf("! ");

	printf("--mark ");
	print_mark(info->mark, info->mask);
}

static void
connmark_mt_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_connmark_mtinfo1 *info = (const void *)match->data;

	if (info->invert)
		printf("! ");

	printf("--mark ");
	print_mark(info->mark, info->mask);
}

static struct xtables_match connmark_mt_reg_v0 = {
	.family		= AF_INET,
	.name		= "connmark",
	.revision	= 0,
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_connmark_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_connmark_info)),
	.help		= connmark_mt_help,
	.parse		= connmark_parse,
	.final_check	= connmark_mt_check,
	.print		= connmark_print,
	.save		= connmark_save,
	.extra_opts	= connmark_mt_opts,
};

static struct xtables_match connmark_mt6_reg_v0 = {
	.family		= AF_INET6,
	.name		= "connmark",
	.revision	= 0,
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_connmark_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_connmark_info)),
	.help		= connmark_mt_help,
	.parse		= connmark_parse,
	.final_check	= connmark_mt_check,
	.print		= connmark_print,
	.save		= connmark_save,
	.extra_opts	= connmark_mt_opts,
};

static struct xtables_match connmark_mt_reg = {
	.version        = IPTABLES_VERSION,
	.name           = "connmark",
	.revision       = 1,
	.family         = AF_INET,
	.size           = XT_ALIGN(sizeof(struct xt_connmark_mtinfo1)),
	.userspacesize  = XT_ALIGN(sizeof(struct xt_connmark_mtinfo1)),
	.help           = connmark_mt_help,
	.parse          = connmark_mt_parse,
	.final_check    = connmark_mt_check,
	.print          = connmark_mt_print,
	.save           = connmark_mt_save,
	.extra_opts     = connmark_mt_opts,
};

static struct xtables_match connmark_mt6_reg = {
	.version        = IPTABLES_VERSION,
	.name           = "connmark",
	.revision       = 1,
	.family         = AF_INET6,
	.size           = XT_ALIGN(sizeof(struct xt_connmark_mtinfo1)),
	.userspacesize  = XT_ALIGN(sizeof(struct xt_connmark_mtinfo1)),
	.help           = connmark_mt_help,
	.parse          = connmark_mt_parse,
	.final_check    = connmark_mt_check,
	.print          = connmark_mt_print,
	.save           = connmark_mt_save,
	.extra_opts     = connmark_mt_opts,
};

void _init(void)
{
	xtables_register_match(&connmark_mt_reg_v0);
	xtables_register_match(&connmark_mt6_reg_v0);
	xtables_register_match(&connmark_mt_reg);
	xtables_register_match(&connmark_mt6_reg);
}
