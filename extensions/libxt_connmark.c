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

/* Function which prints out usage message. */
static void
help(void)
{
	printf(
"CONNMARK match v%s options:\n"
"[!] --mark value[/mask]         Match nfmark value with optional mask\n"
"\n",
IPTABLES_VERSION);
}

static const struct option opts[] = {
	{ "mark", 1, 0, '1' },
	{0}
};

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const void *entry,
      unsigned int *nfcache,
      struct xt_entry_match **match)
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

static void
print_mark(unsigned long mark, unsigned long mask, int numeric)
{
	if(mask != 0xffffffffUL)
		printf("0x%lx/0x%lx ", mark, mask);
	else
		printf("0x%lx ", mark);
}

/* Final check; must have specified --mark. */
static void
final_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM,
			   "MARK match: You must specify `--mark'");
}

/* Prints out the matchinfo. */
static void
print(const void *ip,
      const struct xt_entry_match *match,
      int numeric)
{
	struct xt_connmark_info *info = (struct xt_connmark_info *)match->data;

	printf("CONNMARK match ");
	if (info->invert)
		printf("!");
	print_mark(info->mark, info->mask, numeric);
}

/* Saves the matchinfo in parsable form to stdout. */
static void
save(const void *ip, const struct xt_entry_match *match)
{
	struct xt_connmark_info *info = (struct xt_connmark_info *)match->data;

	if (info->invert)
		printf("! ");

	printf("--mark ");
	print_mark(info->mark, info->mask, 0);
}

static struct xtables_match connmark_match = {
	.family		= AF_INET,
	.name		= "connmark",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_connmark_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_connmark_info)),
	.help		= &help,
	.parse		= &parse,
	.final_check	= &final_check,
	.print		= &print,
	.save		= &save,
	.extra_opts	= opts
};

static struct xtables_match connmark_match6 = {
	.family		= AF_INET6,
	.name		= "connmark",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_connmark_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_connmark_info)),
	.help		= &help,
	.parse		= &parse,
	.final_check	= &final_check,
	.print		= &print,
	.save		= &save,
	.extra_opts	= opts
};

void _init(void)
{
	xtables_register_match(&connmark_match);
	xtables_register_match(&connmark_match6);
}
