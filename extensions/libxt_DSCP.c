/* Shared library add-on to iptables for DSCP
 *
 * (C) 2000- 2002 by Matthew G. Marsh <mgm@paktronix.com>,
 * 		     Harald Welte <laforge@gnumonks.org>
 *
 * This program is distributed under the terms of GNU GPL v2, 1991
 *
 * libipt_DSCP.c borrowed heavily from libipt_TOS.c
 *
 * --set-class added by Iain Barnes
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <xtables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_DSCP.h>

/* This is evil, but it's my code - HW*/
#include "libipt_dscp_helper.c"


static void init(struct xt_entry_target *t)
{
}

static void help(void) 
{
	printf(
"DSCP target options\n"
"  --set-dscp value		Set DSCP field in packet header to value\n"
"  		                This value can be in decimal (ex: 32)\n"
"               		or in hex (ex: 0x20)\n"
"  --set-dscp-class class	Set the DSCP field in packet header to the\n"
"				value represented by the DiffServ class value.\n"
"				This class may be EF,BE or any of the CSxx\n"
"				or AFxx classes.\n"
"\n"
"				These two options are mutually exclusive !\n"
);
}

static const struct option opts[] = {
	{ "set-dscp", 1, NULL, 'F' },
	{ "set-dscp-class", 1, NULL, 'G' },
	{ }
};

static void
parse_dscp(const char *s, struct xt_DSCP_info *dinfo)
{
	unsigned int dscp;
       
	if (string_to_number(s, 0, 255, &dscp) == -1)
		exit_error(PARAMETER_PROBLEM,
			   "Invalid dscp `%s'\n", s);

	if (dscp > XT_DSCP_MAX)
		exit_error(PARAMETER_PROBLEM,
			   "DSCP `%d` out of range\n", dscp);

    	dinfo->dscp = (u_int8_t )dscp;
    	return;
}


static void
parse_class(const char *s, struct xt_DSCP_info *dinfo)
{
	unsigned int dscp = class_to_dscp(s);

	/* Assign the value */
	dinfo->dscp = (u_int8_t)dscp;
}


static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const void *entry,
      struct xt_entry_target **target)
{
	struct xt_DSCP_info *dinfo
		= (struct xt_DSCP_info *)(*target)->data;

	switch (c) {
	case 'F':
		if (*flags)
			exit_error(PARAMETER_PROBLEM,
			           "DSCP target: Only use --set-dscp ONCE!");
		parse_dscp(optarg, dinfo);
		*flags = 1;
		break;
	case 'G':
		if (*flags)
			exit_error(PARAMETER_PROBLEM,
				   "DSCP target: Only use --set-dscp-class ONCE!");
		parse_class(optarg, dinfo);
		*flags = 1;
		break;

	default:
		return 0;
	}

	return 1;
}

static void
final_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM,
		           "DSCP target: Parameter --set-dscp is required");
}

static void
print_dscp(u_int8_t dscp, int numeric)
{
 	printf("0x%02x ", dscp);
}

/* Prints out the targinfo. */
static void
print(const void *ip,
      const struct xt_entry_target *target,
      int numeric)
{
	const struct xt_DSCP_info *dinfo =
		(const struct xt_DSCP_info *)target->data;
	printf("DSCP set ");
	print_dscp(dinfo->dscp, numeric);
}

/* Saves the union ipt_targinfo in parsable form to stdout. */
static void
save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_DSCP_info *dinfo =
		(const struct xt_DSCP_info *)target->data;

	printf("--set-dscp 0x%02x ", dinfo->dscp);
}

static struct xtables_target dscp = { 
	.family		= AF_INET,
	.name		= "DSCP",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_DSCP_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_DSCP_info)),
	.help		= &help,
	.init		= &init,
	.parse		= &parse,
	.final_check	= &final_check,
	.print		= &print,
	.save		= &save,
	.extra_opts	= opts,
};

static struct xtables_target dscp6 = { 
	.family		= AF_INET6,
	.name		= "DSCP",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_DSCP_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_DSCP_info)),
	.help		= &help,
	.init		= &init,
	.parse		= &parse,
	.final_check	= &final_check,
	.print		= &print,
	.save		= &save,
	.extra_opts	= opts,
};

void _init(void)
{
	xtables_register_target(&dscp);
	xtables_register_target(&dscp6);
}
