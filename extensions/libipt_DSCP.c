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

#include <iptables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_DSCP.h>


/* see http://www.iana.org/assignments/dscp-registry */

static struct ds_class 
{
	char *class;
	unsigned int dscp;
} ds_classes[] = 
{
	{ "CS0",   0 },
	{ "CS1",  0x08 },
	{ "CS2",  0x10 },
	{ "CS3",  0x18 },
	{ "CS3",  0x18 },
	{ "CS4",  0x20 },
	{ "CS5",  0x28 },
	{ "CS6",  0x30 },
	{ "CS6",  0x38 },
	{ "BE",    0 },
	{ "AF11", 0x0a },
	{ "AF12", 0x0c },
	{ "AF13", 0x0e },
	{ "AF21", 0x12 },
	{ "AF22", 0x14 },
	{ "AF23", 0x16 },
	{ "AF31", 0x1a },
	{ "AF32", 0x1c },
	{ "AF33", 0x1e },
	{ "AF41", 0x22 },
	{ "AF42", 0x24 },
	{ "AF43", 0x26 },
	{ "EF",   0x2e }
};

static void init(struct ipt_entry_target *t, unsigned int *nfcache) 
{
}

static void help(void) 
{
	printf(
"DSCP target options\n"
"  --set-dscp value		Set DSCP field in packet header to value\n"
"  		                This value can be in decimal (ex: 32)\n"
"               		or in hex (ex: 0x20)\n"
"  --set-class class		Set the DSCP field in packet header to the value\n"
"				represented by the DiffServ class value.\n"
"				This class may be EF,BE or any of the CSxx "
"				or AFxx classes.\n"
"\n"
"				These two options are mutually exclusive !\n"
);
}

static struct option opts[] = {
	{ "set-dscp", 1, 0, 'F' },
	{ "set-class", 1, 0, 'G' },
	{ 0 }
};

static void
parse_dscp(const unsigned char *s, struct ipt_DSCP_info *dinfo)
{
	unsigned int dscp;
       
	if (string_to_number(s, 0, 255, &dscp) == -1)
		exit_error(PARAMETER_PROBLEM,
			   "Invalid dscp `%s'\n", s);

	if (dscp > IPT_DSCP_MAX)
		exit_error(PARAMETER_PROBLEM,
			   "DSCP `%d` out of range\n", dscp);

    	dinfo->dscp = (u_int8_t )dscp;
    	return;
}


static void
parse_class(const unsigned char *s, struct ipt_DSCP_info *dinfo)
{
	int i;

	for (i = 0; i < sizeof(ds_classes) / sizeof(struct ds_class); i++) {
		if (!strncasecmp(s, ds_classes[i].class, 
				strlen(ds_classes[i].class))) {
			dinfo->dscp = (u_int8_t)ds_classes[i].dscp;
			return;
		}
	}

	exit_error(PARAMETER_PROBLEM, "Invalid DSCP class value '%s'", s);
}


static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      struct ipt_entry_target **target)
{
	struct ipt_DSCP_info *dinfo
		= (struct ipt_DSCP_info *)(*target)->data;

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
				   "DSCP target: Only use --set-class ONCE!");
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
print(const struct ipt_ip *ip,
      const struct ipt_entry_target *target,
      int numeric)
{
	const struct ipt_DSCP_info *dinfo =
		(const struct ipt_DSCP_info *)target->data;
	printf("DSCP set ");
	print_dscp(dinfo->dscp, numeric);
}

/* Saves the union ipt_targinfo in parsable form to stdout. */
static void
save(const struct ipt_ip *ip, const struct ipt_entry_target *target)
{
	const struct ipt_DSCP_info *dinfo =
		(const struct ipt_DSCP_info *)target->data;

	printf("--set-dscp 0x%02x ", dinfo->dscp);
}

static
struct iptables_target dscp
= { NULL,
    "DSCP",
    IPTABLES_VERSION,
    IPT_ALIGN(sizeof(struct ipt_DSCP_info)),
    IPT_ALIGN(sizeof(struct ipt_DSCP_info)),
    &help,
    &init,
    &parse,
    &final_check,
    &print,
    &save,
    opts
};

void _init(void)
{
	register_target(&dscp);
}
