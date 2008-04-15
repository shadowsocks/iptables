/* Shared library add-on to iptables to add addrtype matching support 
 * 
 * This program is released under the terms of GNU GPL */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <iptables.h>

#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_addrtype.h>

/* from linux/rtnetlink.h, must match order of enumeration */
static const char *const rtn_names[] = {
	"UNSPEC",
	"UNICAST",
	"LOCAL",
	"BROADCAST",
	"ANYCAST",
	"MULTICAST",
	"BLACKHOLE",
	"UNREACHABLE",
	"PROHIBIT",
	"THROW",
	"NAT",
	"XRESOLVE",
	NULL
};

static void addrtype_help_types(void)
{
	int i;

	for (i = 0; rtn_names[i]; i++)
		printf("                                %s\n", rtn_names[i]);
}

static void addrtype_help(void)
{
	printf(
"Address type match options:\n"
" [!] --src-type type[,...]      Match source address type\n"
" [!] --dst-type type[,...]      Match destination address type\n"
"\n"
"Valid types:           \n");
	addrtype_help_types();
}

static int
parse_type(const char *name, size_t len, u_int16_t *mask)
{
	int i;

	for (i = 0; rtn_names[i]; i++)
		if (strncasecmp(name, rtn_names[i], len) == 0) {
			/* build up bitmask for kernel module */
			*mask |= (1 << i);
			return 1;
		}

	return 0;
}

static void parse_types(const char *arg, u_int16_t *mask)
{
	const char *comma;

	while ((comma = strchr(arg, ',')) != NULL) {
		if (comma == arg || !parse_type(arg, comma-arg, mask))
			exit_error(PARAMETER_PROBLEM,
			           "addrtype: bad type `%s'", arg);
		arg = comma + 1;
	}

	if (strlen(arg) == 0 || !parse_type(arg, strlen(arg), mask))
		exit_error(PARAMETER_PROBLEM, "addrtype: bad type `%s'", arg);
}
	
#define IPT_ADDRTYPE_OPT_SRCTYPE	0x1
#define IPT_ADDRTYPE_OPT_DSTTYPE	0x2

static int
addrtype_parse(int c, char **argv, int invert, unsigned int *flags,
               const void *entry, struct xt_entry_match **match)
{
	struct ipt_addrtype_info *info =
		(struct ipt_addrtype_info *) (*match)->data;

	switch (c) {
	case '1':
		if (*flags&IPT_ADDRTYPE_OPT_SRCTYPE)
			exit_error(PARAMETER_PROBLEM,
			           "addrtype: can't specify src-type twice");
		check_inverse(optarg, &invert, &optind, 0);
		parse_types(argv[optind-1], &info->source);
		if (invert)
			info->invert_source = 1;
		*flags |= IPT_ADDRTYPE_OPT_SRCTYPE;
		break;
	case '2':
		if (*flags&IPT_ADDRTYPE_OPT_DSTTYPE)
			exit_error(PARAMETER_PROBLEM,
			           "addrtype: can't specify dst-type twice");
		check_inverse(optarg, &invert, &optind, 0);
		parse_types(argv[optind-1], &info->dest);
		if (invert)
			info->invert_dest = 1;
		*flags |= IPT_ADDRTYPE_OPT_DSTTYPE;
		break;
	default:
		return 0;
	}
	
	return 1;
}

static void addrtype_check(unsigned int flags)
{
	if (!(flags & (IPT_ADDRTYPE_OPT_SRCTYPE|IPT_ADDRTYPE_OPT_DSTTYPE)))
		exit_error(PARAMETER_PROBLEM,
			   "addrtype: you must specify --src-type or --dst-type");
}

static void print_types(u_int16_t mask)
{
	const char *sep = "";
	int i;

	for (i = 0; rtn_names[i]; i++)
		if (mask & (1 << i)) {
			printf("%s%s", sep, rtn_names[i]);
			sep = ",";
		}

	printf(" ");
}

static void addrtype_print(const void *ip, const struct xt_entry_match *match,
                           int numeric)
{
	const struct ipt_addrtype_info *info = 
		(struct ipt_addrtype_info *) match->data;

	printf("ADDRTYPE match ");
	if (info->source) {
		printf("src-type ");
		if (info->invert_source)
			printf("!");
		print_types(info->source);
	}
	if (info->dest) {
		printf("dst-type ");
		if (info->invert_dest)
			printf("!");
		print_types(info->dest);
	}
}

static void addrtype_save(const void *ip, const struct xt_entry_match *match)
{
	const struct ipt_addrtype_info *info =
		(struct ipt_addrtype_info *) match->data;

	if (info->source) {
		printf("--src-type ");
		if (info->invert_source)
			printf("! ");
		print_types(info->source);
	}
	if (info->dest) {
		printf("--dst-type ");
		if (info->invert_dest)
			printf("! ");
		print_types(info->dest);
	}
}

static const struct option addrtype_opts[] = {
	{ "src-type", 1, NULL, '1' },
	{ "dst-type", 1, NULL, '2' },
	{ .name = NULL }
};

static struct xtables_match addrtype_mt_reg = {
	.name 		= "addrtype",
	.version 	= XTABLES_VERSION,
	.family		= PF_INET,
	.size 		= XT_ALIGN(sizeof(struct ipt_addrtype_info)),
	.userspacesize 	= XT_ALIGN(sizeof(struct ipt_addrtype_info)),
	.help 		= addrtype_help,
	.parse 		= addrtype_parse,
	.final_check 	= addrtype_check,
	.print 		= addrtype_print,
	.save 		= addrtype_save,
	.extra_opts 	= addrtype_opts,
};


void _init(void) 
{
	xtables_register_match(&addrtype_mt_reg);
}
