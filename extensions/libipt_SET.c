/* Shared library add-on to iptables to add IP set mangling target. */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>

#include <iptables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ip_nat_rule.h>
#include <linux/netfilter_ipv4/ip_set.h>
#include <linux/netfilter_ipv4/ipt_set.h>
#include "../ipset/libipt_set.h"

/* Function which prints out usage message. */
static void help(void)
{
	printf("SET v%s options:\n"
	       " --add-set name[:flags] flags\n"
	       " --del-set name[:flags] flags\n"
	       "		add/del src/dst IP/port from/to named sets,\n"
	       "		where flags are the comma separated list of\n"
	       "		'src' and 'dst'.\n"
	       "\n", IPTABLES_VERSION);
}

static struct option opts[] = {
	{"add-set",   1, 0, '1'},
	{"del-set",   1, 0, '2'},
	{0}
};

/* Initialize the target. */
static void init(struct ipt_entry_target *target, unsigned int *nfcache)
{
	struct ipt_set_info_target *info =
	    (struct ipt_set_info_target *) target->data;

	memset(info, 0, sizeof(struct ipt_set_info_target));
	info->add_set.id = -1;
	info->del_set.id = -1;

	/* Can't cache this */
	*nfcache |= NFC_UNKNOWN;
}

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry, struct ipt_entry_target **target)
{
	struct ipt_set_info_target *myinfo =
	    (struct ipt_set_info_target *) (*target)->data;
	struct ipt_set_info *info;

	switch (c) {
	case '1':		/* --add-set <set>[:<flags>] <flags> */
		info = &myinfo->add_set;

		if (check_inverse(optarg, &invert, NULL, 0))
			exit_error(PARAMETER_PROBLEM,
				   "Unexpected `!' after --add-set");

		if (!argv[optind]
		    || argv[optind][0] == '-' || argv[optind][0] == '!')
			exit_error(PARAMETER_PROBLEM,
				   "--add-set requires two args.");

		parse_pool(argv[optind - 1], info);
		parse_ipflags(argv[optind++], info);
		
		*flags = 1;
		break;
	case '2':		/* --del-set <set>[:<flags>] <flags> */
		info = &myinfo->del_set;

		if (check_inverse(optarg, &invert, NULL, 0))
			exit_error(PARAMETER_PROBLEM,
				   "Unexpected `!' after --del-set");

		if (!argv[optind]
		    || argv[optind][0] == '-' || argv[optind][0] == '!')
			exit_error(PARAMETER_PROBLEM,
				   "--del-set requires two args.");

		parse_pool(argv[optind - 1], info);
		if (parse_ipflags(argv[optind++], info))
			exit_error(PARAMETER_PROBLEM,
				   "Can't use overwrite flag with --del-set.");
		
		*flags = 1;
		break;

	default:
		return 0;
	}
	return 1;
}

/* Final check; must specify at least one. */
static void final_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM,
			   "You must specify either `--add-set' or `--del-set'");
}

static void
print_target(const char *prefix, const struct ipt_set_info *info)
{
	int i;
	char setname[IP_SET_MAXNAMELEN];

	if (info->id >= 0) {
		get_set_byid(setname, info->id);
		printf("%s %s", prefix, setname);
		for (i = 0; i < info->set_level; i++)
			printf("%s%s",
			       i == 0 ? ":" : ",",
			       info->flags[i] & IPSET_SRC ? "src" : "dst");
		for (i = info->set_level; i < info->ip_level; i++)
			printf("%s%s%s",
			       i == info->set_level ? " " : ",",
			       info->flags[i] & IPSET_ADD_OVERWRITE ? "+" : "",
			       info->flags[i] & IPSET_SRC ? "src" : "dst");
		printf(" ");
	}
}

/* Prints out the targinfo. */
static void
print(const struct ipt_ip *ip,
      const struct ipt_entry_target *target, int numeric)
{
	struct ipt_set_info_target *info =
	    (struct ipt_set_info_target *) target->data;

	print_target("add-set", &info->add_set);
	print_target("del-set", &info->del_set);
}

/* Saves the union ipt_targinfo in parsable form to stdout. */
static void
save(const struct ipt_ip *ip, const struct ipt_entry_target *target)
{
	struct ipt_set_info_target *info =
	    (struct ipt_set_info_target *) target->data;

	print_target("--add-set", &info->add_set);
	print_target("--del-set", &info->del_set);
}

static
struct iptables_target ipt_set_target 
= {
	.name		= "SET",
	.version	= IPTABLES_VERSION,
	.size		= IPT_ALIGN(sizeof(struct ipt_set_info_target)),
	.userspacesize	= IPT_ALIGN(sizeof(struct ipt_set_info_target)),
	.help		= &help,
	.init		= &init,
	.parse		= &parse,
	.final_check	= &final_check,
	.print		= &print,
	.save		= &save,
	.extra_opts	= opts
};

void _init(void)
{
	register_target(&ipt_set_target);
}
