/* Shared library add-on to iptables to add IP address set matching. */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>
#include <errno.h>

#include <iptables.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include <linux/netfilter_ipv4/ipt_set.h>
#include "../ipset/libipt_set.h"

/* Function which prints out usage message. */
static void help(void)
{
	printf("set v%s options:\n"
	       " [!] --set     name[:flags] flags\n"
	       "		'name' is the set name from to match.\n" 
	       "		'flags' are the comma separated list of\n"
	       "		'src' and 'dst'.\n"
	       "\n", IPTABLES_VERSION);
}

static struct option opts[] = {
	{"set", 1, 0, '1'},
	{0}
};

/* Initialize the match. */
static void init(struct ipt_entry_match *match, unsigned int *nfcache)
{
	struct ipt_set_info_match *info = 
		(struct ipt_set_info_match *) match->data;
	

	memset(info, 0, sizeof(struct ipt_set_info_match));
	info->match.id = -1;

	/* Can't cache this - XXX */
	*nfcache |= NFC_UNKNOWN;
}

/* Function which parses command options; returns true if it ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      unsigned int *nfcache, struct ipt_entry_match **match)
{
	struct ipt_set_info_match *myinfo = 
		(struct ipt_set_info_match *) (*match)->data;
	struct ipt_set_info *info = &myinfo->match;

	switch (c) {
	case '1':		/* --set <set>[:<flags>] <flags> */
		check_inverse(optarg, &invert, &optind, 0);
		if (invert)
			info->flags[0] |= IPSET_MATCH_INV;

		if (!argv[optind]
		    || argv[optind][0] == '-' || argv[optind][0] == '!')
			exit_error(PARAMETER_PROBLEM,
				   "--set requires two args.");

		parse_pool(argv[optind - 1], info);
		if (parse_ipflags(argv[optind++], info))
			exit_error(PARAMETER_PROBLEM,
				   "Can't use overwrite flag with --set.");
		
		*flags = 1;
		break;

	default:
		return 0;
	}

	return 1;
}

/* Final check; must have specified --set. */
static void final_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM,
			   "You must specify either `--set'");
}

static void
print_match(const char *prefix, const struct ipt_set_info *info)
{
	int i;
	char setname[IP_SET_MAXNAMELEN];

	if (info->id >= 0) {
		get_set_byid(setname, info->id);
		printf("%s%s %s", 
		       (info->flags[0] & IPSET_MATCH_INV) ? "!" : "",
		       prefix,
		       setname); 
		for (i = 0; i < info->set_level; i++)
			printf("%s%s",
			       i == 0 ? ":" : ",",
			       info->flags[i] & IPSET_SRC ? "src" : "dst");
		for (i = info->set_level; i < info->ip_level; i++)
			printf("%s%s",
			       i == info->set_level ? " " : ",",
			       info->flags[i] & IPSET_SRC ? "src" : "dst");
		printf(" ");
	}
}

/* Prints out the matchinfo. */
static void
print(const struct ipt_ip *ip,
      const struct ipt_entry_match *match, int numeric)
{
	struct ipt_set_info_match *info = 
		(struct ipt_set_info_match *) match->data;

	print_match("set", &info->match);
}

/* Saves the matchinfo in parsable form to stdout. */
static void save(const struct ipt_ip *ip,
		 const struct ipt_entry_match *match)
{
	struct ipt_set_info_match *info = 
		(struct ipt_set_info_match *) match->data;

	print_match("--set", &info->match);
}

static
struct iptables_match set = { NULL,
	.name		= "set",
	.version	= IPTABLES_VERSION,
	.size		= IPT_ALIGN(sizeof(struct ipt_set_info_match)),
	.userspacesize	= IPT_ALIGN(sizeof(struct ipt_set_info_match)),
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
	register_match(&set);
}
