/* Shared library add-on to iptables to add byte tracking support. */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <iptables.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include <linux/netfilter_ipv4/ipt_connbytes.h>

/* Function which prints out usage message. */
static void
help(void)
{
	printf(
"connbytes v%s options:\n"
" [!] --connbytes from:[to]\n"
"				Transfered byte range to match\n"
"\n", IPTABLES_VERSION);
}

static struct option opts[] = {
	{ "connbytes", 1, 0, '1' },
	{0}
};

/* Initialize the match. */
static void
init(struct ipt_entry_match *m, unsigned int *nfcache)
{
	/* Can't cache this */
	*nfcache |= NFC_UNKNOWN;
}

static void
parse_range(const char *arg, struct ipt_connbytes_info *si)
{
	char *colon,*p;

	si->from = strtoul(arg,&colon,10);
	if (*colon != ':') 
		exit_error(PARAMETER_PROBLEM, "Bad range `%s'", arg);
	si->to = strtoul(colon+1,&p,10);
	if (p == colon+1) {
		/* second number omited */
		si->to = 0xffffffff;
	}
	if (si->from > si->to)
		exit_error(PARAMETER_PROBLEM, "%lu should be less than %lu", si->from,si->to);
}

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      unsigned int *nfcache,
      struct ipt_entry_match **match)
{
	struct ipt_connbytes_info *sinfo = (struct ipt_connbytes_info *)(*match)->data;
	unsigned long i;

	switch (c) {
	case '1':
		if (check_inverse(optarg, &invert, optind, 0))
			optind++;

		parse_range(argv[optind-1], sinfo);
		if (invert) {
			i = sinfo->from;
			sinfo->from = sinfo->to;
			sinfo->to = i;
		}
		*flags = 1;
		break;

	default:
		return 0;
	}

	return 1;
}

static void final_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM, "You must specify `--connbytes'");
}

/* Prints out the matchinfo. */
static void
print(const struct ipt_ip *ip,
      const struct ipt_entry_match *match,
      int numeric)
{
	struct ipt_connbytes_info *sinfo = (struct ipt_connbytes_info *)match->data;

	if (sinfo->from > sinfo->to) 
		printf("connbytes ! %lu:%lu ",sinfo->to,sinfo->from);
	else
		printf("connbytes %lu:%lu ",sinfo->from,sinfo->to);
}

/* Saves the matchinfo in parsable form to stdout. */
static void save(const struct ipt_ip *ip, const struct ipt_entry_match *match)
{
	struct ipt_connbytes_info *sinfo = (struct ipt_connbytes_info *)match->data;

	if (sinfo->from > sinfo->to) 
		printf("! --connbytes %lu:%lu ",sinfo->to,sinfo->from);
	else
		printf("--connbytes %lu:%lu ",sinfo->from,sinfo->to);
}

static
struct iptables_match state
= { NULL,
    "connbytes",
    IPTABLES_VERSION,
    IPT_ALIGN(sizeof(struct ipt_connbytes_info)),
    IPT_ALIGN(sizeof(struct ipt_connbytes_info)),
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
	register_match(&state);
}
