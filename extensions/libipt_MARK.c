/* Shared library add-on to iptables to add MARK target support. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <iptables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
/* For 64bit kernel / 32bit userspace */
#include "../include/linux/netfilter_ipv4/ipt_MARK.h"

/* Function which prints out usage message. */
static void
help(void)
{
	printf(
"MARK target v%s options:\n"
"  --set-mark value                   Set nfmark value\n"
"\n",
IPTABLES_VERSION);
}

static struct option opts[] = {
	{ "set-mark", 1, 0, '1' },
	{ 0 }
};

/* Initialize the target. */
static void
init(struct ipt_entry_target *t, unsigned int *nfcache)
{
}

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      struct ipt_entry_target **target)
{
	struct ipt_mark_target_info *markinfo
		= (struct ipt_mark_target_info *)(*target)->data;

	switch (c) {
	case '1':
#ifdef KERNEL_64_USERSPACE_32
		if (string_to_number_ll(optarg, 0, 0, 
				     &markinfo->mark))
#else
		if (string_to_number_l(optarg, 0, 0, 
				     &markinfo->mark))
#endif
			exit_error(PARAMETER_PROBLEM, "Bad MARK value `%s'", optarg);
		if (*flags)
			exit_error(PARAMETER_PROBLEM,
			           "MARK target: Can't specify --set-mark twice");
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
		           "MARK target: Parameter --set-mark is required");
}

#ifdef KERNEL_64_USERSPACE_32
static void
print_mark(unsigned long long mark)
{
	printf("0x%llx ", mark);
}
#else
static void
print_mark(unsigned long mark)
{
	printf("0x%lx ", mark);
}
#endif

/* Prints out the targinfo. */
static void
print(const struct ipt_ip *ip,
      const struct ipt_entry_target *target,
      int numeric)
{
	const struct ipt_mark_target_info *markinfo =
		(const struct ipt_mark_target_info *)target->data;
	printf("MARK set ");
	print_mark(markinfo->mark);
}

/* Saves the union ipt_targinfo in parsable form to stdout. */
static void
save(const struct ipt_ip *ip, const struct ipt_entry_target *target)
{
	const struct ipt_mark_target_info *markinfo =
		(const struct ipt_mark_target_info *)target->data;

	printf("--set-mark ");
	print_mark(markinfo->mark);
}

static
struct iptables_target mark = {
	.next		= NULL,
	.name		= "MARK",
	.version	= IPTABLES_VERSION,
	.size		= IPT_ALIGN(sizeof(struct ipt_mark_target_info)),
	.userspacesize	= IPT_ALIGN(sizeof(struct ipt_mark_target_info)),
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
	register_target(&mark);
}
