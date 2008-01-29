/* Shared library add-on to iptables to add packet length matching support. */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <xtables.h>
#include <linux/netfilter/xt_length.h>

/* Function which prints out usage message. */
static void length_help(void)
{
	printf(
"length v%s options:\n"
"[!] --length length[:length]    Match packet length against value or range\n"
"                                of values (inclusive)\n",
IPTABLES_VERSION);

}
  
static const struct option length_opts[] = {
	{ "length", 1, NULL, '1' },
	{ .name = NULL }
};

static u_int16_t
parse_length(const char *s)
{
	unsigned int len;
	
	if (string_to_number(s, 0, 0xFFFF, &len) == -1)
		exit_error(PARAMETER_PROBLEM, "length invalid: `%s'\n", s);
	else
		return (u_int16_t )len;
}

/* If a single value is provided, min and max are both set to the value */
static void
parse_lengths(const char *s, struct xt_length_info *info)
{
	char *buffer;
	char *cp;

	buffer = strdup(s);
	if ((cp = strchr(buffer, ':')) == NULL)
		info->min = info->max = parse_length(buffer);
	else {
		*cp = '\0';
		cp++;

		info->min = buffer[0] ? parse_length(buffer) : 0;
		info->max = cp[0] ? parse_length(cp) : 0xFFFF;
	}
	free(buffer);
	
	if (info->min > info->max)
		exit_error(PARAMETER_PROBLEM,
		           "length min. range value `%u' greater than max. "
		           "range value `%u'", info->min, info->max);
	
}

/* Function which parses command options; returns true if it
   ate an option */
static int
length_parse(int c, char **argv, int invert, unsigned int *flags,
             const void *entry, struct xt_entry_match **match)
{
	struct xt_length_info *info = (struct xt_length_info *)(*match)->data;

	switch (c) {
		case '1':
			if (*flags)
				exit_error(PARAMETER_PROBLEM,
				           "length: `--length' may only be "
				           "specified once");
			check_inverse(optarg, &invert, &optind, 0);
			parse_lengths(argv[optind-1], info);
			if (invert)
				info->invert = 1;
			*flags = 1;
			break;
			
		default:
			return 0;
	}
	return 1;
}

/* Final check; must have specified --length. */
static void length_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM,
			   "length: You must specify `--length'");
}

/* Common match printing code. */
static void
print_length(struct xt_length_info *info)
{
	if (info->invert)
		printf("! ");
	
	if (info->max == info->min)
		printf("%u ", info->min);
	else
		printf("%u:%u ", info->min, info->max);
}

/* Prints out the matchinfo. */
static void
length_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	printf("length ");
	print_length((struct xt_length_info *)match->data);
}

/* Saves the union ipt_matchinfo in parsable form to stdout. */
static void length_save(const void *ip, const struct xt_entry_match *match)
{
	printf("--length ");
	print_length((struct xt_length_info *)match->data);
}

static struct xtables_match length_match = {
	.family		= AF_INET,
	.name		= "length",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_length_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_length_info)),
	.help		= length_help,
	.parse		= length_parse,
	.final_check	= length_check,
	.print		= length_print,
	.save		= length_save,
	.extra_opts	= length_opts,
};

static struct xtables_match length_match6 = {
	.family		= AF_INET6,
	.name		= "length",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_length_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_length_info)),
	.help		= length_help,
	.parse		= length_parse,
	.final_check	= length_check,
	.print		= length_print,
	.save		= length_save,
	.extra_opts	= length_opts,
};

void _init(void)
{
	xtables_register_match(&length_match);
	xtables_register_match(&length_match6);
}
