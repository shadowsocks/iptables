/* ip6tables match extension for limiting packets per destination
 *
 * (C) 2003-2004 by Harald Welte <laforge@netfilter.org>
 *
 * Development of this code was funded by Astaro AG, http://www.astaro.com/
 *
 * Based on ipt_limit.c by
 * Jérôme de Vivie   <devivie@info.enserb.u-bordeaux.fr>
 * Hervé Eychenne    <rv@wallfire.org>
 * 
 * Error corections by nmalykh@bilim.com (22.01.2005)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include <stddef.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_hashlimit.h>

#define XT_HASHLIMIT_BURST	5

/* miliseconds */
#define XT_HASHLIMIT_GCINTERVAL	1000
#define XT_HASHLIMIT_EXPIRE	10000

/* Function which prints out usage message. */
static void hashlimit_help(void)
{
	printf(
"hashlimit v%s options:\n"
"--hashlimit <avg>		max average match rate\n"
"                                [Packets per second unless followed by \n"
"                                /sec /minute /hour /day postfixes]\n"
"--hashlimit-mode <mode>		mode is a comma-separated list of\n"
"					dstip,srcip,dstport,srcport\n"
"--hashlimit-name <name>		name for /proc/net/ipt_hashlimit/\n"
"[--hashlimit-burst <num>]	number to match in a burst, default %u\n"
"[--hashlimit-htable-size <num>]	number of hashtable buckets\n"
"[--hashlimit-htable-max <num>]	number of hashtable entries\n"
"[--hashlimit-htable-gcinterval]	interval between garbage collection runs\n"
"[--hashlimit-htable-expire]	after which time are idle entries expired?\n"
"\n", IPTABLES_VERSION, XT_HASHLIMIT_BURST);
}

static const struct option hashlimit_opts[] = {
	{ "hashlimit", 1, NULL, '%' },
	{ "hashlimit-burst", 1, NULL, '$' },
	{ "hashlimit-htable-size", 1, NULL, '&' },
	{ "hashlimit-htable-max", 1, NULL, '*' },
	{ "hashlimit-htable-gcinterval", 1, NULL, '(' },
	{ "hashlimit-htable-expire", 1, NULL, ')' },
	{ "hashlimit-mode", 1, NULL, '_' },
	{ "hashlimit-name", 1, NULL, '"' },
	{ .name = NULL }
};

static
int parse_rate(const char *rate, u_int32_t *val)
{
	const char *delim;
	u_int32_t r;
	u_int32_t mult = 1;  /* Seconds by default. */

	delim = strchr(rate, '/');
	if (delim) {
		if (strlen(delim+1) == 0)
			return 0;

		if (strncasecmp(delim+1, "second", strlen(delim+1)) == 0)
			mult = 1;
		else if (strncasecmp(delim+1, "minute", strlen(delim+1)) == 0)
			mult = 60;
		else if (strncasecmp(delim+1, "hour", strlen(delim+1)) == 0)
			mult = 60*60;
		else if (strncasecmp(delim+1, "day", strlen(delim+1)) == 0)
			mult = 24*60*60;
		else
			return 0;
	}
	r = atoi(rate);
	if (!r)
		return 0;

	/* This would get mapped to infinite (1/day is minimum they
           can specify, so we're ok at that end). */
	if (r / mult > XT_HASHLIMIT_SCALE)
		exit_error(PARAMETER_PROBLEM, "Rate too fast `%s'\n", rate);

	*val = XT_HASHLIMIT_SCALE * mult / r;
	return 1;
}

/* Initialize the match. */
static void hashlimit_init(struct xt_entry_match *m)
{
	struct xt_hashlimit_info *r = (struct xt_hashlimit_info *)m->data;

	r->cfg.burst = XT_HASHLIMIT_BURST;
	r->cfg.gc_interval = XT_HASHLIMIT_GCINTERVAL;
	r->cfg.expire = XT_HASHLIMIT_EXPIRE;

}


/* Parse a 'mode' parameter into the required bitmask */
static int parse_mode(struct xt_hashlimit_info *r, char *optarg)
{
	char *tok;
	char *arg = strdup(optarg);

	if (!arg)
		return -1;

	r->cfg.mode = 0;

	for (tok = strtok(arg, ",|");
	     tok;
	     tok = strtok(NULL, ",|")) {
		if (!strcmp(tok, "dstip"))
			r->cfg.mode |= XT_HASHLIMIT_HASH_DIP;
		else if (!strcmp(tok, "srcip"))
			r->cfg.mode |= XT_HASHLIMIT_HASH_SIP;
		else if (!strcmp(tok, "srcport"))
			r->cfg.mode |= XT_HASHLIMIT_HASH_SPT;
		else if (!strcmp(tok, "dstport"))
			r->cfg.mode |= XT_HASHLIMIT_HASH_DPT;
		else {
			free(arg);
			return -1;
		}
	}
	free(arg);
	return 0;
}

#define PARAM_LIMIT		0x00000001
#define PARAM_BURST		0x00000002
#define PARAM_MODE		0x00000004
#define PARAM_NAME		0x00000008
#define PARAM_SIZE		0x00000010
#define PARAM_MAX		0x00000020
#define PARAM_GCINTERVAL	0x00000040
#define PARAM_EXPIRE		0x00000080

/* Function which parses command options; returns true if it
   ate an option */
static int
hashlimit_parse(int c, char **argv, int invert, unsigned int *flags,
                const void *entry, struct xt_entry_match **match)
{
	struct xt_hashlimit_info *r = 
			(struct xt_hashlimit_info *)(*match)->data;
	unsigned int num;

	switch(c) {
	case '%':
		param_act(P_ONLY_ONCE, "hashlimit", "--hashlimit",
		          *flags & PARAM_LIMIT);
		if (check_inverse(argv[optind-1], &invert, &optind, 0)) break;
		if (!parse_rate(optarg, &r->cfg.avg))
			exit_error(PARAMETER_PROBLEM,
				   "bad rate `%s'", optarg);
		*flags |= PARAM_LIMIT;
		break;

	case '$':
		param_act(P_ONLY_ONCE, "hashlimit", "--hashlimit-burst",
		          *flags & PARAM_BURST);
		if (check_inverse(argv[optind-1], &invert, &optind, 0)) break;
		if (string_to_number(optarg, 0, 10000, &num) == -1)
			exit_error(PARAMETER_PROBLEM,
				   "bad --hashlimit-burst `%s'", optarg);
		r->cfg.burst = num;
		*flags |= PARAM_BURST;
		break;
	case '&':
		param_act(P_ONLY_ONCE, "hashlimit", "--hashlimit-htable-size",
		          *flags & PARAM_SIZE);
		if (check_inverse(argv[optind-1], &invert, &optind, 0)) break;
		if (string_to_number(optarg, 0, 0xffffffff, &num) == -1)
			exit_error(PARAMETER_PROBLEM,
				"bad --hashlimit-htable-size: `%s'", optarg);
		r->cfg.size = num;
		*flags |= PARAM_SIZE;
		break;
	case '*':
		param_act(P_ONLY_ONCE, "hashlimit", "--hashlimit-htable-max",
		          *flags & PARAM_MAX);
		if (check_inverse(argv[optind-1], &invert, &optind, 0)) break;
		if (string_to_number(optarg, 0, 0xffffffff, &num) == -1)
			exit_error(PARAMETER_PROBLEM,
				"bad --hashlimit-htable-max: `%s'", optarg);
		r->cfg.max = num;
		*flags |= PARAM_MAX;
		break;
	case '(':
		param_act(P_ONLY_ONCE, "hashlimit",
		          "--hashlimit-htable-gcinterval",
		          *flags & PARAM_GCINTERVAL);
		if (check_inverse(argv[optind-1], &invert, &optind, 0)) break;
		if (string_to_number(optarg, 0, 0xffffffff, &num) == -1)
			exit_error(PARAMETER_PROBLEM,
				"bad --hashlimit-htable-gcinterval: `%s'", 
				optarg);
		/* FIXME: not HZ dependent!! */
		r->cfg.gc_interval = num;
		*flags |= PARAM_GCINTERVAL;
		break;
	case ')':
		param_act(P_ONLY_ONCE, "hashlimit",
		          "--hashlimit-htable-expire", *flags & PARAM_EXPIRE);
		if (check_inverse(argv[optind-1], &invert, &optind, 0)) break;
		if (string_to_number(optarg, 0, 0xffffffff, &num) == -1)
			exit_error(PARAMETER_PROBLEM,
				"bad --hashlimit-htable-expire: `%s'", optarg);
		/* FIXME: not HZ dependent */
		r->cfg.expire = num;
		*flags |= PARAM_EXPIRE;
		break;
	case '_':
		param_act(P_ONLY_ONCE, "hashlimit", "--hashlimit-mode",
		          *flags & PARAM_MODE);
		if (check_inverse(argv[optind-1], &invert, &optind, 0)) break;
		if (parse_mode(r, optarg) < 0)
			exit_error(PARAMETER_PROBLEM, 
				   "bad --hashlimit-mode: `%s'\n", optarg);
		*flags |= PARAM_MODE;
		break;
	case '"':
		param_act(P_ONLY_ONCE, "hashlimit", "--hashlimit-name",
		          *flags & PARAM_NAME);
		if (check_inverse(argv[optind-1], &invert, &optind, 0)) break;
		if (strlen(optarg) == 0)
			exit_error(PARAMETER_PROBLEM, "Zero-length name?");
		strncpy(r->name, optarg, sizeof(r->name));
		*flags |= PARAM_NAME;
		break;
	default:
		return 0;
	}

	if (invert)
		exit_error(PARAMETER_PROBLEM,
			   "hashlimit does not support invert");

	return 1;
}

/* Final check; nothing. */
static void hashlimit_check(unsigned int flags)
{
	if (!(flags & PARAM_LIMIT))
		exit_error(PARAMETER_PROBLEM,
				"You have to specify --hashlimit");
	if (!(flags & PARAM_MODE))
		exit_error(PARAMETER_PROBLEM,
				"You have to specify --hashlimit-mode");
	if (!(flags & PARAM_NAME))
		exit_error(PARAMETER_PROBLEM,
				"You have to specify --hashlimit-name");
}

static const struct rates
{
	const char *name;
	u_int32_t mult;
} rates[] = { { "day", XT_HASHLIMIT_SCALE*24*60*60 },
	      { "hour", XT_HASHLIMIT_SCALE*60*60 },
	      { "min", XT_HASHLIMIT_SCALE*60 },
	      { "sec", XT_HASHLIMIT_SCALE } };

static void print_rate(u_int32_t period)
{
	unsigned int i;

	for (i = 1; i < sizeof(rates)/sizeof(struct rates); i++) {
		if (period > rates[i].mult
            || rates[i].mult/period < rates[i].mult%period)
			break;
	}

	printf("%u/%s ", rates[i-1].mult / period, rates[i-1].name);
}

static void print_mode(const struct xt_hashlimit_info *r, char separator)
{
	int prevmode = 0;

	if (r->cfg.mode & XT_HASHLIMIT_HASH_SIP) {
		if (prevmode)
			putchar(separator);
		fputs("srcip", stdout);
		prevmode = 1;
	}
	if (r->cfg.mode & XT_HASHLIMIT_HASH_SPT) {
		if (prevmode)
			putchar(separator);
		fputs("srcport", stdout);
		prevmode = 1;
	}
	if (r->cfg.mode & XT_HASHLIMIT_HASH_DIP) {
		if (prevmode)
			putchar(separator);
		fputs("dstip", stdout);
		prevmode = 1;
	}
	if (r->cfg.mode & XT_HASHLIMIT_HASH_DPT) {
		if (prevmode)
			putchar(separator);
		fputs("dstport", stdout);
	}
	putchar(' ');
}

/* Prints out the matchinfo. */
static void hashlimit_print(const void *ip,
                            const struct xt_entry_match *match, int numeric)
{
	struct xt_hashlimit_info *r = 
		(struct xt_hashlimit_info *)match->data;
	fputs("limit: avg ", stdout); print_rate(r->cfg.avg);
	printf("burst %u ", r->cfg.burst);
	fputs("mode ", stdout);
	print_mode(r, '-');
	if (r->cfg.size)
		printf("htable-size %u ", r->cfg.size);
	if (r->cfg.max)
		printf("htable-max %u ", r->cfg.max);
	if (r->cfg.gc_interval != XT_HASHLIMIT_GCINTERVAL)
		printf("htable-gcinterval %u ", r->cfg.gc_interval);
	if (r->cfg.expire != XT_HASHLIMIT_EXPIRE)
		printf("htable-expire %u ", r->cfg.expire);
}

/* FIXME: Make minimalist: only print rate if not default --RR */
static void hashlimit_save(const void *ip, const struct xt_entry_match *match)
{
	struct xt_hashlimit_info *r = 
		(struct xt_hashlimit_info *)match->data;

	fputs("--hashlimit ", stdout); print_rate(r->cfg.avg);
	if (r->cfg.burst != XT_HASHLIMIT_BURST)
		printf("--hashlimit-burst %u ", r->cfg.burst);

	fputs("--hashlimit-mode ", stdout);
	print_mode(r, ',');
	
	printf("--hashlimit-name %s ", r->name);

	if (r->cfg.size)
		printf("--hashlimit-htable-size %u ", r->cfg.size);
	if (r->cfg.max)
		printf("--hashlimit-htable-max %u ", r->cfg.max);
	if (r->cfg.gc_interval != XT_HASHLIMIT_GCINTERVAL)
		printf("--hashlimit-htable-gcinterval %u", r->cfg.gc_interval);
	if (r->cfg.expire != XT_HASHLIMIT_EXPIRE)
		printf("--hashlimit-htable-expire %u ", r->cfg.expire);
}

static struct xtables_match hashlimit_match = {
	.family		= AF_INET,
	.name		= "hashlimit",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_hashlimit_info)),
	.userspacesize	= offsetof(struct xt_hashlimit_info, hinfo),
	.help		= hashlimit_help,
	.init		= hashlimit_init,
	.parse		= hashlimit_parse,
	.final_check	= hashlimit_check,
	.print		= hashlimit_print,
	.save		= hashlimit_save,
	.extra_opts	= hashlimit_opts,
};

static struct xtables_match hashlimit_match6 = {
	.family		= AF_INET6,
	.name		= "hashlimit",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_hashlimit_info)),
	.userspacesize	= offsetof(struct xt_hashlimit_info, hinfo),
	.help		= hashlimit_help,
	.init		= hashlimit_init,
	.parse		= hashlimit_parse,
	.final_check	= hashlimit_check,
	.print		= hashlimit_print,
	.save		= hashlimit_save,
	.extra_opts	= hashlimit_opts,
};

void _init(void)
{
	xtables_register_match(&hashlimit_match);
	xtables_register_match(&hashlimit_match6);
}
