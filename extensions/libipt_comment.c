/* Shared library add-on to iptables to add comment match support.
 *
 * ChangeLog
 *     2003-05-13: Brad Fisher <brad@info-link.net>
 *         Initial comment match
 *     2004-05-12: Brad Fisher <brad@info-link.net>
 *         Port to patch-o-matic-ng
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <iptables.h>
#include <linux/netfilter_ipv4/ipt_comment.h>

/* Function which prints out usage message. */
static void
help(void)
{
	printf(
		"COMMENT match options:\n"
		"--comment COMMENT             Attach a comment to a rule\n\n"
		);
}

static struct option opts[] = {
	{ "comment", 1, 0, '1' },
	{0}
};

/* Initialize the match. */
static void
init(struct ipt_entry_match *m, unsigned int *nfcache)
{
	*nfcache |= NFC_UNKNOWN;
}

static void
parse_comment(const unsigned char *s, struct ipt_comment_info *info)
{	
	int slen = strlen(s);

	if (slen >= IPT_MAX_COMMENT_LEN) {
		exit_error(PARAMETER_PROBLEM,
			"COMMENT must be shorter than %i characters", IPT_MAX_COMMENT_LEN);
	}
	strcpy(info->comment, s);
}

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      unsigned int *nfcache,
      struct ipt_entry_match **match)
{
	struct ipt_comment_info *commentinfo = (struct ipt_comment_info *)(*match)->data;

	switch (c) {
	case '1':
		check_inverse(argv[optind-1], &invert, &optind, 0);
		if (invert) {
			exit_error(PARAMETER_PROBLEM,
					"Sorry, you can't have an inverted comment");
		}
		parse_comment(argv[optind-1], commentinfo);
		*flags = 1;
		break;

	default:
		return 0;
	}
	return 1;
}

/* Final check; must have specified --comment. */
static void
final_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM,
			   "COMMENT match: You must specify `--comment'");
}

/* Prints out the matchinfo. */
static void
print(const struct ipt_ip *ip,
      const struct ipt_entry_match *match,
      int numeric)
{
	struct ipt_comment_info *commentinfo = (struct ipt_comment_info *)match->data;

	commentinfo->comment[IPT_MAX_COMMENT_LEN-1] = '\0';
	printf("/* %s */ ", commentinfo->comment);
}

/* Saves the union ipt_matchinfo in parsable form to stdout. */
static void
save(const struct ipt_ip *ip, const struct ipt_entry_match *match)
{
	struct ipt_comment_info *commentinfo = (struct ipt_comment_info *)match->data;

	commentinfo->comment[IPT_MAX_COMMENT_LEN-1] = '\0';
	printf("--comment \"%s\" ", commentinfo->comment);
}

static struct iptables_match comment = {
    NULL,
    "comment",
    IPTABLES_VERSION,
    IPT_ALIGN(sizeof(struct ipt_comment_info)),
    IPT_ALIGN(sizeof(struct ipt_comment_info)),
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
	register_match(&comment);
}
