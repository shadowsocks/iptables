/* Shared library add-on to iptables to add string matching support. 
 * 
 * Copyright (C) 2000 Emmanuel Roger  <winfield@freegates.be>
 *
 * ChangeLog
 *     27.01.2001: Gianni Tedesco <gianni@ecsc.co.uk>
 *             Changed --tos to --string in save(). Also
 *             updated to work with slightly modified
 *             ipt_string_info.
 */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>

#include <iptables.h>
#include <linux/netfilter_ipv4/ipt_string.h>

/* Function which prints out usage message. */
static void
help(void)
{
	printf(
"STRING match v%s options:\n"
"--string [!] string             Match a string in a packet\n",
IPTABLES_VERSION);

	fputc('\n', stdout);
}

static struct option opts[] = {
	{ "string", 1, 0, '1' },
	{0}
};

/* Initialize the match. */
static void
init(struct ipt_entry_match *m, unsigned int *nfcache)
{
	*nfcache |= NFC_UNKNOWN;
}

static void
parse_string(const unsigned char *s, struct ipt_string_info *info)
{	
	int i=0, slen, sindex=0, schar;
	short hex_f = 0, literal_f = 0;
	char hextmp[3];

	slen = strlen(s);

	if (slen == 0) {
		exit_error(PARAMETER_PROBLEM,
			"STRING must contain at least one char");
	}

	while (i < slen) {
		if (s[i] == '\\' && !hex_f) {
			literal_f = 1;
		} else if (s[i] == '\\') {
			exit_error(PARAMETER_PROBLEM,
				"Cannot include literals in hex data");
		} else if (s[i] == '|') {
			if (hex_f)
				hex_f = 0;
			else
				hex_f = 1;
			if (i+1 >= slen)
				break;
			else
				i++;  /* advance to the next character */
		}

		if (literal_f) {
			if (i+1 >= slen) {
				exit_error(PARAMETER_PROBLEM,
					"Bad literal placement at end of string");
			}
			info->string[sindex] = s[i+1];
			i += 2;  /* skip over literal char */
			literal_f = 0;
		} else if (hex_f) {
			if (i+1 >= slen) {
				exit_error(PARAMETER_PROBLEM,
					"Odd number of hex digits");
			}
			if (i+2 >= slen) {
				/* must end with a "|" */
				exit_error(PARAMETER_PROBLEM, "Invalid hex block");
			}
			hextmp[0] = s[i];
			hextmp[1] = s[i+1];
			hextmp[2] = '\0';
			if (! sscanf(hextmp, "%x", &schar))
				exit_error(PARAMETER_PROBLEM,
					"Invalid hex char `%c'", s[i]);
			info->string[sindex] = (char) schar;
			if (s[i+2] == ' ')
				i += 3;  /* spaces included in the hex block */
			else
				i += 2;
		} else {  /* the char is not part of hex data, so just copy */
			info->string[sindex] = s[i];
			i++;
		}
		if (sindex > BM_MAX_NLEN)
			exit_error(PARAMETER_PROBLEM, "STRING too long `%s'", s);
		sindex++;
	}
}

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      unsigned int *nfcache,
      struct ipt_entry_match **match)
{
	struct ipt_string_info *stringinfo = (struct ipt_string_info *)(*match)->data;

	switch (c) {
	case '1':
		check_inverse(optarg, &invert, &optind, 0);
		parse_string(argv[optind-1], stringinfo);
		if (invert)
			stringinfo->invert = 1;
                stringinfo->len=strlen((char *)&stringinfo->string);
		*flags = 1;
		break;

	default:
		return 0;
	}
	return 1;
}

static void
print_string(char string[], int invert, int numeric)
{

	if (invert)
		fputc('!', stdout);
	printf("%s ",string);
}

/* Final check; must have specified --string. */
static void
final_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM,
			   "STRING match: You must specify `--string'");
}

/* Prints out the matchinfo. */
static void
print(const struct ipt_ip *ip,
      const struct ipt_entry_match *match,
      int numeric)
{
	printf("STRING match ");
	print_string(((struct ipt_string_info *)match->data)->string,
		  ((struct ipt_string_info *)match->data)->invert, numeric);
}

/* Saves the union ipt_matchinfo in parsable form to stdout. */
static void
save(const struct ipt_ip *ip, const struct ipt_entry_match *match)
{
	printf("--string ");
	print_string(((struct ipt_string_info *)match->data)->string,
		  ((struct ipt_string_info *)match->data)->invert, 0);
}

static
struct iptables_match string
= { NULL,
    "string",
    IPTABLES_VERSION,
    IPT_ALIGN(sizeof(struct ipt_string_info)),
    IPT_ALIGN(sizeof(struct ipt_string_info)),
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
	register_match(&string);
}
