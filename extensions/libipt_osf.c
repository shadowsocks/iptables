/*
 * libipt_osf.c
 *
 * Copyright (c) 2003 Evgeniy Polyakov <johnpol@2ka.mipt.ru>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/*
 * iptables interface for OS fingerprint matching module.
 */

#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>

#include <iptables.h>
#include <linux/netfilter_ipv4/ipt_osf.h>

static void help(void)
{
	printf("OS fingerprint match v%s options:\n"
		"  --genre [!] string          Match a OS genre bypassive fingerprinting.\n",
		IPTABLES_VERSION);
}


static struct option opts[] = {
	{ .name = "genre",     .has_arg = 1, .flag = 0, .val = '1' },
	{ .name = 0 }
};


static void init(struct ipt_entry_match *m, unsigned int *nfcache)
{
	*nfcache |= NFC_UNKNOWN;
}


static void parse_string(const unsigned char *s, struct ipt_osf_info *info)
{
	if (strlen(s) < MAXGENRELEN) 
		strcpy(info->genre, s);
	else 
		exit_error(PARAMETER_PROBLEM, "Genre string too long `%s' [%d], max=%d", 
				s, strlen(s), MAXGENRELEN);
}

static int parse(int c, char **argv, int invert, unsigned int *flags,
      			const struct ipt_entry *entry,
      			unsigned int *nfcache,
      			struct ipt_entry_match **match)
{
	struct ipt_osf_info *info = (struct ipt_osf_info *)(*match)->data;
	
	switch(c) 
	{
		case '1':
			if (*flags)
				exit_error(PARAMETER_PROBLEM, "Can't specify multiple strings");
			check_inverse(optarg, &invert, &optind, 0);
			parse_string(argv[optind-1], info);
			if (invert)
				info->invert = 1;
			info->len=strlen((char *)info->genre);
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
		exit_error(PARAMETER_PROBLEM, "OS fingerprint match: You must specify `--genre'");
}

static void print(const struct ipt_ip *ip, const struct ipt_entry_match *match, int numeric)
{
	const struct ipt_osf_info *info = (const struct ipt_osf_info*) match->data;

	printf("OS fingerprint match %s%s ", (info->invert) ? "!" : "", info->genre);
}

static void save(const struct ipt_ip *ip, const struct ipt_entry_match *match)
{
	const struct ipt_osf_info *info = (const struct ipt_osf_info*) match->data;

	printf("--genre %s%s ", (info->invert) ? "! ": "", info->genre);
}


static struct iptables_match osf_match = {
    .name          = "osf",
    .version       = IPTABLES_VERSION,
    .size          = IPT_ALIGN(sizeof(struct ipt_osf_info)),
    .userspacesize = IPT_ALIGN(sizeof(struct ipt_osf_info)),
    .help          = &help,
    .init          = &init,
    .parse         = &parse,
    .final_check   = &final_check,
    .print         = &print,
    .save          = &save,
    .extra_opts    = opts
};


void _init(void)
{
	register_match(&osf_match);
}
