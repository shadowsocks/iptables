/* Shared library add-on to iptables to add MAC address support. */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#if defined(__GLIBC__) && __GLIBC__ == 2
#include <net/ethernet.h>
#else
#include <linux/if_ether.h>
#endif
#include <xtables.h>
#include <linux/netfilter/xt_mac.h>

/* Function which prints out usage message. */
static void mac_help(void)
{
	printf(
"MAC v%s options:\n"
" --mac-source [!] XX:XX:XX:XX:XX:XX\n"
"				Match source MAC address\n"
"\n", IPTABLES_VERSION);
}

static const struct option mac_opts[] = {
	{ "mac-source", 1, NULL, '1' },
	{ .name = NULL }
};

static void
parse_mac(const char *mac, struct xt_mac_info *info)
{
	unsigned int i = 0;

	if (strlen(mac) != ETH_ALEN*3-1)
		exit_error(PARAMETER_PROBLEM, "Bad mac address `%s'", mac);

	for (i = 0; i < ETH_ALEN; i++) {
		long number;
		char *end;

		number = strtol(mac + i*3, &end, 16);

		if (end == mac + i*3 + 2
		    && number >= 0
		    && number <= 255)
			info->srcaddr[i] = number;
		else
			exit_error(PARAMETER_PROBLEM,
				   "Bad mac address `%s'", mac);
	}
}

/* Function which parses command options; returns true if it
   ate an option */
static int
mac_parse(int c, char **argv, int invert, unsigned int *flags,
          const void *entry, struct xt_entry_match **match)
{
	struct xt_mac_info *macinfo = (struct xt_mac_info *)(*match)->data;

	switch (c) {
	case '1':
		check_inverse(optarg, &invert, &optind, 0);
		parse_mac(argv[optind-1], macinfo);
		if (invert)
			macinfo->invert = 1;
		*flags = 1;
		break;

	default:
		return 0;
	}

	return 1;
}

static void print_mac(unsigned char macaddress[ETH_ALEN])
{
	unsigned int i;

	printf("%02X", macaddress[0]);
	for (i = 1; i < ETH_ALEN; i++)
		printf(":%02X", macaddress[i]);
	printf(" ");
}

/* Final check; must have specified --mac. */
static void mac_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM,
			   "You must specify `--mac-source'");
}

/* Prints out the matchinfo. */
static void
mac_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	printf("MAC ");

	if (((struct xt_mac_info *)match->data)->invert)
		printf("! ");
	
	print_mac(((struct xt_mac_info *)match->data)->srcaddr);
}

/* Saves the union ipt_matchinfo in parsable form to stdout. */
static void mac_save(const void *ip, const struct xt_entry_match *match)
{
	if (((struct xt_mac_info *)match->data)->invert)
		printf("! ");

	printf("--mac-source ");
	print_mac(((struct xt_mac_info *)match->data)->srcaddr);
}

static struct xtables_match mac_match = {
	.family		= AF_INET,
 	.name		= "mac",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_mac_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_mac_info)),
	.help		= mac_help,
	.parse		= mac_parse,
	.final_check	= mac_check,
	.print		= mac_print,
	.save		= mac_save,
	.extra_opts	= mac_opts,
};

static struct xtables_match mac_match6 = {
	.family		= AF_INET6,
 	.name		= "mac",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_mac_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_mac_info)),
	.help		= mac_help,
	.parse		= mac_parse,
	.final_check	= mac_check,
	.print		= mac_print,
	.save		= mac_save,
	.extra_opts	= mac_opts,
};

void _init(void)
{
	xtables_register_match(&mac_match);
	xtables_register_match(&mac_match6);
}
