#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xshared.h"

#include "xtables-multi.h"

static const struct subcommand multi_subcommands[] = {
	{"iptables-xml",		iptables_xml_main},
	{"xml",				iptables_xml_main},
	{"iptables",			xtables_ip4_main},
	{"iptables-compat",		xtables_ip4_main},
	{"main4",			xtables_ip4_main},
	{"save4",			xtables_ip4_save_main},
	{"restore4",			xtables_ip4_restore_main},
	{"iptables-save",		xtables_ip4_save_main},
	{"iptables-restore",		xtables_ip4_restore_main},
	{"iptables-compat-save",	xtables_ip4_save_main},
	{"iptables-compat-restore",	xtables_ip4_restore_main},
	{"ip6tables",			xtables_ip6_main},
	{"ip6tables-compat",		xtables_ip6_main},
	{"main6",			xtables_ip6_main},
	{"save6",			xtables_ip6_save_main},
	{"restore6",			xtables_ip6_restore_main},
	{"ip6tables-save",		xtables_ip6_save_main},
	{"ip6tables-restore",		xtables_ip6_restore_main},
	{"ip6tables-compat-save",	xtables_ip6_save_main},
	{"ip6tables-compat-restore",	xtables_ip6_restore_main},
	{"arptables",			xtables_arp_main},
	{"arptables-compat",		xtables_arp_main},
	{"ebtables-compat",		xtables_eb_main},
	{"xtables-config",		xtables_config_main},
	{"xtables-events",		xtables_events_main},
	{NULL},
};

int main(int argc, char **argv)
{
	return subcmd_main(argc, argv, multi_subcommands);
}
