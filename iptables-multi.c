#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xshared.h"
#include "iptables-multi.h"

static const struct subcommand multi4_subcommands[] = {
	{"iptables",         iptables_main},
	{"main",             iptables_main},
	{"iptables-save",    iptables_save_main},
	{"save",             iptables_save_main},
	{"iptables-restore", iptables_restore_main},
	{"restore",          iptables_restore_main},
	{"iptables-xml",     iptables_xml_main},
	{"xml",              iptables_xml_main},
	{NULL},
};

int main(int argc, char **argv)
{
	return subcmd_main(argc, argv, multi4_subcommands);
}
