#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xshared.h"
#include "ip6tables-multi.h"

static const struct subcommand multi6_subcommands[] = {
	{"ip6tables",         ip6tables_main},
	{"main",              ip6tables_main},
	{"ip6tables-save",    ip6tables_save_main},
	{"save",              ip6tables_save_main},
	{"ip6tables-restore", ip6tables_restore_main},
	{"restore",           ip6tables_restore_main},
	{NULL},
};

int main(int argc, char **argv)
{
	return subcmd_main(argc, argv, multi6_subcommands);
}
