/*
 * Shared library add-on to iptables to add early socket matching support.
 *
 * Copyright (C) 2007 BalaBit IT Ltd.
 */
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <xtables.h>
#include <linux/netfilter/xt_socket.h>

static const struct option socket_mt_opts[] = {
	{.name = "transparent", .has_arg = false, .val = 't'},
	XT_GETOPT_TABLEEND,
};

static void socket_mt_help(void)
{
	printf(
		"socket match options:\n"
		"  --transparent    Ignore non-transparent sockets\n\n");
}

static int socket_mt_parse(int c, char **argv, int invert, unsigned int *flags,
			   const void *entry, struct xt_entry_match **match)
{
	struct xt_socket_mtinfo1 *info = (void *)(*match)->data;

	switch (c) {
	case 't':
		info->flags |= XT_SOCKET_TRANSPARENT;
		return true;
	}
	return false;
}

static void
socket_mt_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_socket_mtinfo1 *info = (const void *)match->data;

	if (info->flags & XT_SOCKET_TRANSPARENT)
		printf("--transparent ");
}

static void
socket_mt_print(const void *ip, const struct xt_entry_match *match,
		int numeric)
{
	printf("socket ");
	socket_mt_save(ip, match);
}

static struct xtables_match socket_mt_reg[] = {
	{
		.name          = "socket",
		.revision      = 0,
		.family        = NFPROTO_IPV4,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(0),
		.userspacesize = XT_ALIGN(0),
	},
	{
		.name          = "socket",
		.revision      = 1,
		.family        = NFPROTO_UNSPEC,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(sizeof(struct xt_socket_mtinfo1)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_socket_mtinfo1)),
		.help          = socket_mt_help,
		.parse         = socket_mt_parse,
		.print         = socket_mt_print,
		.save          = socket_mt_save,
		.extra_opts    = socket_mt_opts,
	},
};

void _init(void)
{
	xtables_register_matches(socket_mt_reg, ARRAY_SIZE(socket_mt_reg));
}
