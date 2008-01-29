/*
 *	libxt_owner - iptables addon for xt_owner
 *
 *	Copyright © CC Computer Consultants GmbH, 2007 - 2008
 *	Jan Engelhardt <jengelh@computergmbh.de>
 */
#include <getopt.h>
#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xtables.h>
#include <linux/netfilter/xt_owner.h>
#include <linux/netfilter_ipv4/ipt_owner.h>
#include <linux/netfilter_ipv6/ip6t_owner.h>

enum {
	FLAG_UID_OWNER     = 1 << 0,
	FLAG_GID_OWNER     = 1 << 1,
	FLAG_SOCKET_EXISTS = 1 << 2,
	FLAG_PID_OWNER     = 1 << 3,
	FLAG_SID_OWNER     = 1 << 4,
	FLAG_COMM          = 1 << 5,
};

static void owner_mt_help_v0(void)
{
#ifdef IPT_OWNER_COMM
	printf(
"owner match options:\n"
"[!] --uid-owner userid       Match local UID\n"
"[!] --gid-owner groupid      Match local GID\n"
"[!] --pid-owner processid    Match local PID\n"
"[!] --sid-owner sessionid    Match local SID\n"
"[!] --cmd-owner name         Match local command name\n"
"NOTE: PID, SID and command matching are broken on SMP\n"
"\n");
#else
	printf(
"owner match options:\n"
"[!] --uid-owner userid       Match local UID\n"
"[!] --gid-owner groupid      Match local GID\n"
"[!] --pid-owner processid    Match local PID\n"
"[!] --sid-owner sessionid    Match local SID\n"
"NOTE: PID and SID matching are broken on SMP\n"
"\n");
#endif /* IPT_OWNER_COMM */
}

static void owner_mt6_help_v0(void)
{
	printf(
"owner match options:\n"
"[!] --uid-owner userid       Match local UID\n"
"[!] --gid-owner groupid      Match local GID\n"
"[!] --pid-owner processid    Match local PID\n"
"[!] --sid-owner sessionid    Match local SID\n"
"NOTE: PID and SID matching are broken on SMP\n"
"\n");
}

static void owner_mt_help(void)
{
	printf(
"owner match options:\n"
"[!] --uid-owner userid[-userid]      Match local UID\n"
"[!] --gid-owner groupid[-groupid]    Match local GID\n"
"[!] --socket-exists                  Match if socket exists\n"
"\n");
}

static const struct option owner_mt_opts_v0[] = {
	{.name = "uid-owner", .has_arg = true, .val = 'u'},
	{.name = "gid-owner", .has_arg = true, .val = 'g'},
	{.name = "pid-owner", .has_arg = true, .val = 'p'},
	{.name = "sid-owner", .has_arg = true, .val = 's'},
#ifdef IPT_OWNER_COMM
	{.name = "cmd-owner", .has_arg = true, .val = 'c'},
#endif
	{ .name = NULL }
};

static const struct option owner_mt6_opts_v0[] = {
	{.name = "uid-owner", .has_arg = true, .val = 'u'},
	{.name = "gid-owner", .has_arg = true, .val = 'g'},
	{.name = "pid-owner", .has_arg = true, .val = 'p'},
	{.name = "sid-owner", .has_arg = true, .val = 's'},
	{ .name = NULL }
};

static const struct option owner_mt_opts[] = {
	{.name = "uid-owner",     .has_arg = true,  .val = 'u'},
	{.name = "gid-owner",     .has_arg = true,  .val = 'g'},
	{.name = "socket-exists", .has_arg = false, .val = 'k'},
	{ .name = NULL }
};

static int
owner_mt_parse_v0(int c, char **argv, int invert, unsigned int *flags,
                  const void *entry, struct xt_entry_match **match)
{
	struct ipt_owner_info *info = (void *)(*match)->data;
	struct passwd *pwd;
	struct group *grp;
	unsigned int id;

	switch (c) {
	case 'u':
		param_act(P_ONLY_ONCE, "owner", "--uid-owner", *flags & FLAG_UID_OWNER);
		if ((pwd = getpwnam(optarg)) != NULL)
			id = pwd->pw_uid;
		else if (!strtonum(optarg, NULL, &id, 0, ~(uid_t)0))
			param_act(P_BAD_VALUE, "owner", "--uid-owner", optarg);
		if (invert)
			info->invert |= IPT_OWNER_UID;
		info->match |= IPT_OWNER_UID;
		info->uid    = id;
		*flags      |= FLAG_UID_OWNER;
		return true;

	case 'g':
		param_act(P_ONLY_ONCE, "owner", "--gid-owner", *flags & FLAG_GID_OWNER);
		if ((grp = getgrnam(optarg)) != NULL)
			id = grp->gr_gid;
		else if (!strtonum(optarg, NULL, &id, 0, ~(gid_t)0))
			param_act(P_BAD_VALUE, "owner", "--gid-owner", optarg);
		if (invert)
			info->invert |= IPT_OWNER_GID;
		info->match |= IPT_OWNER_GID;
		info->gid    = id;
		*flags      |= FLAG_GID_OWNER;
		return true;

	case 'p':
		param_act(P_ONLY_ONCE, "owner", "--pid-owner", *flags & FLAG_PID_OWNER);
		if (!strtonum(optarg, NULL, &id, 0, INT_MAX))
			param_act(P_BAD_VALUE, "owner", "--pid-owner", optarg);
		if (invert)
			info->invert |= IPT_OWNER_PID;
		info->match |= IPT_OWNER_PID;
		info->pid    = id;
		*flags      |= FLAG_PID_OWNER;
		return true;

	case 's':
		param_act(P_ONLY_ONCE, "owner", "--sid-owner", *flags & FLAG_SID_OWNER);
		if (!strtonum(optarg, NULL, &id, 0, INT_MAX))
			param_act(P_BAD_VALUE, "owner", "--sid-value", optarg);
		if (invert)
			info->invert |= IPT_OWNER_SID;
		info->match |= IPT_OWNER_SID;
		info->sid    = id;
		*flags      |= FLAG_SID_OWNER;
		return true;

#ifdef IPT_OWNER_COMM
	case 'c':
		param_act(P_ONLY_ONCE, "owner", "--cmd-owner", *flags & FLAG_COMM);
		if (strlen(optarg) > sizeof(info->comm))
			exit_error(PARAMETER_PROBLEM, "owner match: command "
			           "\"%s\" too long, max. %zu characters",
			           optarg, sizeof(info->comm));

		info->comm[sizeof(info->comm)-1] = '\0';
		strncpy(info->comm, optarg, sizeof(info->comm));

		if (invert)
			info->invert |= IPT_OWNER_COMM;
		info->match |= IPT_OWNER_COMM;
		*flags      |= FLAG_COMM;
		return true;
#endif
	}
	return false;
}

static int
owner_mt6_parse_v0(int c, char **argv, int invert, unsigned int *flags,
                   const void *entry, struct xt_entry_match **match)
{
	struct ip6t_owner_info *info = (void *)(*match)->data;
	struct passwd *pwd;
	struct group *grp;
	unsigned int id;

	switch (c) {
	case 'u':
		param_act(P_ONLY_ONCE, "owner", "--uid-owner",
		          *flags & FLAG_UID_OWNER);
		if ((pwd = getpwnam(optarg)) != NULL)
			id = pwd->pw_uid;
		else if (!strtonum(optarg, NULL, &id, 0, ~(uid_t)0))
			param_act(P_BAD_VALUE, "owner", "--uid-owner", optarg);
		if (invert)
			info->invert |= IP6T_OWNER_UID;
		info->match |= IP6T_OWNER_UID;
		info->uid    = id;
		*flags      |= FLAG_UID_OWNER;
		return true;

	case 'g':
		param_act(P_ONLY_ONCE, "owner", "--gid-owner",
		          *flags & FLAG_GID_OWNER);
		if ((grp = getgrnam(optarg)) != NULL)
			id = grp->gr_gid;
		else if (!strtonum(optarg, NULL, &id, 0, ~(gid_t)0))
			param_act(P_BAD_VALUE, "owner", "--gid-owner", optarg);
		if (invert)
			info->invert |= IP6T_OWNER_GID;
		info->match |= IP6T_OWNER_GID;
		info->gid    = id;
		*flags      |= FLAG_GID_OWNER;
		return true;

	case 'p':
		param_act(P_ONLY_ONCE, "owner", "--pid-owner",
		          *flags & FLAG_PID_OWNER);
		if (!strtonum(optarg, NULL, &id, 0, INT_MAX))
			param_act(P_BAD_VALUE, "owner", "--pid-owner", optarg);
		if (invert)
			info->invert |= IP6T_OWNER_PID;
		info->match |= IP6T_OWNER_PID;
		info->pid    = id;
		*flags      |= FLAG_PID_OWNER;
		return true;

	case 's':
		param_act(P_ONLY_ONCE, "owner", "--sid-owner",
		          *flags & FLAG_SID_OWNER);
		if (!strtonum(optarg, NULL, &id, 0, INT_MAX))
			param_act(P_BAD_VALUE, "owner", "--sid-owner", optarg);
		if (invert)
			info->invert |= IP6T_OWNER_SID;
		info->match |= IP6T_OWNER_SID;
		info->sid    = id;
		*flags      |= FLAG_SID_OWNER;
		return true;
	}
	return false;
}

static void owner_parse_range(const char *s, unsigned int *from,
                              unsigned int *to, const char *opt)
{
	char *end;

	/* 4294967295 is reserved, so subtract one from ~0 */
	if (!strtonum(s, &end, from, 0, (~(uid_t)0) - 1))
		param_act(P_BAD_VALUE, "owner", opt, s);
	*to = *from;
	if (*end == '-' || *end == ':')
		if (!strtonum(end + 1, &end, to, 0, (~(uid_t)0) - 1))
			param_act(P_BAD_VALUE, "owner", opt, s);
	if (*end != '\0')
		param_act(P_BAD_VALUE, "owner", opt, s);
}

static int owner_mt_parse(int c, char **argv, int invert, unsigned int *flags,
                          const void *entry, struct xt_entry_match **match)
{
	struct xt_owner_match_info *info = (void *)(*match)->data;
	struct passwd *pwd;
	struct group *grp;
	unsigned int from, to;

	switch (c) {
	case 'u':
		param_act(P_ONLY_ONCE, "owner", "--uid-owner",
		          *flags & FLAG_UID_OWNER);
		if ((pwd = getpwnam(optarg)) != NULL)
			from = to = pwd->pw_uid;
		else
			owner_parse_range(optarg, &from, &to, "--uid-owner");
		if (invert)
			info->invert |= XT_OWNER_UID;
		info->match  |= XT_OWNER_UID;
		info->uid_min = from;
		info->uid_max = to;
		*flags       |= FLAG_UID_OWNER;
		return true;

	case 'g':
		param_act(P_ONLY_ONCE, "owner", "--gid-owner",
		          *flags & FLAG_GID_OWNER);
		if ((grp = getgrnam(optarg)) != NULL)
			from = to = grp->gr_gid;
		else
			owner_parse_range(optarg, &from, &to, "--gid-owner");
		if (invert)
			info->invert |= XT_OWNER_GID;
		info->match  |= XT_OWNER_GID;
		info->gid_min = from;
		info->gid_max = to;
		*flags      |= FLAG_GID_OWNER;
		return true;

	case 'k':
		param_act(P_ONLY_ONCE, "owner", "--socket-exists",
		          *flags & FLAG_SOCKET_EXISTS);
		if (invert)
			info->invert |= XT_OWNER_SOCKET;
		info->match |= XT_OWNER_SOCKET;
		*flags |= FLAG_SOCKET_EXISTS;
		return true;

	}
	return false;
}

static void owner_mt_check(unsigned int flags)
{
	if (flags == 0)
		exit_error(PARAMETER_PROBLEM, "owner: At least one of "
		           "--uid-owner, --gid-owner or --socket-exists "
		           "is required");
}

static void
owner_mt_print_item_v0(const struct ipt_owner_info *info, const char *label,
                       u_int8_t flag, bool numeric)
{
	if (!(info->match & flag))
		return;
	if (info->invert & flag)
		printf("! ");
	printf(label);

	switch (info->match & flag) {
	case IPT_OWNER_UID:
		if (!numeric) {
			struct passwd *pwd = getpwuid(info->uid);

			if (pwd != NULL && pwd->pw_name != NULL) {
				printf("%s ", pwd->pw_name);
				break;
			}
		}
		printf("%u ", (unsigned int)info->uid);
		break;

	case IPT_OWNER_GID:
		if (!numeric) {
			struct group *grp = getgrgid(info->gid);

			if (grp != NULL && grp->gr_name != NULL) {
				printf("%s ", grp->gr_name);
				break;
			}
		}
		printf("%u ", (unsigned int)info->gid);
		break;

	case IPT_OWNER_PID:
		printf("%u ", (unsigned int)info->pid);
		break;

	case IPT_OWNER_SID:
		printf("%u ", (unsigned int)info->sid);
		break;

#ifdef IPT_OWNER_COMM
	case IPT_OWNER_COMM:
		printf("%.*s ", (int)sizeof(info->comm), info->comm);
		break;
#endif
	}
}

static void
owner_mt6_print_item_v0(const struct ip6t_owner_info *info, const char *label,
                        u_int8_t flag, bool numeric)
{
	if (!(info->match & flag))
		return;
	if (info->invert & flag)
		printf("! ");
	printf(label);

	switch (info->match & flag) {
	case IP6T_OWNER_UID:
		if (!numeric) {
			struct passwd *pwd = getpwuid(info->uid);

			if (pwd != NULL && pwd->pw_name != NULL) {
				printf("%s ", pwd->pw_name);
				break;
			}
		}
		printf("%u ", (unsigned int)info->uid);
		break;

	case IP6T_OWNER_GID:
		if (!numeric) {
			struct group *grp = getgrgid(info->gid);

			if (grp != NULL && grp->gr_name != NULL) {
				printf("%s ", grp->gr_name);
				break;
			}
		}
		printf("%u ", (unsigned int)info->gid);
		break;

	case IP6T_OWNER_PID:
		printf("%u ", (unsigned int)info->pid);
		break;

	case IP6T_OWNER_SID:
		printf("%u ", (unsigned int)info->sid);
		break;
	}
}

static void
owner_mt_print_item(const struct xt_owner_match_info *info, const char *label,
                    u_int8_t flag, bool numeric)
{
	if (!(info->match & flag))
		return;
	if (info->invert & flag)
		printf("! ");
	printf(label);

	switch (info->match & flag) {
	case XT_OWNER_UID:
		if (info->uid_min != info->uid_max) {
			printf("%u-%u ", (unsigned int)info->uid_min,
			       (unsigned int)info->uid_max);
			break;
		} else if (!numeric) {
			const struct passwd *pwd = getpwuid(info->uid_min);

			if (pwd != NULL && pwd->pw_name != NULL) {
				printf("%s ", pwd->pw_name);
				break;
			}
		}
		printf("%u ", (unsigned int)info->uid_min);
		break;

	case XT_OWNER_GID:
		if (info->gid_min != info->gid_max) {
			printf("%u-%u ", (unsigned int)info->gid_min,
			       (unsigned int)info->gid_max);
			break;
		} else if (!numeric) {
			const struct group *grp = getgrgid(info->gid_min);

			if (grp != NULL && grp->gr_name != NULL) {
				printf("%s ", grp->gr_name);
				break;
			}
		}
		printf("%u ", (unsigned int)info->gid_min);
		break;
	}
}

static void
owner_mt_print_v0(const void *ip, const struct xt_entry_match *match,
                  int numeric)
{
	const struct ipt_owner_info *info = (void *)match->data;

	owner_mt_print_item_v0(info, "owner UID match ", IPT_OWNER_UID, numeric);
	owner_mt_print_item_v0(info, "owner GID match ", IPT_OWNER_GID, numeric);
	owner_mt_print_item_v0(info, "owner PID match ", IPT_OWNER_PID, numeric);
	owner_mt_print_item_v0(info, "owner SID match ", IPT_OWNER_SID, numeric);
#ifdef IPT_OWNER_COMM
	owner_mt_print_item_v0(info, "owner CMD match ", IPT_OWNER_COMM, numeric);
#endif
}

static void
owner_mt6_print_v0(const void *ip, const struct xt_entry_match *match,
                   int numeric)
{
	const struct ip6t_owner_info *info = (void *)match->data;

	owner_mt6_print_item_v0(info, "owner UID match ", IPT_OWNER_UID, numeric);
	owner_mt6_print_item_v0(info, "owner GID match ", IPT_OWNER_GID, numeric);
	owner_mt6_print_item_v0(info, "owner PID match ", IPT_OWNER_PID, numeric);
	owner_mt6_print_item_v0(info, "owner SID match ", IPT_OWNER_SID, numeric);
}

static void owner_mt_print(const void *ip, const struct xt_entry_match *match,
                           int numeric)
{
	const struct xt_owner_match_info *info = (void *)match->data;

	owner_mt_print_item(info, "owner socket exists ", XT_OWNER_SOCKET, numeric);
	owner_mt_print_item(info, "owner UID match ",     XT_OWNER_UID,    numeric);
	owner_mt_print_item(info, "owner GID match ",     XT_OWNER_GID,    numeric);
}

static void
owner_mt_save_v0(const void *ip, const struct xt_entry_match *match)
{
	const struct ipt_owner_info *info = (void *)match->data;

	owner_mt_print_item_v0(info, "owner UID match ", IPT_OWNER_UID, true);
	owner_mt_print_item_v0(info, "owner GID match ", IPT_OWNER_GID, true);
	owner_mt_print_item_v0(info, "owner PID match ", IPT_OWNER_PID, true);
	owner_mt_print_item_v0(info, "owner SID match ", IPT_OWNER_SID, true);
#ifdef IPT_OWNER_COMM
	owner_mt_print_item_v0(info, "owner CMD match ", IPT_OWNER_COMM, true);
#endif
}

static void
owner_mt6_save_v0(const void *ip, const struct xt_entry_match *match)
{
	const struct ip6t_owner_info *info = (void *)match->data;

	owner_mt6_print_item_v0(info, "owner UID match ", IPT_OWNER_UID, true);
	owner_mt6_print_item_v0(info, "owner GID match ", IPT_OWNER_GID, true);
	owner_mt6_print_item_v0(info, "owner PID match ", IPT_OWNER_PID, true);
	owner_mt6_print_item_v0(info, "owner SID match ", IPT_OWNER_SID, true);
}

static void owner_mt_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_owner_match_info *info = (void *)match->data;

	owner_mt_print_item(info, "--socket-exists ", XT_OWNER_SOCKET, false);
	owner_mt_print_item(info, "--uid-owner",      XT_OWNER_UID,    false);
	owner_mt_print_item(info, "--gid-owner",      XT_OWNER_GID,    false);
}

static struct xtables_match owner_mt_reg_v0 = {
	.version       = IPTABLES_VERSION,
	.name          = "owner",
	.revision      = 0,
	.family        = AF_INET,
	.size          = XT_ALIGN(sizeof(struct ipt_owner_info)),
	.userspacesize = XT_ALIGN(sizeof(struct ipt_owner_info)),
	.help          = owner_mt_help_v0,
	.parse         = owner_mt_parse_v0,
	.final_check   = owner_mt_check,
	.print         = owner_mt_print_v0,
	.save          = owner_mt_save_v0,
	.extra_opts    = owner_mt_opts_v0,
};

static struct xtables_match owner_mt6_reg_v0 = {
	.version       = IPTABLES_VERSION,
	.name          = "owner",
	.revision      = 0,
	.family        = AF_INET6,
	.size          = XT_ALIGN(sizeof(struct ip6t_owner_info)),
	.userspacesize = XT_ALIGN(sizeof(struct ip6t_owner_info)),
	.help          = owner_mt6_help_v0,
	.parse         = owner_mt6_parse_v0,
	.final_check   = owner_mt_check,
	.print         = owner_mt6_print_v0,
	.save          = owner_mt6_save_v0,
	.extra_opts    = owner_mt6_opts_v0,
};

static struct xtables_match owner_mt_reg = {
	.version       = IPTABLES_VERSION,
	.name          = "owner",
	.revision      = 1,
	.family        = AF_INET,
	.size          = XT_ALIGN(sizeof(struct xt_owner_match_info)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_owner_match_info)),
	.help          = owner_mt_help,
	.parse         = owner_mt_parse,
	.final_check   = owner_mt_check,
	.print         = owner_mt_print,
	.save          = owner_mt_save,
	.extra_opts    = owner_mt_opts,
};

static struct xtables_match owner_mt6_reg = {
	.version       = IPTABLES_VERSION,
	.name          = "owner",
	.revision      = 1,
	.family        = AF_INET6,
	.size          = XT_ALIGN(sizeof(struct xt_owner_match_info)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_owner_match_info)),
	.help          = owner_mt_help,
	.parse         = owner_mt_parse,
	.final_check   = owner_mt_check,
	.print         = owner_mt_print,
	.save          = owner_mt_save,
	.extra_opts    = owner_mt_opts,
};

void _init(void)
{
	xtables_register_match(&owner_mt_reg_v0);
	xtables_register_match(&owner_mt6_reg_v0);
	xtables_register_match(&owner_mt_reg);
	xtables_register_match(&owner_mt6_reg);
}
