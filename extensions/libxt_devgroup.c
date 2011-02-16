/* Shared library add-on to iptables to add devgroup matching support.
 *
 * Copyright (c) 2011 Patrick McHardy <kaber@trash.net>
 */
#include <stdbool.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <getopt.h>
#include <xtables.h>
#include <linux/netfilter/xt_devgroup.h>

static void devgroup_help(void)
{
	printf(
"devgroup match options:\n"
"[!] --src-group value[/mask]	Match device group of incoming device\n"
"[!] --dst-group value[/mask]	Match device group of outgoing device\n"
		);
}

enum {
	XT_DEVGROUP_OPT_SRCGROUP = 1,
	XT_DEVGROUP_OPT_DSTGROUP,
};

static const struct option devgroup_opts[] = {
	{ .name = "src-group", .has_arg = true, .val = XT_DEVGROUP_OPT_SRCGROUP },
	{ .name = "dst-group", .has_arg = true, .val = XT_DEVGROUP_OPT_DSTGROUP },
	XT_GETOPT_TABLEEND,
};

struct devgroupname {
	unsigned int		id;
	char			*name;
	int			len;
	struct devgroupname	*next;
};

/* array of devgroups from /etc/iproute2/group_map */
static struct devgroupname *devgroups;
/* 1 if loading failed */
static int rdberr;

static void load_devgroups(void)
{
	const char* rfnm = "/etc/iproute2/group_map";
	char buf[512];
	FILE *fil;
	char *cur, *nxt;
	int id;
	struct devgroupname *oldnm = NULL, *newnm = NULL;

	fil = fopen(rfnm, "r");
	if (!fil) {
		rdberr = 1;
		return;
	}

	while (fgets(buf, sizeof(buf), fil)) {
		cur = buf;
		while ((*cur == ' ') || (*cur == '\t'))
			cur++;
		if ((*cur == '#') || (*cur == '\n') || (*cur == 0))
			continue;

		/* iproute2 allows hex and dec format */
		errno = 0;
		id = strtoul(cur, &nxt, strncmp(cur, "0x", 2) ? 10 : 16);
		if ((nxt == cur) || errno)
			continue;

		/* same boundaries as in iproute2 */
		if (id < 0 || id > 255)
			continue;
		cur = nxt;

		if (!isspace(*cur))
			continue;
		while ((*cur == ' ') || (*cur == '\t'))
			cur++;
		if ((*cur == '#') || (*cur == '\n') || (*cur == 0))
			continue;
		nxt = cur;
		while ((*nxt != 0) && !isspace(*nxt))
			nxt++;
		if (nxt == cur)
			continue;

		/* found valid data */
		newnm = malloc(sizeof(struct devgroupname));
		if (newnm == NULL) {
			perror("libxt_devgroup: malloc failed");
			exit(1);
		}
		newnm->id = id;
		newnm->len = nxt - cur;
		newnm->name = malloc(newnm->len + 1);
		if (newnm->name == NULL) {
			perror("libxt_devgroup: malloc failed");
			exit(1);
		}
		strncpy(newnm->name, cur, newnm->len);
		newnm->name[newnm->len] = 0;
		newnm->next = NULL;

		if (oldnm)
			oldnm->next = newnm;
		else
			devgroups = newnm;
		oldnm = newnm;
	}

	fclose(fil);
}

/* get devgroup id for name, -1 if error/not found */
static int devgroup_name2id(const char* name)
{
	struct devgroupname* cur;

	if ((devgroups == NULL) && (rdberr == 0))
		load_devgroups();
	cur = devgroups;
	if (cur == NULL)
		return -1;
	while (cur) {
		if (!strncmp(name, cur->name, cur->len + 1))
			return cur->id;
		cur = cur->next;
	}
	return -1;
}

/* get devgroup name for id, NULL if error/not found */
static const char *devgroup_id2name(int id)
{
	struct devgroupname* cur;

	if ((devgroups == NULL) && (rdberr == 0))
		load_devgroups();
	cur = devgroups;
	if (cur == NULL)
		return NULL;
	while (cur) {
		if (id == cur->id)
			return cur->name;
		cur = cur->next;
	}
	return NULL;
}

static int devgroup_parse(int c, char **argv, int invert, unsigned int *flags,
                       const void *entry, struct xt_entry_match **match)
{
	struct xt_devgroup_info *info = (struct xt_devgroup_info *)(*match)->data;
	unsigned int id;
	char *end;

	switch (c) {
	case XT_DEVGROUP_OPT_SRCGROUP:
		xtables_check_inverse(optarg, &invert, &optind, 0, argv);
		end = optarg;
		info->src_group = strtoul(optarg, &end, 0);
		if (end != optarg && (*end == '/' || *end == '\0')) {
			if (*end == '/')
				info->src_mask = strtoul(end+1, &end, 0);
			else
				info->src_mask = 0xffffffff;
			if (*end != '\0' || end == optarg)
				xtables_error(PARAMETER_PROBLEM,
					      "Bad src-group value `%s'",
					      optarg);
		} else {
			id = devgroup_name2id(optarg);
			if (id == -1)
				xtables_error(PARAMETER_PROBLEM,
					      "Device group `%s' not found",
					      optarg);
			info->src_group = id;
			info->src_mask  = 0xffffffff;
		}
		info->flags |= XT_DEVGROUP_MATCH_SRC;
		if (invert)
			info->flags |= XT_DEVGROUP_INVERT_SRC;
		*flags |= c;
		break;
	case XT_DEVGROUP_OPT_DSTGROUP:
		xtables_check_inverse(optarg, &invert, &optind, 0, argv);
		end = optarg;
		info->dst_group = strtoul(optarg, &end, 0);
		if (end != optarg && (*end == '/' || *end == '\0')) {
			if (*end == '/')
				info->dst_mask = strtoul(end+1, &end, 0);
			else
				info->dst_mask = 0xffffffff;
			if (*end != '\0' || end == optarg)
				xtables_error(PARAMETER_PROBLEM,
					      "Bad dst-group value `%s'",
					      optarg);
		} else {
			id = devgroup_name2id(optarg);
			if (id == -1)
				xtables_error(PARAMETER_PROBLEM,
					      "Device group `%s' not found",
					      optarg);
			info->dst_group = id;
			info->dst_mask  = 0xffffffff;
		}
		info->flags |= XT_DEVGROUP_MATCH_DST;
		if (invert)
			info->flags |= XT_DEVGROUP_INVERT_DST;
		*flags |= c;
		break;
	}
	return 1;
}

static void
print_devgroup(unsigned int id, unsigned int mask, int numeric)
{
	const char *name = NULL;

	if (mask != 0xffffffff)
		printf("0x%x/0x%x", id, mask);
	else {
		if (numeric == 0)
			name = devgroup_id2name(id);
		if (name)
			printf("%s", name);
		else
			printf("0x%x", id);
	}
}

static void devgroup_show(const char *pfx, const struct xt_devgroup_info *info,
			  int numeric)
{
	if (info->flags & XT_DEVGROUP_MATCH_SRC) {
		if (info->flags & XT_DEVGROUP_INVERT_SRC)
			printf(" !");
		printf(" %ssrc-group ", pfx);
		print_devgroup(info->src_group, info->src_mask, numeric);
	}

	if (info->flags & XT_DEVGROUP_MATCH_DST) {
		if (info->flags & XT_DEVGROUP_INVERT_DST)
			printf(" !");
		printf(" %sdst-group ", pfx);
		print_devgroup(info->src_group, info->src_mask, numeric);
	}
}

static void devgroup_print(const void *ip, const struct xt_entry_match *match,
                        int numeric)
{
	const struct xt_devgroup_info *info = (const void *)match->data;

	devgroup_show("", info, numeric);
}

static void devgroup_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_devgroup_info *info = (const void *)match->data;

	devgroup_show("--", info, 0);
}

static void devgroup_check(unsigned int flags)
{
	if (!flags)
		xtables_error(PARAMETER_PROBLEM,
			      "devgroup match: You must specify either "
			      "'--src-group' or '--dst-group'");
}

static struct xtables_match devgroup_mt_reg = {
	.name		= "devgroup",
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_UNSPEC,
	.size		= XT_ALIGN(sizeof(struct xt_devgroup_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_devgroup_info)),
	.help		= devgroup_help,
	.parse		= devgroup_parse,
	.final_check	= devgroup_check,
	.print		= devgroup_print,
	.save		= devgroup_save,
	.extra_opts	= devgroup_opts,
};

void _init(void)
{
	xtables_register_match(&devgroup_mt_reg);
}
