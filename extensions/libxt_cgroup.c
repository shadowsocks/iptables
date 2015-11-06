#include <stdio.h>
#include <xtables.h>
#include <linux/netfilter/xt_cgroup.h>

enum {
	O_CGROUP = 0,
};

static void cgroup_help(void)
{
	printf(
"cgroup match options:\n"
"[!] --cgroup fwid  Match cgroup fwid\n");
}

static const struct xt_option_entry cgroup_opts[] = {
	{
		.name = "cgroup",
		.id = O_CGROUP,
		.type = XTTYPE_UINT32,
		.flags = XTOPT_INVERT | XTOPT_MAND | XTOPT_PUT,
		XTOPT_POINTER(struct xt_cgroup_info, id)
	},
	XTOPT_TABLEEND,
};

static void cgroup_parse(struct xt_option_call *cb)
{
	struct xt_cgroup_info *cgroupinfo = cb->data;

	xtables_option_parse(cb);
	if (cb->invert)
		cgroupinfo->invert = true;
}

static void
cgroup_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_cgroup_info *info = (void *) match->data;

	printf(" cgroup %s%u", info->invert ? "! ":"", info->id);
}

static void cgroup_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_cgroup_info *info = (void *) match->data;

	printf("%s --cgroup %u", info->invert ? " !" : "", info->id);
}

static struct xtables_match cgroup_match = {
	.family		= NFPROTO_UNSPEC,
	.name		= "cgroup",
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_cgroup_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_cgroup_info)),
	.help		= cgroup_help,
	.print		= cgroup_print,
	.save		= cgroup_save,
	.x6_parse	= cgroup_parse,
	.x6_options	= cgroup_opts,
};

void _init(void)
{
	xtables_register_match(&cgroup_match);
}
