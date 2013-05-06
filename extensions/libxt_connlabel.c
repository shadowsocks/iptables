#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <xtables.h>
#include <linux/netfilter/xt_connlabel.h>

enum {
	O_LABEL = 0,
	O_SET = 1,
};

#define CONNLABEL_CFG "/etc/xtables/connlabel.conf"

static void connlabel_mt_help(void)
{
	puts(
"connlabel match options:\n"
"[!] --label name     Match if label has been set on connection\n"
"    --set            Set label on connection");
}

static const struct xt_option_entry connlabel_mt_opts[] = {
	{.name = "label", .id = O_LABEL, .type = XTTYPE_STRING,
	 .min = 1, .flags = XTOPT_MAND|XTOPT_INVERT},
	{.name = "set", .id = O_SET, .type = XTTYPE_NONE},
	XTOPT_TABLEEND,
};

static int
xtables_parse_connlabel_numerical(const char *s, char **end)
{
	uintmax_t value;

	if (!xtables_strtoul(s, end, &value, 0, XT_CONNLABEL_MAXBIT))
		return -1;
	return value;
}

static bool is_space_posix(int c)
{
	return c == ' ' || c == '\f' || c == '\r' || c == '\t' || c == '\v';
}

static char * trim_label(char *label)
{
	char *end;

	while (is_space_posix(*label))
		label++;
	end = strchr(label, '\n');
	if (end)
		*end = 0;
	else
		end = strchr(label, '\0');
	end--;

	while (is_space_posix(*end) && end > label) {
		*end = 0;
		end--;
	}

	return *label ? label : NULL;
}

static void
xtables_get_connlabel(uint16_t bit, char *buf, size_t len)
{
	FILE *fp = fopen(CONNLABEL_CFG, "r");
	char label[1024];
	char *end;

	if (!fp)
		goto error;

	while (fgets(label, sizeof(label), fp)) {
		int tmp;

		if (label[0] == '#')
			continue;
		tmp = xtables_parse_connlabel_numerical(label, &end);
		if (tmp < 0 || tmp < (int) bit)
			continue;
		if (tmp > (int) bit)
			break;

		end = trim_label(end);
		if (!end)
			continue;
		snprintf(buf, len, "%s", end);
		fclose(fp);
		return;
	}
	fclose(fp);
 error:
	snprintf(buf, len, "%u", (unsigned int) bit);
}


static uint16_t xtables_parse_connlabel(const char *s)
{
	FILE *fp = fopen(CONNLABEL_CFG, "r");
	char label[1024];
	char *end;
	int bit;

	if (!fp)
		xtables_error(PARAMETER_PROBLEM, "label '%s': could not open '%s': %s",
						s, CONNLABEL_CFG, strerror(errno));

	while (fgets(label, sizeof(label), fp)) {
		if (label[0] == '#' || !strstr(label, s))
			continue;
		bit = xtables_parse_connlabel_numerical(label, &end);
		if (bit < 0)
			continue;

		end = trim_label(end);
		if (!end)
			continue;
		if (strcmp(end, s) == 0) {
			fclose(fp);
			return bit;
		}
	}
	fclose(fp);
	xtables_error(PARAMETER_PROBLEM, "label '%s' not found in config file %s",
					s, CONNLABEL_CFG);
}

static void connlabel_mt_parse(struct xt_option_call *cb)
{
	struct xt_connlabel_mtinfo *info = cb->data;
	int tmp;

	xtables_option_parse(cb);

	switch (cb->entry->id) {
	case O_LABEL:
		tmp = xtables_parse_connlabel_numerical(cb->arg, NULL);
		info->bit = tmp < 0 ? xtables_parse_connlabel(cb->arg) : tmp;

		if (cb->invert)
			info->options |= XT_CONNLABEL_OP_INVERT;
		break;
	case O_SET:
		info->options |= XT_CONNLABEL_OP_SET;
		break;
	}

}

static void
connlabel_mt_print_op(const struct xt_connlabel_mtinfo *info, const char *prefix)
{
	if (info->options & XT_CONNLABEL_OP_SET)
		printf(" %sset", prefix);
}

static void
connlabel_mt_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_connlabel_mtinfo *info = (const void *)match->data;
	char buf[1024];

	printf(" connlabel");
	if (info->options & XT_CONNLABEL_OP_INVERT)
		printf(" !");
	if (numeric) {
		printf(" %u", info->bit);
	} else {
		xtables_get_connlabel(info->bit, buf, sizeof(buf));
		printf(" '%s'", buf);
	}
	connlabel_mt_print_op(info, "");
}

static void
connlabel_mt_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_connlabel_mtinfo *info = (const void *)match->data;
	char buf[1024];

	if (info->options & XT_CONNLABEL_OP_INVERT)
		printf(" !");

	xtables_get_connlabel(info->bit, buf, sizeof(buf));
	printf(" --label \"%s\"", buf);

	connlabel_mt_print_op(info, "--");
}

static struct xtables_match connlabel_mt_reg = {
	.family        = NFPROTO_UNSPEC,
	.name          = "connlabel",
	.version       = XTABLES_VERSION,
	.size          = XT_ALIGN(sizeof(struct xt_connlabel_mtinfo)),
	.userspacesize = offsetof(struct xt_connlabel_mtinfo, bit),
	.help          = connlabel_mt_help,
	.print         = connlabel_mt_print,
	.save          = connlabel_mt_save,
	.x6_parse      = connlabel_mt_parse,
	.x6_options    = connlabel_mt_opts,
};

void _init(void)
{
	xtables_register_match(&connlabel_mt_reg);
}
