/* Shared library add-on to iptables to add bridge port matching support. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>
#include <iptables.h>
#include <linux/netfilter_ipv4/ipt_physdev.h>
#if defined(__GLIBC__) && __GLIBC__ == 2
#include <net/ethernet.h>
#else
#include <linux/if_ether.h>
#endif

static void
help(void)
{
	printf(
"physdev v%s options:\n"
" --physdev-in [!] input name[+]	bridge port name ([+] for wildcard)\n"
" --physdev-out [!] output name[+]	bridge port name ([+] for wildcard)\n"
"\n", IPTABLES_VERSION);
}

static struct option opts[] = {
	{ "physdev-in", 1, 0, '1' },
	{ "physdev-out", 1, 0, '2' },
	{0}
};

/* copied from iptables.c */
static void
parse_interface(const char *arg, char *vianame, unsigned char *mask)
{
	int vialen = strlen(arg);
	unsigned int i;

	memset(mask, 0, IFNAMSIZ);
	memset(vianame, 0, IFNAMSIZ);

	if (vialen + 1 > IFNAMSIZ)
		exit_error(PARAMETER_PROBLEM,
			   "interface name `%s' must be shorter than IFNAMSIZ"
			   " (%i)", arg, IFNAMSIZ-1);

	strcpy(vianame, arg);
	if (vialen == 0)
		memset(mask, 0, IFNAMSIZ);
	else if (vianame[vialen - 1] == '+') {
		memset(mask, 0xFF, vialen - 1);
		memset(mask + vialen - 1, 0, IFNAMSIZ - vialen + 1);
		/* Don't remove `+' here! -HW */
	} else {
		/* Include nul-terminator in match */
		memset(mask, 0xFF, vialen + 1);
		memset(mask + vialen + 1, 0, IFNAMSIZ - vialen - 1);
		for (i = 0; vianame[i]; i++) {
			if (!isalnum(vianame[i])
			    && vianame[i] != '_'
			    && vianame[i] != '.') {
				printf("Warning: wierd character in interface"
				       " `%s' (No aliases, :, ! or *).\n",
				       vianame);
				break;
			}
		}
	}
}

static void
init(struct ipt_entry_match *m, unsigned int *nfcache)
{
}

static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      unsigned int *nfcache,
      struct ipt_entry_match **match)
{
	struct ipt_physdev_info *info =
		(struct ipt_physdev_info*)(*match)->data;

	switch (c) {
	case '1':
		if (*flags & IPT_PHYSDEV_OP_MATCH_IN)
			exit_error(PARAMETER_PROBLEM,
				   "multiple --physdev-in not allowed");
		check_inverse(optarg, &invert, &optind, 0);
		parse_interface(argv[optind-1], info->physindev, info->in_mask);
		if (invert)
			info->invert |= IPT_PHYSDEV_OP_MATCH_IN;
		*flags |= IPT_PHYSDEV_OP_MATCH_IN;
		break;

	case '2':
		if (*flags & IPT_PHYSDEV_OP_MATCH_OUT)
			exit_error(PARAMETER_PROBLEM,
				   "multiple --physdev-out not allowed");
		check_inverse(optarg, &invert, &optind, 0);
		parse_interface(argv[optind-1], info->physoutdev,
				info->out_mask);
		if (invert)
			info->invert |= IPT_PHYSDEV_OP_MATCH_OUT;
		*flags |= IPT_PHYSDEV_OP_MATCH_OUT;
		break;

	default:
		return 0;
	}

	return 1;
}

static void final_check(unsigned int flags)
{
}

static void print_iface(u_int8_t invert, char *dev, char *prefix)
{
	char iface[IFNAMSIZ+2];

	if (invert) {
		iface[0] = '!';
		iface[1] = '\0';
	} else
		iface[0] = '\0';

	if (dev[0] != '\0') {
		strcat(iface, dev);
		printf("%s%s", prefix, iface);
	}
}

static void
print(const struct ipt_ip *ip,
      const struct ipt_entry_match *match,
      int numeric)
{
	struct ipt_physdev_info *info =
		(struct ipt_physdev_info*)match->data;

	printf("PHYSDEV match");
	print_iface(info->invert & IPT_PHYSDEV_OP_MATCH_IN, info->physindev,
		    " physindev=");
	print_iface(info->invert & IPT_PHYSDEV_OP_MATCH_OUT, info->physoutdev,
		    " physoutdev=");
	printf(" ");
}

static void save(const struct ipt_ip *ip, const struct ipt_entry_match *match)
{
	struct ipt_physdev_info *info =
		(struct ipt_physdev_info*)match->data;

	print_iface(info->invert & IPT_PHYSDEV_OP_MATCH_IN, info->physindev,
		    "--physdev-in ");
	print_iface(info->invert & IPT_PHYSDEV_OP_MATCH_OUT, info->physoutdev,
		    "--physdev-out ");
	printf(" ");
}

static
struct iptables_match physdev
= { NULL,
    "physdev",
    IPTABLES_VERSION,
    IPT_ALIGN(sizeof(struct ipt_physdev_info)),
    IPT_ALIGN(sizeof(struct ipt_physdev_info)),
    &help,
    &init,
    &parse,
    &final_check,
    &print,
    &save,
    opts
};

void _init(void)
{
	register_match(&physdev);
}
