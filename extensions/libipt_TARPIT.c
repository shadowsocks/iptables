/* Shared library add-on to iptables for TARPIT support */
#include <stdio.h>
#include <getopt.h>
#include <iptables.h>

static void
help(void)
{
	fputs(
"TARPIT takes no options\n"
"\n", stdout);
}

static struct option opts[] = {
	{ 0 }
};

static void
init(struct ipt_entry_target *t, unsigned int *nfcache)
{
	/* Can't cache this */
	*nfcache |= NFC_UNKNOWN;
}

static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      struct ipt_entry_target **target)
{
	return 0;
}

static void final_check(unsigned int flags)
{
}

static void
print(const struct ipt_ip *ip,
      const struct ipt_entry_target *target,
      int numeric)
{
}

static void save(const struct ipt_ip *ip, const struct ipt_entry_target *target)
{
}

static
struct iptables_target tarpit
= { NULL,
    "TARPIT",
    IPTABLES_VERSION,
    IPT_ALIGN(0),
    IPT_ALIGN(0),
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
	register_target(&tarpit);
}
