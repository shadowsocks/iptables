#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <iptables.h>

#include<linux/netfilter_ipv4/ip_tables.h>
#include<linux/netfilter_ipv4/ipt_condition.h>


static void help(void)
{
  printf("condition match v%s options:\n"
  "--condition [!] filename       Match on boolean value stored in /proc file"
  "\n", IPTABLES_VERSION);
}

static struct option opts[] = { { "condition", 1, 0, 'X' }, { 0 } };

static void init(struct ipt_entry_match *m, unsigned int *nfcache)
{
  *nfcache |= NFC_UNKNOWN;
}

static int parse(int c, char **argv, int invert, unsigned int *flags,
		const struct ipt_entry *entry, unsigned int *nfcache,
		struct ipt_entry_match **match)
{
  struct condition_info *info = (struct condition_info*)(*match)->data;

  check_inverse(optarg, &invert, &optind, 0);

  if(*flags)
    exit_error(PARAMETER_PROBLEM, "Can't specify multiple conditions");

  if(c == 'X')
  {
    if(strlen(argv[optind-1]) < VARIABLE_NAME_LEN)
      strcpy(info->name, argv[optind-1]);
    else
      exit_error(PARAMETER_PROBLEM, "File name too long");

    info->invert = invert;
    *flags = 1;
    return 1;
  }

  return 0;
}


static void final_check(unsigned int flags)
{
  if(!flags)
    exit_error(PARAMETER_PROBLEM, "Condition match: must specify --condition");
}


static void print(const struct ipt_ip *ip,
		const struct ipt_entry_match *match, int numeric)
{
  const struct condition_info *info = (const struct condition_info*)match->data;

  printf("condition %s%s ", (info->invert) ? "!" : "", info->name);
}


static void save(const struct ipt_ip *ip, const struct ipt_entry_match *match)
{
  const struct condition_info *info = (const struct condition_info*)match->data;

  printf("--condition %s%s ", (info->invert) ? "! " : "", info->name);
}


static struct iptables_match condition = {
  NULL,
  "condition",
  IPTABLES_VERSION,
  IPT_ALIGN(sizeof(struct condition_info)),
  IPT_ALIGN(sizeof(struct condition_info)),
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
  register_match(&condition);
}

