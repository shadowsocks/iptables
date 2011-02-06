#ifndef IPTABLES_XSHARED_H
#define IPTABLES_XSHARED_H 1

#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

struct xtables_rule_match;
struct xtables_target;

struct iptables_command_state {
	union {
		struct ipt_entry fw;
		struct ip6t_entry fw6;
	};
	int invert;
	int c;
	unsigned int options;
	struct xtables_rule_match *matches;
	struct xtables_target *target;
	char *protocol;
	int proto_used;
	char **argv;
};

enum {
	XT_OPTION_OFFSET_SCALE = 256,
};

extern void print_extension_helps(const struct xtables_target *,
	const struct xtables_rule_match *);

#endif /* IPTABLES_XSHARED_H */
