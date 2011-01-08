#ifndef IPTABLES_XSHARED_H
#define IPTABLES_XSHARED_H 1

struct xtables_rule_match;
struct xtables_target;

enum {
	XT_OPTION_OFFSET_SCALE = 256,
};

extern void print_extension_helps(const struct xtables_target *,
	const struct xtables_rule_match *);

#endif /* IPTABLES_XSHARED_H */
