#ifndef _IPTABLES_USER_H
#define _IPTABLES_USER_H

#include "xtables.h"
#include "libiptc/libiptc.h"

#ifndef IPT_LIB_DIR
#define IPT_LIB_DIR XT_LIB_DIR
#endif

#ifndef IPT_SO_GET_REVISION_MATCH /* Old kernel source. */
#define IPT_SO_GET_REVISION_MATCH	(IPT_BASE_CTL + 2)
#define IPT_SO_GET_REVISION_TARGET	(IPT_BASE_CTL + 3)
#endif /* IPT_SO_GET_REVISION_MATCH   Old kernel source */

#define iptables_rule_match	xtables_rule_match
#define iptables_match		xtables_match
#define iptables_target		xtables_target
#define ipt_tryload		xt_tryload

extern int line;

/* Your shared library should call one of these. */
extern void register_match(struct iptables_match *me);
extern void register_target(struct iptables_target *me);

extern struct in_addr *dotted_to_addr(const char *dotted);
extern struct in_addr *dotted_to_mask(const char *dotted);
extern char *addr_to_dotted(const struct in_addr *addrp);
extern char *addr_to_anyname(const struct in_addr *addr);
extern char *mask_to_dotted(const struct in_addr *mask);

extern void parse_hostnetworkmask(const char *name, struct in_addr **addrpp,
                      struct in_addr *maskp, unsigned int *naddrs);
extern u_int16_t parse_protocol(const char *s);

extern int do_command(int argc, char *argv[], char **table,
		      iptc_handle_t *handle);
extern int delete_chain(const ipt_chainlabel chain, int verbose,
			iptc_handle_t *handle);
extern int flush_entries(const ipt_chainlabel chain, int verbose, 
			iptc_handle_t *handle);
extern int for_each_chain(int (*fn)(const ipt_chainlabel, int, iptc_handle_t *),
		int verbose, int builtinstoo, iptc_handle_t *handle);

/* kernel revision handling */
extern int kernel_version;
extern void get_kernel_version(void);
#define LINUX_VERSION(x,y,z)	(0x10000*(x) + 0x100*(y) + z)
#define LINUX_VERSION_MAJOR(x)	(((x)>>16) & 0xFF)
#define LINUX_VERSION_MINOR(x)	(((x)>> 8) & 0xFF)
#define LINUX_VERSION_PATCH(x)	( (x)      & 0xFF)

#endif /*_IPTABLES_USER_H*/
