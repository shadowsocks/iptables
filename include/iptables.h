#ifndef _IPTABLES_USER_H
#define _IPTABLES_USER_H

#include "xtables.h"
#include "libiptc/libiptc.h"

#ifndef IPT_SO_GET_REVISION_MATCH /* Old kernel source. */
#define IPT_SO_GET_REVISION_MATCH	(IPT_BASE_CTL + 2)
#define IPT_SO_GET_REVISION_TARGET	(IPT_BASE_CTL + 3)
#endif /* IPT_SO_GET_REVISION_MATCH   Old kernel source */

#define iptables_rule_match	xtables_rule_match
#define ipt_tryload		xt_tryload

extern int line;

/* Your shared library should call one of these. */
extern int do_command(int argc, char *argv[], char **table,
		      iptc_handle_t *handle);
extern int delete_chain(const ipt_chainlabel chain, int verbose,
			iptc_handle_t *handle);
extern int flush_entries(const ipt_chainlabel chain, int verbose, 
			iptc_handle_t *handle);
extern int for_each_chain(int (*fn)(const ipt_chainlabel, int, iptc_handle_t *),
		int verbose, int builtinstoo, iptc_handle_t *handle);
extern void print_rule(const struct ipt_entry *e,
		iptc_handle_t *handle, const char *chain, int counters);

/* kernel revision handling */
extern int kernel_version;
extern void get_kernel_version(void);
#define LINUX_VERSION(x,y,z)	(0x10000*(x) + 0x100*(y) + z)
#define LINUX_VERSION_MAJOR(x)	(((x)>>16) & 0xFF)
#define LINUX_VERSION_MINOR(x)	(((x)>> 8) & 0xFF)
#define LINUX_VERSION_PATCH(x)	( (x)      & 0xFF)

#endif /*_IPTABLES_USER_H*/
