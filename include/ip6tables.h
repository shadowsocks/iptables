#ifndef _IP6TABLES_USER_H
#define _IP6TABLES_USER_H

#include <netinet/ip.h>
#include <xtables.h>
#include <libiptc/libip6tc.h>

#ifndef IP6T_SO_GET_REVISION_MATCH /* Old kernel source. */
#define IP6T_SO_GET_REVISION_MATCH	68
#define IP6T_SO_GET_REVISION_TARGET	69
#endif /* IP6T_SO_GET_REVISION_MATCH   Old kernel source */

#define ip6tables_rule_match	xtables_rule_match
#define ip6t_tryload		xt_tryload

extern int line;

/* Your shared library should call one of these. */
extern int do_command6(int argc, char *argv[], char **table,
		       ip6tc_handle_t *handle);

extern int for_each_chain(int (*fn)(const ip6t_chainlabel, int, ip6tc_handle_t *), int verbose, int builtinstoo, ip6tc_handle_t *handle);
extern int flush_entries(const ip6t_chainlabel chain, int verbose, ip6tc_handle_t *handle);
extern int delete_chain(const ip6t_chainlabel chain, int verbose, ip6tc_handle_t *handle);
void print_rule(const struct ip6t_entry *e, ip6tc_handle_t *h, const char *chain, int counters);

#endif /*_IP6TABLES_USER_H*/
