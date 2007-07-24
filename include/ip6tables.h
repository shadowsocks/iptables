#ifndef _IP6TABLES_USER_H
#define _IP6TABLES_USER_H

#include <xtables.h>

#include "iptables_common.h"
#include "libiptc/libip6tc.h"

#ifndef IP6T_LIB_DIR
#define IP6T_LIB_DIR "/usr/local/lib/iptables"
#endif

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif
#ifndef IPPROTO_DCCP
#define IPPROTO_DCCP 33
#endif
#ifndef IPPROTO_UDPLITE
#define IPPROTO_UDPLITE 136
#endif

#ifndef IP6T_SO_GET_REVISION_MATCH /* Old kernel source. */
#define IP6T_SO_GET_REVISION_MATCH	68
#define IP6T_SO_GET_REVISION_TARGET	69
#endif /* IP6T_SO_GET_REVISION_MATCH   Old kernel source */

#define ip6tables_rule_match	xtables_rule_match
#define ip6tables_match		xtables_match
#define ip6tables_target	xtables_target
#define ip6t_tryload		xt_tryload

extern int line;

/* Your shared library should call one of these. */
extern void register_match6(struct ip6tables_match *me);
extern void register_target6(struct ip6tables_target *me);

extern int service_to_port(const char *name, const char *proto);
extern u_int16_t parse_port(const char *port, const char *proto);
extern int do_command6(int argc, char *argv[], char **table,
		       ip6tc_handle_t *handle);
extern void parse_interface(const char *arg, char *vianame, unsigned char *mask);

extern int for_each_chain(int (*fn)(const ip6t_chainlabel, int, ip6tc_handle_t *), int verbose, int builtinstoo, ip6tc_handle_t *handle);
extern int flush_entries(const ip6t_chainlabel chain, int verbose, ip6tc_handle_t *handle);
extern int delete_chain(const ip6t_chainlabel chain, int verbose, ip6tc_handle_t *handle);

#endif /*_IP6TABLES_USER_H*/
