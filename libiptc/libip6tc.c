/* Library which manipulates firewall rules.  Version 0.1. */

/* Architecture of firewall rules is as follows:
 *
 * Chains go INPUT, FORWARD, OUTPUT then user chains.
 * Each user chain starts with an ERROR node.
 * Every chain ends with an unconditional jump: a RETURN for user chains,
 * and a POLICY for built-ins.
 */

/* (C)1999 Paul ``Rusty'' Russell - Placed under the GNU GPL (See
   COPYING for details). */

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#ifdef DEBUG_CONNTRACK
#define inline
#endif

#if !defined(__GLIBC__) || (__GLIBC__ < 2)
typedef unsigned int socklen_t;
#endif

#include "libiptc/libip6tc.h"

#define HOOK_PRE_ROUTING	NF_IP6_PRE_ROUTING
#define HOOK_LOCAL_IN		NF_IP6_LOCAL_IN
#define HOOK_FORWARD		NF_IP6_FORWARD
#define HOOK_LOCAL_OUT		NF_IP6_LOCAL_OUT
#define HOOK_POST_ROUTING	NF_IP6_POST_ROUTING

#define STRUCT_ENTRY_TARGET	struct ip6t_entry_target
#define STRUCT_ENTRY		struct ip6t_entry
#define STRUCT_ENTRY_MATCH	struct ip6t_entry_match
#define STRUCT_GETINFO		struct ip6t_getinfo
#define STRUCT_GET_ENTRIES	struct ip6t_get_entries
#define STRUCT_COUNTERS		struct ip6t_counters
#define STRUCT_COUNTERS_INFO	struct ip6t_counters_info
#define STRUCT_STANDARD_TARGET	struct ip6t_standard_target
#define STRUCT_REPLACE		struct ip6t_replace

#define STRUCT_TC_HANDLE	struct ip6tc_handle
#define TC_HANDLE_T		ip6tc_handle_t

#define ENTRY_ITERATE		IP6T_ENTRY_ITERATE
#define TABLE_MAXNAMELEN	IP6T_TABLE_MAXNAMELEN
#define FUNCTION_MAXNAMELEN	IP6T_FUNCTION_MAXNAMELEN

#define GET_TARGET		ip6t_get_target

#define ERROR_TARGET		IP6T_ERROR_TARGET
#define NUMHOOKS		NF_IP6_NUMHOOKS

#define IPT_CHAINLABEL		ip6t_chainlabel

#define TC_DUMP_ENTRIES		dump_entries6
#define TC_IS_CHAIN		ip6tc_is_chain
#define TC_NEXT_CHAIN		ip6tc_next_chain
#define TC_NUM_RULES		ip6tc_num_rules
#define TC_GET_RULE		ip6tc_get_rule
#define TC_GET_TARGET		ip6tc_get_target
#define TC_BUILTIN		ip6tc_builtin
#define TC_GET_POLICY		ip6tc_get_policy
#define TC_INSERT_ENTRY		ip6tc_insert_entry
#define TC_REPLACE_ENTRY	ip6tc_replace_entry
#define TC_APPEND_ENTRY		ip6tc_append_entry
#define TC_DELETE_ENTRY		ip6tc_delete_entry
#define TC_DELETE_NUM_ENTRY	ip6tc_delete_num_entry
#define TC_CHECK_PACKET		ip6tc_check_packet
#define TC_FLUSH_ENTRIES	ip6tc_flush_entries
#define TC_ZERO_ENTRIES		ip6tc_zero_entries
#define TC_CREATE_CHAIN		ip6tc_create_chain
#define TC_GET_REFERENCES	ip6tc_get_references
#define TC_DELETE_CHAIN		ip6tc_delete_chain
#define TC_RENAME_CHAIN		ip6tc_rename_chain
#define TC_SET_POLICY		ip6tc_set_policy
#define TC_GET_RAW_SOCKET	ip6tc_get_raw_socket
#define TC_INIT			ip6tc_init
#define TC_COMMIT		ip6tc_commit
#define TC_STRERROR		ip6tc_strerror

#define TC_AF			AF_INET6
#define TC_IPPROTO		IPPROTO_IPV6

#define SO_SET_REPLACE		IP6T_SO_SET_REPLACE
#define SO_SET_ADD_COUNTERS	IP6T_SO_SET_ADD_COUNTERS
#define SO_GET_INFO		IP6T_SO_GET_INFO
#define SO_GET_ENTRIES		IP6T_SO_GET_ENTRIES
#define SO_GET_VERSION		IP6T_SO_GET_VERSION

#define STANDARD_TARGET		IP6T_STANDARD_TARGET
#define LABEL_RETURN		IP6TC_LABEL_RETURN
#define LABEL_ACCEPT		IP6TC_LABEL_ACCEPT
#define LABEL_DROP		IP6TC_LABEL_DROP

#define ALIGN			IP6T_ALIGN
#define RETURN			IP6T_RETURN

#include "libiptc.c"

#define BIT6(a, l) \
 (((a->in6_u.u6_addr32[(l) / 32]) >> ((l) & 31)) & 1)

int
ipv6_prefix_length(const struct in6_addr *a)
{
	int l, i;
	for (l = 0; l < 128; l++) {
		if (BIT6(a, l) == 0)
			break;
	}
	for (i = l + 1; i < 128; i++) {
		if (BIT6(a, i) == 1)
			return -1;
	}
	return l;
}

static int
dump_entry(struct ip6t_entry *e, const ip6tc_handle_t handle)
{
	size_t i;
	char buf[40];
	int len;
	struct ip6t_entry_target *t;
	
	printf("Entry %u (%lu):\n", entry2index(handle, e),
	       entry2offset(handle, e));
	puts("SRC IP: ");
	inet_ntop(AF_INET6, &e->ipv6.src, buf, sizeof buf);
	puts(buf);
	putchar('/');
	len = ipv6_prefix_length(&e->ipv6.smsk);
	if (len != -1)
		printf("%d", len);
	else {
		inet_ntop(AF_INET6, &e->ipv6.smsk, buf, sizeof buf);
		puts(buf);
	}
	putchar('\n');
	
	puts("DST IP: ");
	inet_ntop(AF_INET6, &e->ipv6.dst, buf, sizeof buf);
	puts(buf);
	putchar('/');
	len = ipv6_prefix_length(&e->ipv6.dmsk);
	if (len != -1)
		printf("%d", len);
	else {
		inet_ntop(AF_INET6, &e->ipv6.dmsk, buf, sizeof buf);
		puts(buf);
	}
	putchar('\n');
	
	printf("Interface: `%s'/", e->ipv6.iniface);
	for (i = 0; i < IFNAMSIZ; i++)
		printf("%c", e->ipv6.iniface_mask[i] ? 'X' : '.');
	printf("to `%s'/", e->ipv6.outiface);
	for (i = 0; i < IFNAMSIZ; i++)
		printf("%c", e->ipv6.outiface_mask[i] ? 'X' : '.');
	printf("\nProtocol: %u\n", e->ipv6.proto);
	if (e->ipv6.flags & IP6T_F_TOS)
		printf("TOS: %u\n", e->ipv6.tos);
	printf("Flags: %02X\n", e->ipv6.flags);
	printf("Invflags: %02X\n", e->ipv6.invflags);
	printf("Counters: %llu packets, %llu bytes\n",
	       e->counters.pcnt, e->counters.bcnt);
	printf("Cache: %08X ", e->nfcache);
	if (e->nfcache & NFC_ALTERED) printf("ALTERED ");
	if (e->nfcache & NFC_UNKNOWN) printf("UNKNOWN ");
	if (e->nfcache & NFC_IP6_SRC) printf("IP6_SRC ");
	if (e->nfcache & NFC_IP6_DST) printf("IP6_DST ");
	if (e->nfcache & NFC_IP6_IF_IN) printf("IP6_IF_IN ");
	if (e->nfcache & NFC_IP6_IF_OUT) printf("IP6_IF_OUT ");
	if (e->nfcache & NFC_IP6_TOS) printf("IP6_TOS ");
	if (e->nfcache & NFC_IP6_PROTO) printf("IP6_PROTO ");
	if (e->nfcache & NFC_IP6_OPTIONS) printf("IP6_OPTIONS ");
	if (e->nfcache & NFC_IP6_TCPFLAGS) printf("IP6_TCPFLAGS ");
	if (e->nfcache & NFC_IP6_SRC_PT) printf("IP6_SRC_PT ");
	if (e->nfcache & NFC_IP6_DST_PT) printf("IP6_DST_PT ");
	if (e->nfcache & NFC_IP6_PROTO_UNKNOWN) printf("IP6_PROTO_UNKNOWN ");
	printf("\n");
	
	IP6T_MATCH_ITERATE(e, print_match);

	t = ip6t_get_target(e);
	printf("Target name: `%s' [%u]\n", t->u.name, t->target_size);
	if (strcmp(t->u.name, IP6T_STANDARD_TARGET) == 0) {
		int pos = *(int *)t->data;
		if (pos < 0)
			printf("verdict=%s\n",
			       pos == -NF_ACCEPT-1 ? "NF_ACCEPT"
			       : pos == -NF_DROP-1 ? "NF_DROP"
			       : pos == IP6T_RETURN ? "RETURN"
			       : "UNKNOWN");
		else
			printf("verdict=%u\n", pos);
	} else if (strcmp(t->u.name, IP6T_ERROR_TARGET) == 0)
		printf("error=`%s'\n", t->data);

	printf("\n");
	return 0;
}

static inline int
is_same(const struct STRUCT_ENTRY *a, const struct STRUCT_ENTRY *b,
	unsigned char *matchmask)
{
	unsigned int i;
	struct STRUCT_ENTRY_TARGET *ta, *tb;
	unsigned char *mptr;

	/* Always compare head structures: ignore mask here. */
	if (memcmp(&a->ipv6.src, &b->ipv6.src, sizeof(struct in6_addr))
	    || memcmp(&a->ipv6.dst, &b->ipv6.dst, sizeof(struct in6_addr))
	    || memcmp(&a->ipv6.smsk, &b->ipv6.smsk, sizeof(struct in6_addr))
	    || memcmp(&a->ipv6.dmsk, &b->ipv6.dmsk, sizeof(struct in6_addr))
	    || a->ipv6.proto != b->ipv6.proto
	    || a->ipv6.tos != b->ipv6.tos
	    || a->ipv6.flags != b->ipv6.flags
	    || a->ipv6.invflags != b->ipv6.invflags)
		return 0;

	for (i = 0; i < IFNAMSIZ; i++) {
		if (a->ipv6.iniface_mask[i] != b->ipv6.iniface_mask[i])
			return 0;
		if ((a->ipv6.iniface[i] & a->ipv6.iniface_mask[i])
		    != (b->ipv6.iniface[i] & b->ipv6.iniface_mask[i]))
			return 0;
		if (a->ipv6.outiface_mask[i] != b->ipv6.outiface_mask[i])
			return 0;
		if ((a->ipv6.outiface[i] & a->ipv6.outiface_mask[i])
		    != (b->ipv6.outiface[i] & b->ipv6.outiface_mask[i]))
			return 0;
	}

	if (a->nfcache != b->nfcache
	    || a->target_offset != b->target_offset
	    || a->next_offset != b->next_offset)
		return 0;

	mptr = matchmask + sizeof(struct STRUCT_ENTRY);
	if (IP6T_MATCH_ITERATE(a, match_different, a->elems, b->elems))
		return 0;

	ta = GET_TARGET((struct STRUCT_ENTRY *)a);
	tb = GET_TARGET((struct STRUCT_ENTRY *)b);
	if (ta->target_size != tb->target_size)
		return 0;
	if (strcmp(ta->u.name, tb->u.name) != 0)
		return 0;
	mptr += sizeof(*ta);

	if (target_different(ta->data, tb->data,
			     ta->u.target_size - sizeof(*ta), mptr))
		return 0;

	return 1;
}
