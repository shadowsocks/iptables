#ifndef _XTABLES_EBTABLES_H_
#define _XTABLES_EBTABLES_H_

#include <netinet/in.h>
#include <linux/netfilter_bridge/ebtables.h>
#include <linux/netfilter/x_tables.h>

/* We use replace->flags, so we can't use the following values:
 * 0x01 == OPT_COMMAND, 0x02 == OPT_TABLE, 0x100 == OPT_ZERO */
#define LIST_N    0x04
#define LIST_C    0x08
#define LIST_X    0x10
#define LIST_MAC2 0x20

/* Be backwards compatible, so don't use '+' in kernel */
#define IF_WILDCARD 1

extern unsigned char eb_mac_type_unicast[ETH_ALEN];
extern unsigned char eb_msk_type_unicast[ETH_ALEN];
extern unsigned char eb_mac_type_multicast[ETH_ALEN];
extern unsigned char eb_msk_type_multicast[ETH_ALEN];
extern unsigned char eb_mac_type_broadcast[ETH_ALEN];
extern unsigned char eb_msk_type_broadcast[ETH_ALEN];
extern unsigned char eb_mac_type_bridge_group[ETH_ALEN];
extern unsigned char eb_msk_type_bridge_group[ETH_ALEN];

int ebt_get_mac_and_mask(const char *from, unsigned char *to, unsigned char *mask);

struct xtables_ebt_entry {
	unsigned int bitmask;
	unsigned int invflags;
	unsigned int flags;
	uint16_t ethproto;
	char in[IFNAMSIZ];
	char logical_in[IFNAMSIZ];
	unsigned char in_mask[IFNAMSIZ];
	char out[IFNAMSIZ];
	char logical_out[IFNAMSIZ];
	unsigned char out_mask[IFNAMSIZ];
	unsigned char sourcemac[ETH_ALEN];
	unsigned char sourcemsk[ETH_ALEN];
	unsigned char destmac[ETH_ALEN];
	unsigned char destmsk[ETH_ALEN];
	struct xtables_rule_match *matches;
	struct xtables_target *target;
	struct xt_counters counters;
	const char *jumpto;
};
#endif
