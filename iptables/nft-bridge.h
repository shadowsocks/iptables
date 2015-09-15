#ifndef _NFT_BRIDGE_H_
#define _NFT_BRIDGE_H_

#include <netinet/in.h>
//#include <linux/netfilter_bridge/ebtables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/nf_tables.h>
#include <net/ethernet.h>
#include <libiptc/libxtc.h>

/* We use replace->flags, so we can't use the following values:
 * 0x01 == OPT_COMMAND, 0x02 == OPT_TABLE, 0x100 == OPT_ZERO */
#define LIST_N	  0x04
#define LIST_C	  0x08
#define LIST_X	  0x10
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

/* From: include/linux/netfilter_bridge/ebtables.h
 *
 * Adapted for the need of the ebtables-compat.
 */

#define EBT_TABLE_MAXNAMELEN 32
#define EBT_CHAIN_MAXNAMELEN EBT_TABLE_MAXNAMELEN
#define EBT_FUNCTION_MAXNAMELEN EBT_TABLE_MAXNAMELEN

/* verdicts >0 are "branches" */
#define EBT_ACCEPT   -1
#define EBT_DROP     -2
#define EBT_CONTINUE -3
#define EBT_RETURN   -4
#define NUM_STANDARD_TARGETS   4

#define EBT_ENTRY_OR_ENTRIES 0x01
/* these are the normal masks */
#define EBT_NOPROTO 0x02
#define EBT_802_3 0x04
#define EBT_SOURCEMAC 0x08
#define EBT_DESTMAC 0x10
#define EBT_F_MASK (EBT_NOPROTO | EBT_802_3 | EBT_SOURCEMAC | EBT_DESTMAC \
   | EBT_ENTRY_OR_ENTRIES)

#define EBT_IPROTO 0x01
#define EBT_IIN 0x02
#define EBT_IOUT 0x04
#define EBT_ISOURCE 0x8
#define EBT_IDEST 0x10
#define EBT_ILOGICALIN 0x20
#define EBT_ILOGICALOUT 0x40
#define EBT_INV_MASK (EBT_IPROTO | EBT_IIN | EBT_IOUT | EBT_ILOGICALIN \
   | EBT_ILOGICALOUT | EBT_ISOURCE | EBT_IDEST)

/* ebtables target modules store the verdict inside an int. We can
 * reclaim a part of this int for backwards compatible extensions.
 * The 4 lsb are more than enough to store the verdict.
 */
#define EBT_VERDICT_BITS 0x0000000F

/* Fake ebt_entry */
struct ebt_entry {
	/* this needs to be the first field */
	unsigned int bitmask;
	unsigned int invflags;
	uint16_t ethproto;
	/* the physical in-dev */
	char in[IFNAMSIZ];
	/* the logical in-dev */
	char logical_in[IFNAMSIZ];
	/* the physical out-dev */
	char out[IFNAMSIZ];
	/* the logical out-dev */
	char logical_out[IFNAMSIZ];
	unsigned char sourcemac[ETH_ALEN];
	unsigned char sourcemsk[ETH_ALEN];
	unsigned char destmac[ETH_ALEN];
	unsigned char destmsk[ETH_ALEN];

	unsigned char in_mask[IFNAMSIZ];
	unsigned char out_mask[IFNAMSIZ];
};

/* trick for ebtables-compat, since watchers are targets */
struct ebt_match {
	struct ebt_match				*next;
	union {
		struct xtables_match		*match;
		struct xtables_target		*watcher;
	} u;
	bool					ismatch;
};

struct ebtables_command_state {
	struct ebt_entry fw;
	struct xtables_target *target;
	struct xtables_rule_match *matches;
	struct ebt_match *match_list;
	const char *jumpto;
	struct xt_counters counters;
	int invert;
	int c;
	char **argv;
	int proto_used;
	char *protocol;
	unsigned int options;
};

void nft_rule_to_ebtables_command_state(struct nftnl_rule *r,
					struct ebtables_command_state *cs);

static const char *ebt_standard_targets[NUM_STANDARD_TARGETS] = {
	"ACCEPT",
	"DROP",
	"CONTINUE",
	"RETURN",
};

static inline const char *nft_ebt_standard_target(unsigned int num)
{
	if (num > NUM_STANDARD_TARGETS)
		return NULL;

	return ebt_standard_targets[num];
}

static inline int ebt_fill_target(const char *str, unsigned int *verdict)
{
	int i, ret = 0;

	for (i = 0; i < NUM_STANDARD_TARGETS; i++) {
		if (!strcmp(str, nft_ebt_standard_target(i))) {
			*verdict = -i - 1;
			break;
		}
	}

	if (i == NUM_STANDARD_TARGETS)
		ret = 1;

	return ret;
}

static inline const char *ebt_target_name(unsigned int verdict)
{
	return nft_ebt_standard_target(-verdict - 1);
}

#define EBT_CHECK_OPTION(flags, mask) ({			\
	if (*flags & mask)					\
		xtables_error(PARAMETER_PROBLEM,		\
			      "Multiple use of same "		\
			      "option not allowed");		\
	*flags |= mask;						\
})								\

void ebt_cs_clean(struct ebtables_command_state *cs);

#endif
