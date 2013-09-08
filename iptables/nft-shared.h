#ifndef _NFT_SHARED_H_
#define _NFT_SHARED_H_

#include <stdbool.h>

#include <libnftables/rule.h>
#include <libnftables/expr.h>

#include "xshared.h"

#if 0
#define DEBUGP(x, args...) fprintf(stdout, x, ## args)
#define NLDEBUG
#define DEBUG_DEL
#else
#define DEBUGP(x, args...)
#endif

/*
 * iptables print output emulation
 */

#define FMT_NUMERIC	0x0001
#define FMT_NOCOUNTS	0x0002
#define FMT_KILOMEGAGIGA 0x0004
#define FMT_OPTIONS	0x0008
#define FMT_NOTABLE	0x0010
#define FMT_NOTARGET	0x0020
#define FMT_VIA		0x0040
#define FMT_NONEWLINE	0x0080
#define FMT_LINENUMBERS 0x0100

#define FMT_PRINT_RULE (FMT_NOCOUNTS | FMT_OPTIONS | FMT_VIA \
			| FMT_NUMERIC | FMT_NOTABLE)
#define FMT(tab,notab) ((format) & FMT_NOTABLE ? (notab) : (tab))

struct xtables_args;

struct nft_family_ops {
	int (*add)(struct nft_rule *r, void *data);
	bool (*is_same)(const struct iptables_command_state *a,
			const struct iptables_command_state *b);
	void (*print_payload)(struct nft_rule_expr *e,
			      struct nft_rule_expr_iter *iter);
	void (*parse_meta)(struct nft_rule_expr *e, uint8_t key,
			   void *data);
	void (*parse_payload)(struct nft_rule_expr_iter *iter,
			      uint32_t offset, void *data);
	void (*parse_immediate)(const char *jumpto, bool nft_goto, void *data);
	void (*print_firewall)(struct nft_rule *r, unsigned int num,
			       unsigned int format);
	uint8_t (*save_firewall)(const struct iptables_command_state *cs,
				 unsigned int format);
	void (*post_parse)(int command, struct iptables_command_state *cs,
			   struct xtables_args *args);
	void (*parse_target)(struct xtables_target *t, void *data);
};

void add_meta(struct nft_rule *r, uint32_t key);
void add_payload(struct nft_rule *r, int offset, int len);
void add_bitwise_u16(struct nft_rule *r, int mask, int xor);
void add_cmp_ptr(struct nft_rule *r, uint32_t op, void *data, size_t len);
void add_cmp_u8(struct nft_rule *r, uint8_t val, uint32_t op);
void add_cmp_u16(struct nft_rule *r, uint16_t val, uint32_t op);
void add_cmp_u32(struct nft_rule *r, uint32_t val, uint32_t op);
void add_iniface(struct nft_rule *r, char *iface, int invflags);
void add_outiface(struct nft_rule *r, char *iface, int invflags);
void add_addr(struct nft_rule *r, int offset,
	      void *data, size_t len, int invflags);
void add_proto(struct nft_rule *r, int offset, size_t len,
	       uint8_t proto, int invflags);
void add_compat(struct nft_rule *r, uint32_t proto, bool inv);

bool is_same_interfaces(const char *a_iniface, const char *a_outiface,
			unsigned const char *a_iniface_mask,
			unsigned const char *a_outiface_mask,
			const char *b_iniface, const char *b_outiface,
			unsigned const char *b_iniface_mask,
			unsigned const char *b_outiface_mask);

void parse_meta(struct nft_rule_expr *e, uint8_t key, char *iniface,
		unsigned char *iniface_mask, char *outiface,
		unsigned char *outiface_mask, uint8_t *invflags);
void print_proto(uint16_t proto, int invert);
void get_cmp_data(struct nft_rule_expr_iter *iter,
		  void *data, size_t dlen, bool *inv);
void nft_rule_to_iptables_command_state(struct nft_rule *r,
					struct iptables_command_state *cs);
void print_firewall_details(const struct iptables_command_state *cs,
			    const char *targname, uint8_t flags,
			    uint8_t invflags, uint8_t proto,
			    unsigned int num, unsigned int format);
void print_ifaces(const char *iniface, const char *outiface, uint8_t invflags,
		  unsigned int format);
void print_matches_and_target(struct iptables_command_state *cs,
			      unsigned int format);
void save_firewall_details(const struct iptables_command_state *cs,
			   uint8_t invflags, uint16_t proto,
			   const char *iniface,
			   unsigned const char *iniface_mask,
			   const char *outiface,
			   unsigned const char *outiface_mask,
			   unsigned int format);

struct nft_family_ops *nft_family_ops_lookup(int family);

struct addr_mask {
	union {
		struct in_addr	*v4;
		struct in6_addr *v6;
	} addr;

	unsigned int naddrs;

	union {
		struct in_addr	*v4;
		struct in6_addr *v6;
	} mask;
};

struct xtables_args {
	int		family;
	uint16_t	proto;
	uint8_t		flags;
	uint8_t		invflags;
	char		iniface[IFNAMSIZ], outiface[IFNAMSIZ];
	unsigned char	iniface_mask[IFNAMSIZ], outiface_mask[IFNAMSIZ];
	bool		goto_set;
	const char	*shostnetworkmask, *dhostnetworkmask;
	const char	*pcnt, *bcnt;
	struct addr_mask s, d;
	unsigned long long pcnt_cnt, bcnt_cnt;
};

#define CMD_NONE		0x0000U
#define CMD_INSERT		0x0001U
#define CMD_DELETE		0x0002U
#define CMD_DELETE_NUM		0x0004U
#define CMD_REPLACE		0x0008U
#define CMD_APPEND		0x0010U
#define CMD_LIST		0x0020U
#define CMD_FLUSH		0x0040U
#define CMD_ZERO		0x0080U
#define CMD_NEW_CHAIN		0x0100U
#define CMD_DELETE_CHAIN	0x0200U
#define CMD_SET_POLICY		0x0400U
#define CMD_RENAME_CHAIN	0x0800U
#define CMD_LIST_RULES		0x1000U
#define CMD_ZERO_NUM		0x2000U
#define CMD_CHECK		0x4000U

#endif
