#ifndef _LINUX_NF_TABLES_H
#define _LINUX_NF_TABLES_H

enum nft_registers {
	NFT_REG_VERDICT,
	NFT_REG_1,
	NFT_REG_2,
	NFT_REG_3,
	NFT_REG_4,
	__NFT_REG_MAX
};
#define NFT_REG_MAX	(__NFT_REG_MAX - 1)

enum nft_verdicts {
	NFT_CONTINUE	= -1,
	NFT_BREAK	= -2,
	NFT_JUMP	= -3,
	NFT_GOTO	= -4,
	NFT_RETURN	= -5,
};

enum nf_tables_msg_types {
	NFT_MSG_NEWTABLE,
	NFT_MSG_GETTABLE,
	NFT_MSG_DELTABLE,
	NFT_MSG_NEWCHAIN,
	NFT_MSG_GETCHAIN,
	NFT_MSG_DELCHAIN,
	NFT_MSG_NEWRULE,
	NFT_MSG_GETRULE,
	NFT_MSG_DELRULE,
	NFT_MSG_NEWSET,
	NFT_MSG_GETSET,
	NFT_MSG_DELSET,
	NFT_MSG_NEWSETELEM,
	NFT_MSG_GETSETELEM,
	NFT_MSG_DELSETELEM,
	NFT_MSG_COMMIT,
	NFT_MSG_ABORT,
	NFT_MSG_MAX,
};

enum nft_list_attributes {
	NFTA_LIST_UNPEC,
	NFTA_LIST_ELEM,
	__NFTA_LIST_MAX
};
#define NFTA_LIST_MAX		(__NFTA_LIST_MAX - 1)

enum nft_hook_attributes {
	NFTA_HOOK_UNSPEC,
	NFTA_HOOK_HOOKNUM,
	NFTA_HOOK_PRIORITY,
	__NFTA_HOOK_MAX
};
#define NFTA_HOOK_MAX		(__NFTA_HOOK_MAX - 1)

/**
 * enum nft_table_flags - nf_tables table flags
 *
 * @NFT_TABLE_F_DORMANT: this table is not active
 */
enum nft_table_flags {
	NFT_TABLE_F_DORMANT	= 0x1,
};

enum nft_table_attributes {
	NFTA_TABLE_UNSPEC,
	NFTA_TABLE_NAME,
	NFTA_TABLE_FLAGS,
	__NFTA_TABLE_MAX
};
#define NFTA_TABLE_MAX		(__NFTA_TABLE_MAX - 1)

enum nft_chain_attributes {
	NFTA_CHAIN_UNSPEC,
	NFTA_CHAIN_TABLE,
	NFTA_CHAIN_HANDLE,
	NFTA_CHAIN_NAME,
	NFTA_CHAIN_HOOK,
	NFTA_CHAIN_POLICY,
	NFTA_CHAIN_USE,
	NFTA_CHAIN_TYPE,
	__NFTA_CHAIN_MAX
};
#define NFTA_CHAIN_MAX		(__NFTA_CHAIN_MAX - 1)

enum {
	NFT_RULE_F_COMMIT	= (1 << 0),
	NFT_RULE_F_MASK		= NFT_RULE_F_COMMIT,
};

enum nft_rule_attributes {
	NFTA_RULE_UNSPEC,
	NFTA_RULE_TABLE,
	NFTA_RULE_CHAIN,
	NFTA_RULE_HANDLE,
	NFTA_RULE_EXPRESSIONS,
	NFTA_RULE_FLAGS,
	NFTA_RULE_COMPAT,
	__NFTA_RULE_MAX
};
#define NFTA_RULE_MAX		(__NFTA_RULE_MAX - 1)

enum nft_rule_compat_flags {
	NFT_RULE_COMPAT_F_INV	= (1 << 1),
	NFT_RULE_COMPAT_F_MASK	= NFT_RULE_COMPAT_F_INV,
};

enum nft_rule_compat_attributes {
	NFTA_RULE_COMPAT_UNSPEC,
	NFTA_RULE_COMPAT_PROTO,
	NFTA_RULE_COMPAT_FLAGS,
	__NFTA_RULE_COMPAT_MAX
};
#define NFTA_RULE_COMPAT_MAX	(__NFTA_RULE_COMPAT_MAX - 1)

/**
 * enum nft_set_flags - nf_tables set flags
 *
 * @NFT_SET_ANONYMOUS: name allocation, automatic cleanup on unlink
 * @NFT_SET_CONSTANT: set contents may not change while bound
 * @NFT_SET_INTERVAL: set contains intervals
 * @NFT_SET_MAP: set is used as a dictionary
 */
enum nft_set_flags {
	NFT_SET_ANONYMOUS		= 0x1,
	NFT_SET_CONSTANT		= 0x2,
	NFT_SET_INTERVAL		= 0x4,
	NFT_SET_MAP			= 0x8,
};

/**
 * enum nft_set_attributes - nf_tables set netlink attributes
 *
 * @NFTA_SET_TABLE: table name (NLA_STRING)
 * @NFTA_SET_NAME: set name (NLA_STRING)
 * @NFTA_SET_FLAGS: bitmask of enum nft_set_flags (NLA_U32)
 * @NFTA_SET_KEY_TYPE: key data type, informational purpose only (NLA_U32)
 * @NFTA_SET_KEY_LEN: key data length (NLA_U32)
 * @NFTA_SET_DATA_TYPE: mapping data type (NLA_U32)
 * @NFTA_SET_DATA_LEN: mapping data length (NLA_U32)
 */
enum nft_set_attributes {
	NFTA_SET_UNSPEC,
	NFTA_SET_TABLE,
	NFTA_SET_NAME,
	NFTA_SET_FLAGS,
	NFTA_SET_KEY_TYPE,
	NFTA_SET_KEY_LEN,
	NFTA_SET_DATA_TYPE,
	NFTA_SET_DATA_LEN,
	__NFTA_SET_MAX
};
#define NFTA_SET_MAX		(__NFTA_SET_MAX - 1)

/**
 * enum nft_set_elem_flags - nf_tables set element flags
 *
 * @NFT_SET_ELEM_INTERVAL_END: element ends the previous interval
 */
enum nft_set_elem_flags {
	NFT_SET_ELEM_INTERVAL_END	= 0x1,
};

/**
 * enum nft_set_elem_attributes - nf_tables set element netlink attributes
 *
 * @NFTA_SET_ELEM_KEY: key value (NLA_NESTED: nft_data)
 * @NFTA_SET_ELEM_DATA: data value of mapping (NLA_NESTED: nft_data_attributes)
 * @NFTA_SET_ELEM_FLAGS: bitmask of nft_set_elem_flags (NLA_U32)
 */
enum nft_set_elem_attributes {
	NFTA_SET_ELEM_UNSPEC,
	NFTA_SET_ELEM_KEY,
	NFTA_SET_ELEM_DATA,
	NFTA_SET_ELEM_FLAGS,
	__NFTA_SET_ELEM_MAX
};
#define NFTA_SET_ELEM_MAX	(__NFTA_SET_ELEM_MAX - 1)

/**
 * enum nft_set_elem_list_attributes - nf_tables set element list netlink attributes
 *
 * @NFTA_SET_ELEM_LIST_TABLE: table of the set to be changed (NLA_STRING)
 * @NFTA_SET_ELEM_LIST_SET: name of the set to be changed (NLA_STRING)
 * @NFTA_SET_ELEM_LIST_ELEMENTS: list of set elements (NLA_NESTED: nft_set_elem_attributes)
 */
enum nft_set_elem_list_attributes {
	NFTA_SET_ELEM_LIST_UNSPEC,
	NFTA_SET_ELEM_LIST_TABLE,
	NFTA_SET_ELEM_LIST_SET,
	NFTA_SET_ELEM_LIST_ELEMENTS,
	__NFTA_SET_ELEM_LIST_MAX
};
#define NFTA_SET_ELEM_LIST_MAX	(__NFTA_SET_ELEM_LIST_MAX - 1)

/**
 * enum nft_data_types - nf_tables data types
 *
 * @NFT_DATA_VALUE: generic data
 * @NFT_DATA_VERDICT: netfilter verdict
 *
 * The type of data is usually determined by the kernel directly and is not
 * explicitly specified by userspace. The only difference are sets, where
 * userspace specifies the key and mapping data types.
 *
 * The values 0xffffff00-0xffffffff are reserved for internally used types.
 * The remaining range can be freely used by userspace to encode types, all
 * values are equivalent to NFT_DATA_VALUE.
 */
enum nft_data_types {
	NFT_DATA_VALUE,
	NFT_DATA_VERDICT	= 0xffffff00U,
};

#define NFT_DATA_RESERVED_MASK	0xffffff00U

enum nft_data_attributes {
	NFTA_DATA_UNSPEC,
	NFTA_DATA_VALUE,
	NFTA_DATA_VERDICT,
	__NFTA_DATA_MAX
};
#define NFTA_DATA_MAX		(__NFTA_DATA_MAX - 1)

enum nft_verdict_attributes {
	NFTA_VERDICT_UNSPEC,
	NFTA_VERDICT_CODE,
	NFTA_VERDICT_CHAIN,
	__NFTA_VERDICT_MAX
};
#define NFTA_VERDICT_MAX	(__NFTA_VERDICT_MAX - 1)

enum nft_expr_attributes {
	NFTA_EXPR_UNSPEC,
	NFTA_EXPR_NAME,
	NFTA_EXPR_DATA,
	__NFTA_EXPR_MAX
};
#define NFTA_EXPR_MAX		(__NFTA_EXPR_MAX - 1)

enum nft_immediate_attributes {
	NFTA_IMMEDIATE_UNSPEC,
	NFTA_IMMEDIATE_DREG,
	NFTA_IMMEDIATE_DATA,
	__NFTA_IMMEDIATE_MAX
};
#define NFTA_IMMEDIATE_MAX	(__NFTA_IMMEDIATE_MAX - 1)

enum nft_bitwise_attributes {
	NFTA_BITWISE_UNSPEC,
	NFTA_BITWISE_SREG,
	NFTA_BITWISE_DREG,
	NFTA_BITWISE_LEN,
	NFTA_BITWISE_MASK,
	NFTA_BITWISE_XOR,
	__NFTA_BITWISE_MAX
};
#define NFTA_BITWISE_MAX	(__NFTA_BITWISE_MAX - 1)

enum nft_byteorder_ops {
	NFT_BYTEORDER_NTOH,
	NFT_BYTEORDER_HTON,
};

enum nft_byteorder_attributes {
	NFTA_BYTEORDER_UNSPEC,
	NFTA_BYTEORDER_SREG,
	NFTA_BYTEORDER_DREG,
	NFTA_BYTEORDER_OP,
	NFTA_BYTEORDER_LEN,
	NFTA_BYTEORDER_SIZE,
	__NFTA_BYTEORDER_MAX
};
#define NFTA_BYTEORDER_MAX	(__NFTA_BYTEORDER_MAX - 1)

enum nft_cmp_ops {
	NFT_CMP_EQ,
	NFT_CMP_NEQ,
	NFT_CMP_LT,
	NFT_CMP_LTE,
	NFT_CMP_GT,
	NFT_CMP_GTE,
};

enum nft_cmp_attributes {
	NFTA_CMP_UNSPEC,
	NFTA_CMP_SREG,
	NFTA_CMP_OP,
	NFTA_CMP_DATA,
	__NFTA_CMP_MAX
};
#define NFTA_CMP_MAX		(__NFTA_CMP_MAX - 1)

enum nft_lookup_attributes {
	NFTA_LOOKUP_UNSPEC,
	NFTA_LOOKUP_SET,
	NFTA_LOOKUP_SREG,
	NFTA_LOOKUP_DREG,
	__NFTA_LOOKUP_MAX
};
#define NFTA_LOOKUP_MAX		(__NFTA_LOOKUP_MAX - 1)

enum nft_payload_bases {
	NFT_PAYLOAD_LL_HEADER,
	NFT_PAYLOAD_NETWORK_HEADER,
	NFT_PAYLOAD_TRANSPORT_HEADER,
};

enum nft_payload_attributes {
	NFTA_PAYLOAD_UNSPEC,
	NFTA_PAYLOAD_DREG,
	NFTA_PAYLOAD_BASE,
	NFTA_PAYLOAD_OFFSET,
	NFTA_PAYLOAD_LEN,
	__NFTA_PAYLOAD_MAX
};
#define NFTA_PAYLOAD_MAX	(__NFTA_PAYLOAD_MAX - 1)

enum nft_exthdr_attributes {
	NFTA_EXTHDR_UNSPEC,
	NFTA_EXTHDR_DREG,
	NFTA_EXTHDR_TYPE,
	NFTA_EXTHDR_OFFSET,
	NFTA_EXTHDR_LEN,
	__NFTA_EXTHDR_MAX
};
#define NFTA_EXTHDR_MAX		(__NFTA_EXTHDR_MAX - 1)

enum nft_meta_keys {
	NFT_META_LEN,
	NFT_META_PROTOCOL,
	NFT_META_PRIORITY,
	NFT_META_MARK,
	NFT_META_IIF,
	NFT_META_OIF,
	NFT_META_IIFNAME,
	NFT_META_OIFNAME,
	NFT_META_IIFTYPE,
	NFT_META_OIFTYPE,
	NFT_META_SKUID,
	NFT_META_SKGID,
	NFT_META_NFTRACE,
	NFT_META_RTCLASSID,
	NFT_META_SECMARK,
};

enum nft_meta_attributes {
	NFTA_META_UNSPEC,
	NFTA_META_DREG,
	NFTA_META_KEY,
	__NFTA_META_MAX
};
#define NFTA_META_MAX		(__NFTA_META_MAX - 1)

enum nft_ct_keys {
	NFT_CT_STATE,
	NFT_CT_DIRECTION,
	NFT_CT_STATUS,
	NFT_CT_MARK,
	NFT_CT_SECMARK,
	NFT_CT_EXPIRATION,
	NFT_CT_HELPER,
	NFT_CT_PROTOCOL,
	NFT_CT_SRC,
	NFT_CT_DST,
	NFT_CT_PROTO_SRC,
	NFT_CT_PROTO_DST,
};

enum nft_ct_attributes {
	NFTA_CT_UNSPEC,
	NFTA_CT_DREG,
	NFTA_CT_KEY,
	NFTA_CT_DIRECTION,
	__NFTA_CT_MAX
};
#define NFTA_CT_MAX		(__NFTA_CT_MAX - 1)

enum nft_limit_attributes {
	NFTA_LIMIT_UNSPEC,
	NFTA_LIMIT_RATE,
	NFTA_LIMIT_DEPTH,
	__NFTA_LIMIT_MAX
};
#define NFTA_LIMIT_MAX		(__NFTA_LIMIT_MAX - 1)

enum nft_counter_attributes {
	NFTA_COUNTER_UNSPEC,
	NFTA_COUNTER_BYTES,
	NFTA_COUNTER_PACKETS,
	__NFTA_COUNTER_MAX
};
#define NFTA_COUNTER_MAX	(__NFTA_COUNTER_MAX - 1)

enum nft_log_attributes {
	NFTA_LOG_UNSPEC,
	NFTA_LOG_GROUP,
	NFTA_LOG_PREFIX,
	NFTA_LOG_SNAPLEN,
	NFTA_LOG_QTHRESHOLD,
	__NFTA_LOG_MAX
};
#define NFTA_LOG_MAX		(__NFTA_LOG_MAX - 1)

enum nft_reject_types {
	NFT_REJECT_ICMP_UNREACH,
	NFT_REJECT_TCP_RST,
};

enum nft_reject_attributes {
	NFTA_REJECT_UNSPEC,
	NFTA_REJECT_TYPE,
	NFTA_REJECT_ICMP_CODE,
	__NFTA_REJECT_MAX
};
#define NFTA_REJECT_MAX		(__NFTA_REJECT_MAX - 1)

enum nft_nat_types {
	NFT_NAT_SNAT,
	NFT_NAT_DNAT,
};

enum nft_nat_attributes {
	NFTA_NAT_UNSPEC,
	NFTA_NAT_TYPE,
	NFTA_NAT_ADDR_MIN,
	NFTA_NAT_ADDR_MAX,
	NFTA_NAT_PROTO_MIN,
	NFTA_NAT_PROTO_MAX,
	__NFTA_NAT_MAX
};
#define NFTA_NAT_MAX		(__NFTA_NAT_MAX - 1)

#endif /* _LINUX_NF_TABLES_H */
