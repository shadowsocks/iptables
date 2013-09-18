#ifndef _NFT_H_
#define _NFT_H_

#include "xshared.h"
#include "nft-shared.h"
#include <libiptc/linux_list.h>

#define FILTER         0
#define MANGLE         1
#define RAW            2
#define SECURITY       3
#define NAT            4
#define TABLES_MAX     5

struct builtin_chain {
	const char *name;
	const char *type;
	uint32_t prio;
	uint32_t hook;
};

struct builtin_table {
	const char *name;
	struct builtin_chain chains[NF_INET_NUMHOOKS];
};

struct nft_handle {
	int			family;
	struct mnl_socket	*nl;
	uint32_t		portid;
	uint32_t		seq;
	struct list_head	rule_list;
	int			rule_list_num;
	struct mnl_nlmsg_batch	*batch;
	struct nft_family_ops	*ops;
	struct builtin_table	*tables;
};

extern struct builtin_table xtables_ipv4[TABLES_MAX];
extern struct builtin_table xtables_arp[TABLES_MAX];

int mnl_talk(struct nft_handle *h, struct nlmsghdr *nlh,
	     int (*cb)(const struct nlmsghdr *nlh, void *data),
	     void *data);
int nft_init(struct nft_handle *h, struct builtin_table *t);
void nft_fini(struct nft_handle *h);

/*
 * Operations with tables.
 */
struct nft_table;
struct nft_chain_list;

int nft_table_builtin_add(struct nft_handle *h, struct builtin_table *_t, bool dormant);
struct builtin_table *nft_table_builtin_find(struct nft_handle *h, const char *table);
int nft_table_add(struct nft_handle *h, const struct nft_table *t);
int nft_for_each_table(struct nft_handle *h, int (*func)(struct nft_handle *h, const char *tablename, bool counters), bool counters);
bool nft_table_find(struct nft_handle *h, const char *tablename);
int nft_table_set_dormant(struct nft_handle *h, const char *table);
int nft_table_wake_dormant(struct nft_handle *h, const char *table);
int nft_table_purge_chains(struct nft_handle *h, const char *table, struct nft_chain_list *list);

/*
 * Operations with chains.
 */
struct nft_chain;

struct nft_chain *nft_chain_builtin_alloc(struct builtin_table *table, struct builtin_chain *chain, int policy);
void nft_chain_builtin_add(struct nft_handle *h, struct builtin_table *table, struct builtin_chain *chain, int policy);
struct builtin_chain *nft_chain_builtin_find(struct builtin_table *t, const char *chain);
int nft_chain_builtin_init(struct nft_handle *h, const char *table, const char *chain, int policy);
int nft_chain_add(struct nft_handle *h, const struct nft_chain *c);
int nft_chain_set(struct nft_handle *h, const char *table, const char *chain, const char *policy, const struct xt_counters *counters);
struct nft_chain_list *nft_chain_dump(struct nft_handle *h);
struct nft_chain *nft_chain_list_find(struct nft_chain_list *list, const char *table, const char *chain);
int nft_chain_save(struct nft_handle *h, struct nft_chain_list *list, const char *table);
int nft_chain_user_add(struct nft_handle *h, const char *chain, const char *table);
int nft_chain_user_del(struct nft_handle *h, const char *chain, const char *table);
int nft_chain_user_rename(struct nft_handle *h, const char *chain, const char *table, const char *newname);
int nft_chain_zero_counters(struct nft_handle *h, const char *chain, const char *table);

/*
 * Operations with rule-set.
 */
struct nft_rule;

int nft_rule_append(struct nft_handle *h, const char *chain, const char *table, void *data, uint64_t handle, bool verbose);
int nft_rule_insert(struct nft_handle *h, const char *chain, const char *table, void *data, int rulenum, bool verbose);
int nft_rule_check(struct nft_handle *h, const char *chain, const char *table, void *data, bool verbose);
int nft_rule_delete(struct nft_handle *h, const char *chain, const char *table, void *data, bool verbose);
int nft_rule_delete_num(struct nft_handle *h, const char *chain, const char *table, int rulenum, bool verbose);
int nft_rule_replace(struct nft_handle *h, const char *chain, const char *table, void *data, int rulenum, bool verbose);
int nft_rule_list(struct nft_handle *h, const char *chain, const char *table, int rulenum, unsigned int format);
int nft_rule_list_save(struct nft_handle *h, const char *chain, const char *table, int rulenum, int counters);
int nft_rule_save(struct nft_handle *h, const char *table, bool counters);
int nft_rule_flush(struct nft_handle *h, const char *chain, const char *table);
int nft_rule_zero_counters(struct nft_handle *h, const char *chain, const char *table, int rulenum);

struct nft_rule_list *nft_rule_list_create(struct nft_handle *h);
void nft_rule_list_destroy(struct nft_rule_list *list);

/*
 * Operations used in userspace tools
 */
int add_counters(struct nft_rule *r, uint64_t packets, uint64_t bytes);
int add_verdict(struct nft_rule *r, int verdict);
int add_match(struct nft_rule *r, struct xt_entry_match *m);
int add_target(struct nft_rule *r, struct xt_entry_target *t);
int add_jumpto(struct nft_rule *r, const char *name, int verdict);
int add_action(struct nft_rule *r, struct iptables_command_state *cs, int ip_flags);

enum nft_rule_print {
	NFT_RULE_APPEND,
	NFT_RULE_DEL,
};

void nft_rule_print_save(const struct iptables_command_state *cs,
			 struct nft_rule *r, enum nft_rule_print type,
			 unsigned int format);

/*
 * global commit and abort
 */
int nft_commit(struct nft_handle *h);
int nft_abort(struct nft_handle *h);

/*
 * revision compatibility.
 */
int nft_compatible_revision(const char *name, uint8_t rev, int opt);

/*
 * Error reporting.
 */
const char *nft_strerror(int err);

/* For xtables.c */
int do_commandx(struct nft_handle *h, int argc, char *argv[], char **table);
/* For xtables-arptables.c */
int do_commandarp(struct nft_handle *h, int argc, char *argv[], char **table);

/*
 * Parse config for tables and chain helper functions
 */
#define XTABLES_CONFIG_DEFAULT  "/etc/xtables.conf"

struct nft_table_list;
struct nft_chain_list;

extern int xtables_config_parse(const char *filename, struct nft_table_list *table_list, struct nft_chain_list *chain_list);

enum {
	NFT_LOAD_VERBOSE = (1 << 0),
};

int nft_xtables_config_load(struct nft_handle *h, const char *filename, uint32_t flags);

/*
 * ARP
 */

struct arpt_entry;

int nft_arp_rule_append(struct nft_handle *h, const char *chain,
			const char *table, struct arpt_entry *fw,
			bool verbose);
int nft_arp_rule_insert(struct nft_handle *h, const char *chain,
			const char *table, struct arpt_entry *fw,
			int rulenum, bool verbose);

void nft_rule_to_arpt_entry(struct nft_rule *r, struct arpt_entry *fw);

#endif
