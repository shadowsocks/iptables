#ifndef _NFT_H_
#define _NFT_H_

#include "xshared.h"

struct nft_handle {
	struct mnl_socket	*nl;
	uint32_t		portid;
	uint32_t		seq;
};

int nft_init(struct nft_handle *h);
void nft_fini(struct nft_handle *h);

/*
 * Operations with tables.
 */
struct nft_table;

int nft_table_add(struct nft_handle *h, const struct nft_table *t);
int nft_for_each_table(struct nft_handle *h, int (*func)(struct nft_handle *h, const char *tablename, bool counters), bool counters);
bool nft_table_find(struct nft_handle *h, const char *tablename);

/*
 * Operations with chains.
 */
struct nft_chain;

int nft_chain_add(struct nft_handle *h, const struct nft_chain *c);
int nft_chain_set(struct nft_handle *h, const char *table, const char *chain, const char *policy, const struct xt_counters *counters);
struct nft_chain_list *nft_chain_dump(struct nft_handle *h);
int nft_chain_save(struct nft_handle *h, struct nft_chain_list *list, const char *table);
int nft_chain_user_add(struct nft_handle *h, const char *chain, const char *table);
int nft_chain_user_del(struct nft_handle *h, const char *chain, const char *table);
int nft_chain_user_rename(struct nft_handle *h, const char *chain, const char *table, const char *newname);

/*
 * Operations with rule-set.
 */
struct nft_rule;

int nft_rule_add(struct nft_handle *h, const char *chain, const char *table, struct iptables_command_state *cmd, bool append, uint64_t handle, bool verbose);
int nft_rule_check(struct nft_handle *h, const char *chain, const char *table, struct iptables_command_state *cmd, bool verbose);
int nft_rule_delete(struct nft_handle *h, const char *chain, const char *table, struct iptables_command_state *cmd, bool verbose);
int nft_rule_delete_num(struct nft_handle *h, const char *chain, const char *table, int rulenum, bool verbose);
int nft_rule_replace(struct nft_handle *h, const char *chain, const char *table, struct iptables_command_state *cmd, int rulenum, bool verbose);
int nft_rule_list(struct nft_handle *h, const char *chain, const char *table, int rulenum, unsigned int format);
int nft_rule_list_save(struct nft_handle *h, const char *chain, const char *table, int rulenum, int counters);
int nft_rule_save(struct nft_handle *h, const char *table, bool counters);
int nft_rule_flush(struct nft_handle *h, const char *chain, const char *table);

/*
 * revision compatibility.
 */
int nft_compatible_revision(const char *name, uint8_t rev, int opt);

/*
 * Error reporting.
 */
const char *nft_strerror(int err);

#endif
