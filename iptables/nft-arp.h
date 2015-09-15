#ifndef _NFT_ARP_H_
#define _NFT_ARP_H_

extern char *opcodes[];
#define NUMOPCODES 9

struct arptables_command_state {
	struct arpt_entry fw;
	struct xtables_target *target;
	const char *jumpto;
};

void nft_rule_to_arptables_command_state(struct nftnl_rule *r,
					 struct arptables_command_state *cs);

#endif
