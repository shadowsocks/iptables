/* Header file for iptables ipt_ECN target
 *
 * (C) 2002 by Harald Welte <laforge@gnumonks.org>
 *
 * This software is distributed under GNU GPL v2, 1991
 * 
 * ipt_ECN.h,v 1.1 2002/02/17 21:30:16 laforge Exp
*/
#ifndef _IPT_DSCP_H
#define _IPT_DSCP_H
#include <linux/netfilter_ipv4/ipt_DSCP.h>

#define IPT_ECN_MASK	(~IPT_DSCP_MASK)

enum ipt_ecn_operation {
	IPT_ECN_OP_NONE = 0,
	IPT_ECN_OP_REMOVE,
};
#define IPT_ECN_OP_MAX	IPT_ECN_OP_REMOVE

struct ipt_ECN_info {
	enum ipt_ecn_operation operation;
};

#endif /* _IPT_ECN_H */
