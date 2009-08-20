/* iptables module for using NFQUEUE mechanism
 *
 * (C) 2005 Harald Welte <laforge@netfilter.org>
 *
 * This software is distributed under GNU GPL v2, 1991
 * 
*/
#ifndef _XT_NFQ_TARGET_H
#define _XT_NFQ_TARGET_H

/* target info */
struct xt_NFQ_info {
	u_int16_t queuenum;
};

struct xt_NFQ_info_v1 {
	u_int16_t queuenum;
	u_int16_t queues_total;
};

#endif /* _XT_NFQ_TARGET_H */
