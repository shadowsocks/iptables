/* Set DSCP field
 *
 * (C) 2000-2002 by Matthew G. Marsh <mgm@paktronix.com>
 *		     Harald Welte <laforge@gnumonks.org>
 *
 * This software is distributed under GNU GPL v2, 1991
 * 
 * ipt_DSCP.h borrowed heavily from ipt_TOS.h  11/09/2000
 *
 * $Id: ipt_DSCP.h,v 1.3 2002/02/17 19:56:28 laforge Exp $
*/
#ifndef _IPT_DSCP_H
#define _IPT_DSCP_H

#define IPT_DSCP_MASK	0xf4	/* 11111100 */
#define IPT_DSCP_SHIFT	2	/* shift DSCP two bits for ECN */
#define IPT_DSCP_MAX	0x3f	/* 00111111 */

struct ipt_DSCP_info {
	u_int8_t dscp;
};

#endif /* _IPT_DSCP_H */
