/* Set DSCP field
 *
 * (C) 2000-2002 by Matthew G. Marsh <mgm@paktronix.com>
 *		     Harald Welte <laforge@gnumonks.org>
 *
 * This software is distributed under GNU GPL v2, 1991
 * 
 * ipt_DSCP.h borrowed heavily from ipt_TOS.h  11/09/2000
*/
#ifndef _IPT_DSCP_H
#define _IPT_DSCP_H

#define IPT_DSCP_MASK	0x4f

struct ipt_DSCP_info {
	u_int8_t dscp;
};

