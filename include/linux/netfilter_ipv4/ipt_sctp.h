/* iptables module for matching the SCTP header
 *
 * (C) 2003 Harald Welte <laforge@gnumonks.org>
 *
 * This software is distributed under GNU GPL v2, 1991
 *
 * $Id$
 */
#ifndef _IPT_SCTP_H
#define _IPT_SCTP_H

struct ipt_sctp_info {
	u_int16_t spts[2];			/* Souce port range */
	u_int16_t dpts[2];			/* Destination port range */
	u_int32_t chunks;			/* chunks to be matched */
	u_int32_t chunk_mask;			/* chunk mask to be matched */
	u_int8_t invflags;			/* Inverse flags */
};

#define IPT_SCTP_INV_SRCPT	0x01	/* Invert the sense of source ports */
#define IPT_SCTP_INV_DSTPT	0x02	/* Invert the sense of dest ports */
#define IPT_SCTP_INV_CHUNKS	0x03	/* Invert the sense of chunks */
#define IPT_SCTP_INV_MASK	0x03	/* All possible flags */

#endif /* _IPT_SCTP_H */
