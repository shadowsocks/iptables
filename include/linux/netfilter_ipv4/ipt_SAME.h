#ifndef _IPT_SAME_H
#define _IPT_SAME_H

#define IPT_SAME_NODST		0x01

struct ipt_same_info
{
	unsigned char info;

	unsigned int rangesize;

	/* hangs off end. */
	struct ip_nat_range range[1];
};

#endif /*_IPT_SAME_H*/
