#ifndef _IPT_CONNMARK_H
#define _IPT_CONNMARK_H

struct ipt_connmark_info {
	unsigned long mark, mask;
	u_int8_t invert;
};

#endif /*_IPT_CONNMARK_H*/
