#ifndef _IPT_CONNMARK_H_target
#define _IPT_CONNMARK_H_target

enum {
	IPT_CONNMARK_SET = 0,
	IPT_CONNMARK_SAVE,
	IPT_CONNMARK_RESTORE
};

struct ipt_connmark_target_info {
	unsigned long mark;
	u_int8_t mode;
};

#endif /*_IPT_CONNMARK_H_target*/
