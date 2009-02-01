#ifndef _XTABLES_INTERNAL_H
#define _XTABLES_INTERNAL_H 1

#ifndef XT_LIB_DIR
#	define XT_LIB_DIR "/usr/local/lib/iptables"
#endif

/* protocol family dependent informations */
struct afinfo {
	/* protocol family */
	int family;

	/* prefix of library name (ex "libipt_" */
	char *libprefix;

	/* used by setsockopt (ex IPPROTO_IP */
	int ipproto;

	/* kernel module (ex "ip_tables" */
	char *kmod;

	/* optname to check revision support of match */
	int so_rev_match;

	/* optname to check revision support of match */
	int so_rev_target;
};

extern char *lib_dir;

/* This is decleared in ip[6]tables.c */
extern struct afinfo afinfo;

extern void _init(void);

#endif /* _XTABLES_INTERNAL_H */
