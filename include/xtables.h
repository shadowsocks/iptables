#ifndef _XTABLES_H
#define _XTABLES_H

#include <sys/types.h>
#include <linux/types.h>
#include <linux/netfilter/x_tables.h>
#include <libiptc/libxtc.h>

#ifndef XT_LIB_DIR
#define XT_LIB_DIR "/usr/local/lib/iptables"
#endif

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif
#ifndef IPPROTO_DCCP
#define IPPROTO_DCCP 33
#endif
#ifndef IPPROTO_UDPLITE
#define IPPROTO_UDPLITE	136
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

enum xt_tryload {
	DONT_LOAD,
	DURING_LOAD,
	TRY_LOAD,
	LOAD_MUST_SUCCEED
};

struct xtables_rule_match
{
	struct xtables_rule_match *next;
	struct xtables_match *match;
	/* Multiple matches of the same type: the ones before
	   the current one are completed from parsing point of view */
	unsigned int completed;
};

/* Include file for additions: new matches and targets. */
struct xtables_match
{
	struct xtables_match *next;

	xt_chainlabel name;

	/* Revision of match (0 by default). */
	u_int8_t revision;

	u_int16_t family;

	const char *version;

	/* Size of match data. */
	size_t size;

	/* Size of match data relevent for userspace comparison purposes */
	size_t userspacesize;

	/* Function which prints out usage message. */
	void (*help)(void);

	/* Initialize the match. */
	void (*init)(struct xt_entry_match *m);

	/* Function which parses command options; returns true if it
           ate an option */
	/* entry is struct ipt_entry for example */
	int (*parse)(int c, char **argv, int invert, unsigned int *flags,
		     const void *entry,
		     struct xt_entry_match **match);

	/* Final check; exit if not ok. */
	void (*final_check)(unsigned int flags);

	/* Prints out the match iff non-NULL: put space at end */
	/* ip is struct ipt_ip * for example */
	void (*print)(const void *ip,
		      const struct xt_entry_match *match, int numeric);

	/* Saves the match info in parsable form to stdout. */
	/* ip is struct ipt_ip * for example */
	void (*save)(const void *ip, const struct xt_entry_match *match);

	/* Pointer to list of extra command-line options */
	const struct option *extra_opts;

	/* Ignore these men behind the curtain: */
	unsigned int option_offset;
	struct xt_entry_match *m;
	unsigned int mflags;
#ifdef NO_SHARED_LIBS
	unsigned int loaded; /* simulate loading so options are merged properly */
#endif
};

struct xtables_target
{
	struct xtables_target *next;

	xt_chainlabel name;

	/* Revision of target (0 by default). */
	u_int8_t revision;

	u_int16_t family;

	const char *version;

	/* Size of target data. */
	size_t size;

	/* Size of target data relevent for userspace comparison purposes */
	size_t userspacesize;

	/* Function which prints out usage message. */
	void (*help)(void);

	/* Initialize the target. */
	void (*init)(struct xt_entry_target *t);

	/* Function which parses command options; returns true if it
           ate an option */
	/* entry is struct ipt_entry for example */
	int (*parse)(int c, char **argv, int invert, unsigned int *flags,
		     const void *entry,
		     struct xt_entry_target **targetinfo);

	/* Final check; exit if not ok. */
	void (*final_check)(unsigned int flags);

	/* Prints out the target iff non-NULL: put space at end */
	void (*print)(const void *ip,
		      const struct xt_entry_target *target, int numeric);

	/* Saves the targinfo in parsable form to stdout. */
	void (*save)(const void *ip,
		     const struct xt_entry_target *target);

	/* Pointer to list of extra command-line options */
	const struct option *extra_opts;

	/* Ignore these men behind the curtain: */
	unsigned int option_offset;
	struct xt_entry_target *t;
	unsigned int tflags;
	unsigned int used;
#ifdef NO_SHARED_LIBS
	unsigned int loaded; /* simulate loading so options are merged properly */
#endif
};

extern char *lib_dir;

extern void *fw_calloc(size_t count, size_t size);
extern void *fw_malloc(size_t size);

extern const char *modprobe;
extern int xtables_insmod(const char *modname, const char *modprobe, int quiet);
extern int load_xtables_ko(const char *modprobe, int quiet);

/* This is decleared in ip[6]tables.c */
extern struct afinfo afinfo;

/* Keeping track of external matches and targets: linked lists.  */
extern struct xtables_match *xtables_matches;
extern struct xtables_target *xtables_targets;

/* Your shared library should call one of these. */
extern void xtables_register_match(struct xtables_match *me);
extern void xtables_register_target(struct xtables_target *me);

extern struct xtables_match *find_match(const char *name, enum xt_tryload,
					struct xtables_rule_match **match);
extern struct xtables_target *find_target(const char *name, enum xt_tryload);

extern int string_to_number_ll(const char *s,
			       unsigned long long min,
			       unsigned long long max,
			       unsigned long long *ret);
extern int string_to_number_l(const char *s,
			      unsigned long min,
			      unsigned long max,
			      unsigned long *ret);
extern int string_to_number(const char *s,
			    unsigned int min,
			    unsigned int max,
			    unsigned int *ret);
extern int service_to_port(const char *name, const char *proto);
extern u_int16_t parse_port(const char *port, const char *proto);
extern void
parse_interface(const char *arg, char *vianame, unsigned char *mask);

enum exittype {
	OTHER_PROBLEM = 1,
	PARAMETER_PROBLEM,
	VERSION_PROBLEM,
	RESOURCE_PROBLEM
};

/* this is a special 64bit data type that is 8-byte aligned */
#define aligned_u64 u_int64_t __attribute__((aligned(8)))

int check_inverse(const char option[], int *invert, int *optind, int argc);
void exit_error(enum exittype, const char *, ...)__attribute__((noreturn,
							  format(printf,2,3)));
extern const char *program_name, *program_version;

#define _init __attribute__((constructor)) my_init
#ifdef NO_SHARED_LIBS
# ifdef _INIT
#  undef _init
#  define _init _INIT
# endif
  extern void init_extensions(void);
#endif

#endif /* _XTABLES_H */
