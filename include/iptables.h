#ifndef _IPTABLES_USER_H
#define _IPTABLES_USER_H

#include "libiptc/libiptc.h"

/* Include file for additions: new matches and targets. */
struct iptables_match
{
	struct iptables_match *next;

	ipt_chainlabel name;

	const char *version;

	/* Size of match data. */
	size_t size;

	/* Size of match data relevent for userspace comparison purposes */
	size_t userspacesize;

	/* Function which prints out usage message. */
	void (*help)(void);

	/* Initialize the match. */
	void (*init)(struct ipt_entry_match *m, unsigned int *nfcache);

	/* Function which parses command options; returns true if it
           ate an option */
	int (*parse)(int c, char **argv, int invert, unsigned int *flags,
		     const struct ipt_entry *entry,
		     unsigned int *nfcache,
		     struct ipt_entry_match **match);

	/* Final check; exit if not ok. */
	void (*final_check)(unsigned int flags);

	/* Prints out the match iff non-NULL: put space at end */
	void (*print)(const struct ipt_ip *ip,
		      const struct ipt_entry_match *match, int numeric);

	/* Saves the union ipt_matchinfo in parsable form to stdout. */
	void (*save)(const struct ipt_ip *ip,
		     const struct ipt_entry_match *match);

	/* Pointer to list of extra command-line options */
	struct option *extra_opts;

	/* Ignore these men behind the curtain: */
	unsigned int option_offset;
	struct ipt_entry_match *m;
	unsigned int mflags;
};

struct iptables_target
{
	struct iptables_target *next;

	ipt_chainlabel name;

	const char *version;

	/* Size of target data. */
	size_t size;

	/* Size of target data relevent for userspace comparison purposes */
	size_t userspacesize;

	/* Function which prints out usage message. */
	void (*help)(void);

	/* Initialize the target. */
	void (*init)(struct ipt_entry_target *t, unsigned int *nfcache);

	/* Function which parses command options; returns true if it
           ate an option */
	int (*parse)(int c, char **argv, int invert, unsigned int *flags,
		     const struct ipt_entry *entry,
		     struct ipt_entry_target **target);

	/* Final check; exit if not ok. */
	void (*final_check)(unsigned int flags);

	/* Prints out the target iff non-NULL: put space at end */
	void (*print)(const struct ipt_ip *ip,
		      const struct ipt_entry_target *target, int numeric);

	/* Saves the targinfo in parsable form to stdout. */
	void (*save)(const struct ipt_ip *ip,
		     const struct ipt_entry_target *target);

	/* Pointer to list of extra command-line options */
	struct option *extra_opts;

	/* Ignore these men behind the curtain: */
	unsigned int option_offset;
	struct ipt_entry_target *t;
	unsigned int tflags;
};

/* Your shared library should call one of these. */
extern void register_match(struct iptables_match *me);
extern void register_target(struct iptables_target *me);

/* Functions we share */
enum exittype {
	OTHER_PROBLEM = 1,
	PARAMETER_PROBLEM,
	VERSION_PROBLEM
};
extern void exit_printhelp() __attribute__((noreturn));
extern void exit_tryhelp(int) __attribute__((noreturn));
int check_inverse(const char option[], int *invert);
extern int string_to_number(const char *, int, int);
void exit_error(enum exittype, char *, ...)__attribute__((noreturn,
							  format(printf,2,3)));
extern char *addr_to_dotted(const struct in_addr *addrp);
struct in_addr *dotted_to_addr(const char *dotted);
extern const char *program_name, *program_version;

extern int do_command(int argc, char *argv[], char **table,
		      iptc_handle_t *handle);
/* Keeping track of external matches and targets: linked lists.  */
extern struct iptables_match *iptables_matches;
extern struct iptables_target *iptables_targets;

extern struct iptables_target *find_target(const char *name, int tryload);
extern struct iptables_match *find_match(const char *name, int tryload);
#endif /*_IPTABLES_USER_H*/
