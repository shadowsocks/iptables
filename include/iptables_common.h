#ifndef _IPTABLES_COMMON_H
#define _IPTABLES_COMMON_H
/* Shared definitions between ipv4 and ipv6. */

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
extern const char *program_name, *program_version;

#endif /*_IPTABLES_COMMON_H*/
