#ifndef _IPTABLES_COMMON_H
#define _IPTABLES_COMMON_H
/* Shared definitions between ipv4 and ipv6. */

enum exittype {
	OTHER_PROBLEM = 1,
	PARAMETER_PROBLEM,
	VERSION_PROBLEM,
	RESOURCE_PROBLEM
};

/* this is a special 64bit data type that is 8-byte aligned */
#define aligned_u64 unsigned long long __attribute__((aligned(8)))

extern void exit_printhelp() __attribute__((noreturn));
extern void exit_tryhelp(int) __attribute__((noreturn));
int check_inverse(const char option[], int *invert, int *optind, int argc);
void exit_error(enum exittype, char *, ...)__attribute__((noreturn,
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

#define __be32	u_int32_t
#define __le32	u_int32_t
#define __be16	u_int16_t
#define __le16	u_int16_t

#endif /*_IPTABLES_COMMON_H*/
