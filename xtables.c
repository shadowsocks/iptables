/*
 * (C) 2000-2006 by the netfilter coreteam <coreteam@netfilter.org>:
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <xtables.h>

#ifndef NO_SHARED_LIBS
#include <dlfcn.h>
#endif

#define NPROTO	255

#ifndef PROC_SYS_MODPROBE
#define PROC_SYS_MODPROBE "/proc/sys/kernel/modprobe"
#endif

char *lib_dir;

/* the path to command to load kernel module */
const char *modprobe = NULL;

/* Keeping track of external matches and targets: linked lists.  */
struct xtables_match *xtables_matches;
struct xtables_target *xtables_targets;

void *fw_calloc(size_t count, size_t size)
{
	void *p;

	if ((p = calloc(count, size)) == NULL) {
		perror("ip[6]tables: calloc failed");
		exit(1);
	}

	return p;
}

void *fw_malloc(size_t size)
{
	void *p;

	if ((p = malloc(size)) == NULL) {
		perror("ip[6]tables: malloc failed");
		exit(1);
	}

	return p;
}

static char *get_modprobe(void)
{
	int procfile;
	char *ret;

#define PROCFILE_BUFSIZ	1024
	procfile = open(PROC_SYS_MODPROBE, O_RDONLY);
	if (procfile < 0)
		return NULL;

	ret = (char *) malloc(PROCFILE_BUFSIZ);
	if (ret) {
		memset(ret, 0, PROCFILE_BUFSIZ);
		switch (read(procfile, ret, PROCFILE_BUFSIZ)) {
		case -1: goto fail;
		case PROCFILE_BUFSIZ: goto fail; /* Partial read.  Wierd */
		}
		if (ret[strlen(ret)-1]=='\n') 
			ret[strlen(ret)-1]=0;
		close(procfile);
		return ret;
	}
 fail:
	free(ret);
	close(procfile);
	return NULL;
}

int xtables_insmod(const char *modname, const char *modprobe, int quiet)
{
	char *buf = NULL;
	char *argv[4];
	int status;

	/* If they don't explicitly set it, read out of kernel */
	if (!modprobe) {
		buf = get_modprobe();
		if (!buf)
			return -1;
		modprobe = buf;
	}

	switch (fork()) {
	case 0:
		argv[0] = (char *)modprobe;
		argv[1] = (char *)modname;
		if (quiet) {
			argv[2] = "-q";
			argv[3] = NULL;
		} else {
			argv[2] = NULL;
			argv[3] = NULL;
		}
		execv(argv[0], argv);

		/* not usually reached */
		exit(1);
	case -1:
		return -1;

	default: /* parent */
		wait(&status);
	}

	free(buf);
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return 0;
	return -1;
}

int load_xtables_ko(const char *modprobe, int quiet)
{
	static int loaded = 0;
	static int ret = -1;

	if (!loaded) {
		ret = xtables_insmod(afinfo.kmod, modprobe, quiet);
		loaded = (ret == 0);
	}

	return ret;
}

int string_to_number_ll(const char *s, unsigned long long min,
			unsigned long long max, unsigned long long *ret)
{
	unsigned long long number;
	char *end;

	/* Handle hex, octal, etc. */
	errno = 0;
	number = strtoull(s, &end, 0);
	if (*end == '\0' && end != s) {
		/* we parsed a number, let's see if we want this */
		if (errno != ERANGE && min <= number && (!max || number <= max)) {
			*ret = number;
			return 0;
		}
	}
	return -1;
}

int string_to_number_l(const char *s, unsigned long min, unsigned long max,
		       unsigned long *ret)
{
	int result;
	unsigned long long number;

	result = string_to_number_ll(s, min, max, &number);
	*ret = (unsigned long)number;

	return result;
}

int string_to_number(const char *s, unsigned int min, unsigned int max,
		unsigned int *ret)
{
	int result;
	unsigned long number;

	result = string_to_number_l(s, min, max, &number);
	*ret = (unsigned int)number;

	return result;
}

/*
 * strtonum{,l} - string to number conversion
 *
 * If @end is NULL, we assume the caller does not want
 * a case like "15a", so reject it.
 */
bool strtonuml(const char *s, char **end, unsigned long *value,
               unsigned long min, unsigned long max)
{
	unsigned long v;
	char *my_end;

	errno = 0;
	v = strtoul(s, &my_end, 0);

	if (my_end == s)
		return false;
	if (end != NULL)
		*end = my_end;

	if (errno != ERANGE && min <= v && (max == 0 || v <= max)) {
		if (value != NULL)
			*value = v;
		if (end == NULL)
			return *my_end == '\0';
		return true;
	}

	return false;
}

bool strtonum(const char *s, char **end, unsigned int *value,
                  unsigned int min, unsigned int max)
{
	unsigned long v;
	bool ret;

	ret = strtonuml(s, end, &v, min, max);
	if (value != NULL)
		*value = v;
	return ret;
}

int service_to_port(const char *name, const char *proto)
{
	struct servent *service;

	if ((service = getservbyname(name, proto)) != NULL)
		return ntohs((unsigned short) service->s_port);

	return -1;
}

u_int16_t parse_port(const char *port, const char *proto)
{
	unsigned int portnum;

	if ((string_to_number(port, 0, 65535, &portnum)) != -1 ||
	    (portnum = service_to_port(port, proto)) != -1)
		return (u_int16_t)portnum;

	exit_error(PARAMETER_PROBLEM,
		   "invalid port/service `%s' specified", port);
}

void parse_interface(const char *arg, char *vianame, unsigned char *mask)
{
	int vialen = strlen(arg);
	unsigned int i;

	memset(mask, 0, IFNAMSIZ);
	memset(vianame, 0, IFNAMSIZ);

	if (vialen + 1 > IFNAMSIZ)
		exit_error(PARAMETER_PROBLEM,
			   "interface name `%s' must be shorter than IFNAMSIZ"
			   " (%i)", arg, IFNAMSIZ-1);

	strcpy(vianame, arg);
	if ((vialen == 0) || (vialen == 1 && vianame[0] == '+'))
		memset(mask, 0, IFNAMSIZ);
	else if (vianame[vialen - 1] == '+') {
		memset(mask, 0xFF, vialen - 1);
		memset(mask + vialen - 1, 0, IFNAMSIZ - vialen + 1);
		/* Don't remove `+' here! -HW */
	} else {
		/* Include nul-terminator in match */
		memset(mask, 0xFF, vialen + 1);
		memset(mask + vialen + 1, 0, IFNAMSIZ - vialen - 1);
		for (i = 0; vianame[i]; i++) {
			if (vianame[i] == ':' ||
			    vianame[i] == '!' ||
			    vianame[i] == '*') {
				fprintf(stderr,
					"Warning: weird character in interface"
					" `%s' (No aliases, :, ! or *).\n",
					vianame);
				break;
			}
		}
	}
}

struct xtables_match *find_match(const char *name, enum xt_tryload tryload,
				 struct xtables_rule_match **matches)
{
	struct xtables_match *ptr;
	const char *icmp6 = "icmp6";

	/* This is ugly as hell. Nonetheless, there is no way of changing
	 * this without hurting backwards compatibility */
	if ( (strcmp(name,"icmpv6") == 0) ||
	     (strcmp(name,"ipv6-icmp") == 0) ||
	     (strcmp(name,"icmp6") == 0) )
		name = icmp6;

	for (ptr = xtables_matches; ptr; ptr = ptr->next) {
		if (strcmp(name, ptr->name) == 0) {
			struct xtables_match *clone;

			/* First match of this type: */
			if (ptr->m == NULL)
				break;

			/* Second and subsequent clones */
			clone = fw_malloc(sizeof(struct xtables_match));
			memcpy(clone, ptr, sizeof(struct xtables_match));
			clone->mflags = 0;
			/* This is a clone: */
			clone->next = clone;

			ptr = clone;
			break;
		}
	}

#ifndef NO_SHARED_LIBS
	if (!ptr && tryload != DONT_LOAD && tryload != DURING_LOAD) {
		char path[strlen(lib_dir) + sizeof("/.so")
			  + strlen(afinfo.libprefix) + strlen(name)];

		sprintf(path, "%s/libxt_%s.so", lib_dir, name);
		if (dlopen(path, RTLD_NOW) != NULL)
			/* Found library.  If it didn't register itself,
			   maybe they specified target as match. */
			ptr = find_match(name, DONT_LOAD, NULL);

		if (ptr == NULL) {
			sprintf(path, "%s/%s%s.so", lib_dir, afinfo.libprefix,
				name);
			if (dlopen(path, RTLD_NOW) != NULL)
				ptr = find_match(name, DONT_LOAD, NULL);
		}

		if (ptr == NULL && tryload == LOAD_MUST_SUCCEED)
			exit_error(PARAMETER_PROBLEM,
				   "Couldn't load match `%s':%s\n",
				   name, dlerror());
	}
#else
	if (ptr && !ptr->loaded) {
		if (tryload != DONT_LOAD)
			ptr->loaded = 1;
		else
			ptr = NULL;
	}
	if(!ptr && (tryload == LOAD_MUST_SUCCEED)) {
		exit_error(PARAMETER_PROBLEM,
			   "Couldn't find match `%s'\n", name);
	}
#endif

	if (ptr && matches) {
		struct xtables_rule_match **i;
		struct xtables_rule_match *newentry;

		newentry = fw_malloc(sizeof(struct xtables_rule_match));

		for (i = matches; *i; i = &(*i)->next) {
			if (strcmp(name, (*i)->match->name) == 0)
				(*i)->completed = 1;
		}
		newentry->match = ptr;
		newentry->completed = 0;
		newentry->next = NULL;
		*i = newentry;
	}

	return ptr;
}


struct xtables_target *find_target(const char *name, enum xt_tryload tryload)
{
	struct xtables_target *ptr;

	/* Standard target? */
	if (strcmp(name, "") == 0
	    || strcmp(name, XTC_LABEL_ACCEPT) == 0
	    || strcmp(name, XTC_LABEL_DROP) == 0
	    || strcmp(name, XTC_LABEL_QUEUE) == 0
	    || strcmp(name, XTC_LABEL_RETURN) == 0)
		name = "standard";

	for (ptr = xtables_targets; ptr; ptr = ptr->next) {
		if (strcmp(name, ptr->name) == 0)
			break;
	}

#ifndef NO_SHARED_LIBS
	if (!ptr && tryload != DONT_LOAD && tryload != DURING_LOAD) {
		char path[strlen(lib_dir) + sizeof("/.so")
			  + strlen(afinfo.libprefix) + strlen(name)];

		sprintf(path, "%s/libxt_%s.so", lib_dir, name);
		if (dlopen(path, RTLD_NOW) != NULL)
			/* Found library.  If it didn't register itself,
			   maybe they specified match as a target. */
			ptr = find_target(name, DONT_LOAD);

		if (ptr == NULL) {
			sprintf(path, "%s/%s%s.so", lib_dir, afinfo.libprefix,
				name);
			if (dlopen(path, RTLD_NOW) != NULL)
				ptr = find_target(name, DONT_LOAD);
		}
		if (ptr == NULL && tryload == LOAD_MUST_SUCCEED)
			exit_error(PARAMETER_PROBLEM,
				   "Couldn't load target `%s':%s\n",
				   name, dlerror());
	}
#else
	if (ptr && !ptr->loaded) {
		if (tryload != DONT_LOAD)
			ptr->loaded = 1;
		else
			ptr = NULL;
	}
	if(!ptr && (tryload == LOAD_MUST_SUCCEED)) {
		exit_error(PARAMETER_PROBLEM,
			   "Couldn't find target `%s'\n", name);
	}
#endif

	if (ptr)
		ptr->used = 1;

	return ptr;
}

static int compatible_revision(const char *name, u_int8_t revision, int opt)
{
	struct xt_get_revision rev;
	socklen_t s = sizeof(rev);
	int max_rev, sockfd;

	sockfd = socket(afinfo.family, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0) {
		if (errno == EPERM) {
			/* revision 0 is always supported. */
			if (revision != 0)
				fprintf(stderr, "Could not determine whether "
						"revision %u is supported, "
						"assuming it is.\n",
					revision);
			return 1;
		}
		fprintf(stderr, "Could not open socket to kernel: %s\n",
			strerror(errno));
		exit(1);
	}

	load_xtables_ko(modprobe, 1);

	strcpy(rev.name, name);
	rev.revision = revision;

	max_rev = getsockopt(sockfd, afinfo.ipproto, opt, &rev, &s);
	if (max_rev < 0) {
		/* Definitely don't support this? */
		if (errno == ENOENT || errno == EPROTONOSUPPORT) {
			close(sockfd);
			return 0;
		} else if (errno == ENOPROTOOPT) {
			close(sockfd);
			/* Assume only revision 0 support (old kernel) */
			return (revision == 0);
		} else {
			fprintf(stderr, "getsockopt failed strangely: %s\n",
				strerror(errno));
			exit(1);
		}
	}
	close(sockfd);
	return 1;
}


static int compatible_match_revision(const char *name, u_int8_t revision)
{
	return compatible_revision(name, revision, afinfo.so_rev_match);
}

static int compatible_target_revision(const char *name, u_int8_t revision)
{
	return compatible_revision(name, revision, afinfo.so_rev_target);
}

void xtables_register_match(struct xtables_match *me)
{
	struct xtables_match **i, *old;

	if (strcmp(me->version, program_version) != 0) {
		fprintf(stderr, "%s: match `%s' v%s (I'm v%s).\n",
			program_name, me->name, me->version, program_version);
		exit(1);
	}

	/* Revision field stole a char from name. */
	if (strlen(me->name) >= XT_FUNCTION_MAXNAMELEN-1) {
		fprintf(stderr, "%s: target `%s' has invalid name\n",
			program_name, me->name);
		exit(1);
	}

	if (me->family >= NPROTO) {
		fprintf(stderr,
			"%s: BUG: match %s has invalid protocol family\n",
			program_name, me->name);
		exit(1);
	}

	/* ignore not interested match */
	if (me->family != afinfo.family)
		return;

	old = find_match(me->name, DURING_LOAD, NULL);
	if (old) {
		if (old->revision == me->revision) {
			fprintf(stderr,
				"%s: match `%s' already registered.\n",
				program_name, me->name);
			exit(1);
		}

		/* Now we have two (or more) options, check compatibility. */
		if (compatible_match_revision(old->name, old->revision)
		    && old->revision > me->revision)
			return;

		/* Replace if compatible. */
		if (!compatible_match_revision(me->name, me->revision))
			return;

		/* Delete old one. */
		for (i = &xtables_matches; *i!=old; i = &(*i)->next);
		*i = old->next;
	}

	if (me->size != XT_ALIGN(me->size)) {
		fprintf(stderr, "%s: match `%s' has invalid size %u.\n",
			program_name, me->name, (unsigned int)me->size);
		exit(1);
	}

	/* Append to list. */
	for (i = &xtables_matches; *i; i = &(*i)->next);
	me->next = NULL;
	*i = me;

	me->m = NULL;
	me->mflags = 0;
}

void xtables_register_target(struct xtables_target *me)
{
	struct xtables_target *old;

	if (strcmp(me->version, program_version) != 0) {
		fprintf(stderr, "%s: target `%s' v%s (I'm v%s).\n",
			program_name, me->name, me->version, program_version);
		exit(1);
	}

	/* Revision field stole a char from name. */
	if (strlen(me->name) >= XT_FUNCTION_MAXNAMELEN-1) {
		fprintf(stderr, "%s: target `%s' has invalid name\n",
			program_name, me->name);
		exit(1);
	}

	if (me->family >= NPROTO) {
		fprintf(stderr,
			"%s: BUG: target %s has invalid protocol family\n",
			program_name, me->name);
		exit(1);
	}

	/* ignore not interested target */
	if (me->family != afinfo.family)
		return;

	old = find_target(me->name, DURING_LOAD);
	if (old) {
		struct xtables_target **i;

		if (old->revision == me->revision) {
			fprintf(stderr,
				"%s: target `%s' already registered.\n",
				program_name, me->name);
			exit(1);
		}

		/* Now we have two (or more) options, check compatibility. */
		if (compatible_target_revision(old->name, old->revision)
		    && old->revision > me->revision)
			return;

		/* Replace if compatible. */
		if (!compatible_target_revision(me->name, me->revision))
			return;

		/* Delete old one. */
		for (i = &xtables_targets; *i!=old; i = &(*i)->next);
		*i = old->next;
	}

	if (me->size != XT_ALIGN(me->size)) {
		fprintf(stderr, "%s: target `%s' has invalid size %u.\n",
			program_name, me->name, (unsigned int)me->size);
		exit(1);
	}

	/* Prepend to list. */
	me->next = xtables_targets;
	xtables_targets = me;
	me->t = NULL;
	me->tflags = 0;
}

void param_act(unsigned int status, const char *p1, ...)
{
	const char *p2, *p3;
	va_list args;
	bool b;

	va_start(args, p1);

	switch (status) {
	case P_ONLY_ONCE:
		p2 = va_arg(args, const char *);
		b  = va_arg(args, unsigned int);
		if (!b)
			return;
		exit_error(PARAMETER_PROBLEM,
		           "%s: \"%s\" option may only be specified once",
		           p1, p2);
		break;
	case P_NO_INVERT:
		p2 = va_arg(args, const char *);
		b  = va_arg(args, unsigned int);
		if (!b)
			return;
		exit_error(PARAMETER_PROBLEM,
		           "%s: \"%s\" option cannot be inverted", p1, p2);
		break;
	case P_BAD_VALUE:
		p2 = va_arg(args, const char *);
		p3 = va_arg(args, const char *);
		exit_error(PARAMETER_PROBLEM,
		           "%s: Bad value for \"%s\" option: \"%s\"",
		           p1, p2, p3);
		break;
	case P_ONE_ACTION:
		b = va_arg(args, unsigned int);
		if (!b)
			return;
		exit_error(PARAMETER_PROBLEM,
		           "%s: At most one action is possible", p1);
		break;
	default:
		exit_error(status, p1, args);
		break;
	}

	va_end(args);
}
