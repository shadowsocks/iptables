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
#include <arpa/inet.h>

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
	unsigned portnum;

	if ((string_to_number(port, 0, 65535, &portnum)) != -1 ||
	    (portnum = service_to_port(port, proto)) != (unsigned)-1)
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
#ifndef NO_SHARED_LIBS
	struct stat sb;
#endif
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
		else if (stat(path, &sb) == 0)
			fprintf(stderr, "%s: %s\n", path, dlerror());

		if (ptr == NULL) {
			sprintf(path, "%s/%s%s.so", lib_dir, afinfo.libprefix,
				name);
			if (dlopen(path, RTLD_NOW) != NULL)
				ptr = find_match(name, DONT_LOAD, NULL);
			else if (stat(path, &sb) == 0)
				fprintf(stderr, "%s: %s\n", path, dlerror());
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
#ifndef NO_SHARED_LIBS
	struct stat sb;
#endif
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
		else if (stat(path, &sb) == 0)
			fprintf(stderr, "%s: %s\n", path, dlerror());

		if (ptr == NULL) {
			sprintf(path, "%s/%s%s.so", lib_dir, afinfo.libprefix,
				name);
			if (dlopen(path, RTLD_NOW) != NULL)
				ptr = find_target(name, DONT_LOAD);
			else if (stat(path, &sb) == 0)
				fprintf(stderr, "%s: %s\n", path, dlerror());
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

const char *ipaddr_to_numeric(const struct in_addr *addrp)
{
	static char buf[20];
	const unsigned char *bytep = (const void *)&addrp->s_addr;

	sprintf(buf, "%u.%u.%u.%u", bytep[0], bytep[1], bytep[2], bytep[3]);
	return buf;
}

static const char *ipaddr_to_host(const struct in_addr *addr)
{
	struct hostent *host;

	host = gethostbyaddr(addr, sizeof(struct in_addr), AF_INET);
	if (host == NULL)
		return NULL;

	return host->h_name;
}

static const char *ipaddr_to_network(const struct in_addr *addr)
{
	struct netent *net;

	if ((net = getnetbyaddr(ntohl(addr->s_addr), AF_INET)) != NULL)
		return net->n_name;

	return NULL;
}

const char *ipaddr_to_anyname(const struct in_addr *addr)
{
	const char *name;

	if ((name = ipaddr_to_host(addr)) != NULL ||
	    (name = ipaddr_to_network(addr)) != NULL)
		return name;

	return ipaddr_to_numeric(addr);
}

const char *ipmask_to_numeric(const struct in_addr *mask)
{
	static char buf[20];
	uint32_t maskaddr, bits;
	int i;

	maskaddr = ntohl(mask->s_addr);

	if (maskaddr == 0xFFFFFFFFL)
		/* we don't want to see "/32" */
		return "";

	i = 32;
	bits = 0xFFFFFFFEL;
	while (--i >= 0 && maskaddr != bits)
		bits <<= 1;
	if (i >= 0)
		sprintf(buf, "/%d", i);
	else
		/* mask was not a decent combination of 1's and 0's */
		sprintf(buf, "/%s", ipaddr_to_numeric(mask));

	return buf;
}

static struct in_addr *__numeric_to_ipaddr(const char *dotted, bool is_mask)
{
	static struct in_addr addr;
	unsigned char *addrp;
	unsigned int onebyte;
	char buf[20], *p, *q;
	int i;

	/* copy dotted string, because we need to modify it */
	strncpy(buf, dotted, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';
	addrp = (void *)&addr.s_addr;

	p = buf;
	for (i = 0; i < 3; ++i) {
		if ((q = strchr(p, '.')) == NULL) {
			if (is_mask)
				return NULL;

			/* autocomplete, this is a network address */
			if (!strtonum(p, NULL, &onebyte, 0, 255))
				return NULL;

			addrp[i] = onebyte;
			while (i < 3)
				addrp[++i] = 0;

			return &addr;
		}

		*q = '\0';
		if (!strtonum(p, NULL, &onebyte, 0, 255))
			return NULL;

		addrp[i] = onebyte;
		p = q + 1;
	}

	/* we have checked 3 bytes, now we check the last one */
	if (!strtonum(p, NULL, &onebyte, 0, 255))
		return NULL;

	addrp[3] = onebyte;
	return &addr;
}

struct in_addr *numeric_to_ipaddr(const char *dotted)
{
	return __numeric_to_ipaddr(dotted, false);
}

struct in_addr *numeric_to_ipmask(const char *dotted)
{
	return __numeric_to_ipaddr(dotted, true);
}

static struct in_addr *network_to_ipaddr(const char *name)
{
	static struct in_addr addr;
	struct netent *net;

	if ((net = getnetbyname(name)) != NULL) {
		if (net->n_addrtype != AF_INET)
			return NULL;
		addr.s_addr = htonl(net->n_net);
		return &addr;
	}

	return NULL;
}

static struct in_addr *host_to_ipaddr(const char *name, unsigned int *naddr)
{
	struct hostent *host;
	struct in_addr *addr;
	unsigned int i;

	*naddr = 0;
	if ((host = gethostbyname(name)) != NULL) {
		if (host->h_addrtype != AF_INET ||
		    host->h_length != sizeof(struct in_addr))
			return NULL;

		while (host->h_addr_list[*naddr] != NULL)
			++*naddr;
		addr = fw_calloc(*naddr, sizeof(struct in_addr) * *naddr);
		for (i = 0; i < *naddr; i++)
			memcpy(&addr[i], host->h_addr_list[i],
			       sizeof(struct in_addr));
		return addr;
	}

	return NULL;
}

static struct in_addr *
ipparse_hostnetwork(const char *name, unsigned int *naddrs)
{
	struct in_addr *addrptmp, *addrp;

	if ((addrptmp = numeric_to_ipaddr(name)) != NULL ||
	    (addrptmp = network_to_ipaddr(name)) != NULL) {
		addrp = fw_malloc(sizeof(struct in_addr));
		memcpy(addrp, addrptmp, sizeof(*addrp));
		*naddrs = 1;
		return addrp;
	}
	if ((addrptmp = host_to_ipaddr(name, naddrs)) != NULL)
		return addrptmp;

	exit_error(PARAMETER_PROBLEM, "host/network `%s' not found", name);
}

static struct in_addr *parse_ipmask(const char *mask)
{
	static struct in_addr maskaddr;
	struct in_addr *addrp;
	unsigned int bits;

	if (mask == NULL) {
		/* no mask at all defaults to 32 bits */
		maskaddr.s_addr = 0xFFFFFFFF;
		return &maskaddr;
	}
	if ((addrp = numeric_to_ipmask(mask)) != NULL)
		/* dotted_to_addr already returns a network byte order addr */
		return addrp;
	if (string_to_number(mask, 0, 32, &bits) == -1)
		exit_error(PARAMETER_PROBLEM,
			   "invalid mask `%s' specified", mask);
	if (bits != 0) {
		maskaddr.s_addr = htonl(0xFFFFFFFF << (32 - bits));
		return &maskaddr;
	}

	maskaddr.s_addr = 0U;
	return &maskaddr;
}

void ipparse_hostnetworkmask(const char *name, struct in_addr **addrpp,
                             struct in_addr *maskp, unsigned int *naddrs)
{
	unsigned int i, j, k, n;
	struct in_addr *addrp;
	char buf[256], *p;

	strncpy(buf, name, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';
	if ((p = strrchr(buf, '/')) != NULL) {
		*p = '\0';
		addrp = parse_ipmask(p + 1);
	} else {
		addrp = parse_ipmask(NULL);
	}
	memcpy(maskp, addrp, sizeof(*maskp));

	/* if a null mask is given, the name is ignored, like in "any/0" */
	if (maskp->s_addr == 0U)
		strcpy(buf, "0.0.0.0");

	addrp = *addrpp = ipparse_hostnetwork(buf, naddrs);
	n = *naddrs;
	for (i = 0, j = 0; i < n; ++i) {
		addrp[j++].s_addr &= maskp->s_addr;
		for (k = 0; k < j - 1; ++k)
			if (addrp[k].s_addr == addrp[j-1].s_addr) {
				--*naddrs;
				--j;
				break;
			}
	}
}

const char *ip6addr_to_numeric(const struct in6_addr *addrp)
{
	/* 0000:0000:0000:0000:0000:000.000.000.000
	 * 0000:0000:0000:0000:0000:0000:0000:0000 */
	static char buf[50+1];
	return inet_ntop(AF_INET6, addrp, buf, sizeof(buf));
}

static const char *ip6addr_to_host(const struct in6_addr *addr)
{
	static char hostname[NI_MAXHOST];
	struct sockaddr_in6 saddr;
	int err;

	memset(&saddr, 0, sizeof(struct sockaddr_in6));
	memcpy(&saddr.sin6_addr, addr, sizeof(*addr));
	saddr.sin6_family = AF_INET6;

	err = getnameinfo((const void *)&saddr, sizeof(struct sockaddr_in6),
	      hostname, sizeof(hostname) - 1, NULL, 0, 0);
	if (err != 0) {
#ifdef DEBUG
		fprintf(stderr,"IP2Name: %s\n",gai_strerror(err));
#endif
		return NULL;
	}

#ifdef DEBUG
	fprintf (stderr, "\naddr2host: %s\n", hostname);
#endif
	return hostname;
}

const char *ip6addr_to_anyname(const struct in6_addr *addr)
{
	const char *name;

	if ((name = ip6addr_to_host(addr)) != NULL)
		return name;

	return ip6addr_to_numeric(addr);
}

static int ip6addr_prefix_length(const struct in6_addr *k)
{
	unsigned int bits = 0;
	uint32_t a, b, c, d;

	a = k->s6_addr32[0];
	b = k->s6_addr32[1];
	c = k->s6_addr32[2];
	d = k->s6_addr32[3];
	while (a & 0x80000000U) {
		++bits;
		a <<= 1;
		a  |= (b >> 31) & 1;
		b <<= 1;
		b  |= (c >> 31) & 1;
		c <<= 1;
		c  |= (d >> 31) & 1;
		d <<= 1;
	}
	if (a != 0 || b != 0 || c != 0 || d != 0)
		return -1;
	return bits;
}

const char *ip6mask_to_numeric(const struct in6_addr *addrp)
{
	static char buf[50+2];
	int l = ip6addr_prefix_length(addrp);

	if (l == -1) {
		strcpy(buf, "/");
		strcat(buf, ip6addr_to_numeric(addrp));
		return buf;
	}
	sprintf(buf, "/%d", l);
	return buf;
}

struct in6_addr *numeric_to_ip6addr(const char *num)
{
	static struct in6_addr ap;
	int err;

	if ((err = inet_pton(AF_INET6, num, &ap)) == 1)
		return &ap;
#ifdef DEBUG
	fprintf(stderr, "\nnumeric2addr: %d\n", err);
#endif
	return NULL;
}

static struct in6_addr *
host_to_ip6addr(const char *name, unsigned int *naddr)
{
	static struct in6_addr *addr;
	struct addrinfo hints;
	struct addrinfo *res;
	int err;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags    = AI_CANONNAME;
	hints.ai_family   = AF_INET6;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_IPV6;
	hints.ai_next     = NULL;

	*naddr = 0;
	if ((err = getaddrinfo(name, NULL, &hints, &res)) != 0) {
#ifdef DEBUG
		fprintf(stderr,"Name2IP: %s\n",gai_strerror(err));
#endif
		return NULL;
	} else {
		if (res->ai_family != AF_INET6 ||
		    res->ai_addrlen != sizeof(struct sockaddr_in6))
			return NULL;

#ifdef DEBUG
		fprintf(stderr, "resolved: len=%d  %s ", res->ai_addrlen,
		        ip6addr_to_numeric(&((struct sockaddr_in6 *)res->ai_addr)->sin6_addr));
#endif
		/* Get the first element of the address-chain */
		addr = fw_malloc(sizeof(struct in6_addr));
		memcpy(addr, &((const struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
		       sizeof(struct in6_addr));
		freeaddrinfo(res);
		*naddr = 1;
		return addr;
	}

	return NULL;
}

static struct in6_addr *network_to_ip6addr(const char *name)
{
	/*	abort();*/
	/* TODO: not implemented yet, but the exception breaks the
	 *       name resolvation */
	return NULL;
}

static struct in6_addr *
ip6parse_hostnetwork(const char *name, unsigned int *naddrs)
{
	struct in6_addr *addrp, *addrptmp;

	if ((addrptmp = numeric_to_ip6addr(name)) != NULL ||
	    (addrptmp = network_to_ip6addr(name)) != NULL) {
		addrp = fw_malloc(sizeof(struct in6_addr));
		memcpy(addrp, addrptmp, sizeof(*addrp));
		*naddrs = 1;
		return addrp;
	}
	if ((addrp = host_to_ip6addr(name, naddrs)) != NULL)
		return addrp;

	exit_error(PARAMETER_PROBLEM, "host/network `%s' not found", name);
}

static struct in6_addr *parse_ip6mask(char *mask)
{
	static struct in6_addr maskaddr;
	struct in6_addr *addrp;
	unsigned int bits;

	if (mask == NULL) {
		/* no mask at all defaults to 128 bits */
		memset(&maskaddr, 0xff, sizeof maskaddr);
		return &maskaddr;
	}
	if ((addrp = numeric_to_ip6addr(mask)) != NULL)
		return addrp;
	if (string_to_number(mask, 0, 128, &bits) == -1)
		exit_error(PARAMETER_PROBLEM,
			   "invalid mask `%s' specified", mask);
	if (bits != 0) {
		char *p = (void *)&maskaddr;
		memset(p, 0xff, bits / 8);
		memset(p + (bits / 8) + 1, 0, (128 - bits) / 8);
		p[bits/8] = 0xff << (8 - (bits & 7));
		return &maskaddr;
	}

	memset(&maskaddr, 0, sizeof(maskaddr));
	return &maskaddr;
}

void ip6parse_hostnetworkmask(const char *name, struct in6_addr **addrpp,
                              struct in6_addr *maskp, unsigned int *naddrs)
{
	struct in6_addr *addrp;
	unsigned int i, j, k, n;
	char buf[256], *p;

	strncpy(buf, name, sizeof(buf) - 1);
	buf[sizeof(buf)-1] = '\0';
	if ((p = strrchr(buf, '/')) != NULL) {
		*p = '\0';
		addrp = parse_ip6mask(p + 1);
	} else {
		addrp = parse_ip6mask(NULL);
	}
	memcpy(maskp, addrp, sizeof(*maskp));

	/* if a null mask is given, the name is ignored, like in "any/0" */
	if (memcmp(maskp, &in6addr_any, sizeof(in6addr_any)) == 0)
		strcpy(buf, "::");

	addrp = *addrpp = ip6parse_hostnetwork(buf, naddrs);
	n = *naddrs;
	for (i = 0, j = 0; i < n; ++i) {
		for (k = 0; k < 4; ++k)
			addrp[j].in6_u.u6_addr32[k] &= maskp->in6_u.u6_addr32[k];
		++j;
		for (k = 0; k < j - 1; ++k)
			if (IN6_ARE_ADDR_EQUAL(&addrp[k], &addrp[j - 1])) {
				--*naddrs;
				--j;
				break;
			}
	}
}

void save_string(const char *value)
{
	static const char no_quote_chars[] = "_-0123456789"
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	static const char escape_chars[] = "\"\\'";
	size_t length;
	const char *p;

	length = strcspn(value, no_quote_chars);
	if (length > 0 && value[length] == 0) {
		/* no quoting required */
		fputs(value, stdout);
		putchar(' ');
	} else {
		/* there is at least one dangerous character in the
		   value, which we have to quote.  Write double quotes
		   around the value and escape special characters with
		   a backslash */
		putchar('"');

		for (p = strpbrk(value, escape_chars); p != NULL;
		     p = strpbrk(value, escape_chars)) {
			if (p > value)
				fwrite(value, 1, p - value, stdout);
			putchar('\\');
			putchar(*p);
			value = p + 1;
		}

		/* print the rest and finish the double quoted
		   string */
		fputs(value, stdout);
		printf("\" ");
	}
}
