/* Library which manipulates firewall rules.  Version 0.1. */

/* Architecture of firewall rules is as follows:
 *
 * Chains go INPUT, FORWARD, OUTPUT then user chains.
 * Each user chain starts with an ERROR node.
 * Every chain ends with an unconditional jump: a RETURN for user chains,
 * and a POLICY for built-ins.
 */

/* (C)1999 Paul ``Rusty'' Russell - Placed under the GNU GPL (See
   COPYING for details). */

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#if !defined(__GLIBC__) || (__GLIBC__ < 2)
typedef unsigned int socklen_t;
#endif

#include <libiptc/libiptc.h>
#include <linux/netfilter_ipv4/ipt_limit.h>

#define IP_VERSION	4
#define IP_OFFSET	0x1FFF

#ifndef IPT_LIB_DIR
#define IPT_LIB_DIR "/usr/local/lib/iptables"
#endif

static int sockfd = -1;
static void *iptc_fn = NULL;

static const char *hooknames[]
= { [NF_IP_PRE_ROUTING]  "PREROUTING",
    [NF_IP_LOCAL_IN]     "INPUT",
    [NF_IP_FORWARD]      "FORWARD",
    [NF_IP_LOCAL_OUT]    "OUTPUT",
    [NF_IP_POST_ROUTING] "POSTROUTING"
};

struct counter_map
{
	enum {
		COUNTER_MAP_NOMAP,
		COUNTER_MAP_NORMAL_MAP,
		COUNTER_MAP_ZEROED
	} maptype;
	unsigned int mappos;
};

/* Convenience structures */
struct ipt_error_target
{
	struct ipt_entry_target t;
	char error[IPT_TABLE_MAXNAMELEN];
};

struct iptc_handle
{
	/* Have changes been made? */
	int changed;
	/* Size in here reflects original state. */
	struct ipt_getinfo info;

	struct counter_map *counter_map;
	/* Array of hook names */
	const char **hooknames;

	/* This was taking us ~50 seconds to list 300 rules. */
	/* Cached: last find_label result */
	char cache_label_name[IPT_TABLE_MAXNAMELEN];
	int cache_label_return;
	unsigned int cache_label_offset;

	/* Number in here reflects current state. */
	unsigned int new_number;
	struct ipt_get_entries entries;
};

static void
set_changed(iptc_handle_t h)
{
	h->cache_label_name[0] = '\0';
	h->changed = 1;
}

static void do_check(iptc_handle_t h, unsigned int line);
#define CHECK(h) do_check((h), __LINE__)

static inline int
get_number(const struct ipt_entry *i,
	   const struct ipt_entry *seek,
	   unsigned int *pos)
{
	if (i == seek)
		return 1;
	(*pos)++;
	return 0;
}

static unsigned int
entry2index(const iptc_handle_t h, const struct ipt_entry *seek)
{
	unsigned int pos = 0;

	if (IPT_ENTRY_ITERATE(h->entries.entries, h->entries.size,
			      get_number, seek, &pos) == 0) {
		fprintf(stderr, "ERROR: offset %i not an entry!\n",
			(unsigned char *)seek - h->entries.entries);
		abort();
	}
	return pos;
}

static inline int
get_entry_n(struct ipt_entry *i,
	    unsigned int number,
	    unsigned int *pos,
	    struct ipt_entry **pe)
{
	if (*pos == number) {
		*pe = i;
		return 1;
	}
	(*pos)++;
	return 0;
}

static struct ipt_entry *
index2entry(iptc_handle_t h, unsigned int index)
{
	unsigned int pos = 0;
	struct ipt_entry *ret = NULL;

	IPT_ENTRY_ITERATE(h->entries.entries, h->entries.size,
			  get_entry_n, index, &pos, &ret);

	return ret;
}

static inline struct ipt_entry *
get_entry(iptc_handle_t h, unsigned int offset)
{
	return (struct ipt_entry *)(h->entries.entries + offset);
}

static inline unsigned long
entry2offset(const iptc_handle_t h, const struct ipt_entry *e)
{
	return (unsigned char *)e - h->entries.entries;
}

static unsigned long
index2offset(iptc_handle_t h, unsigned int index)
{
	return entry2offset(h, index2entry(h, index));
}

static const char *
get_errorlabel(iptc_handle_t h, unsigned int offset)
{
	struct ipt_entry *e;

	e = get_entry(h, offset);
	if (strcmp(ipt_get_target(e)->u.name, IPT_ERROR_TARGET) != 0) {
		fprintf(stderr, "ERROR: offset %u not an error node!\n",
			offset);
		abort();
	}

	return (const char *)ipt_get_target(e)->data;
}

/* Allocate handle of given size */
static iptc_handle_t
alloc_handle(const char *tablename, unsigned int size, unsigned int num_rules)
{
	size_t len;
	iptc_handle_t h;

	len = sizeof(struct iptc_handle)
		+ size
		+ num_rules * sizeof(struct counter_map);

	if ((h = malloc(len)) == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	h->changed = 0;
	h->cache_label_name[0] = '\0';
	h->counter_map = (void *)h
		+ sizeof(struct iptc_handle)
		+ size;
	strcpy(h->info.name, tablename);
	strcpy(h->entries.name, tablename);

	return h;
}

iptc_handle_t
iptc_init(const char *tablename)
{
	iptc_handle_t h;
	struct ipt_getinfo info;
	unsigned int i;
	int tmp;
	socklen_t s;

	iptc_fn = iptc_init;

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0)
		return NULL;

	s = sizeof(info);
	if (strlen(tablename) >= IPT_TABLE_MAXNAMELEN) {
		errno = EINVAL;
		return NULL;
	}
	strcpy(info.name, tablename);
	if (getsockopt(sockfd, IPPROTO_IP, IPT_SO_GET_INFO, &info, &s) < 0)
		return NULL;

	if ((h = alloc_handle(info.name, info.size, info.num_entries))
	    == NULL)
		return NULL;

/* Too hard --RR */
#if 0
	sprintf(pathname, "%s/%s", IPT_LIB_DIR, info.name);
	dynlib = dlopen(pathname, RTLD_NOW);
	if (!dynlib) {
		errno = ENOENT;
		return NULL;
	}
	h->hooknames = dlsym(dynlib, "hooknames");
	if (!h->hooknames) {
		errno = ENOENT;
		return NULL;
	}
#else
	h->hooknames = hooknames;
#endif

	/* Initialize current state */
	h->info = info;
	h->new_number = h->info.num_entries;
	for (i = 0; i < h->info.num_entries; i++)
		h->counter_map[i]
			= ((struct counter_map){COUNTER_MAP_NORMAL_MAP, i});

	h->entries.size = h->info.size;

	tmp = sizeof(struct ipt_get_entries) + h->info.size;

	if (getsockopt(sockfd, IPPROTO_IP, IPT_SO_GET_ENTRIES, &h->entries,
		       &tmp) < 0) {
		free(h);
		return NULL;
	}

	CHECK(h);
	return h;
}

#define IP_PARTS_NATIVE(n)			\
(unsigned int)((n)>>24)&0xFF,			\
(unsigned int)((n)>>16)&0xFF,			\
(unsigned int)((n)>>8)&0xFF,			\
(unsigned int)((n)&0xFF)

#define IP_PARTS(n) IP_PARTS_NATIVE(ntohl(n))

static inline int
print_match(const struct ipt_entry_match *m)
{
	printf("Match name: `%s'\n", m->u.name);
	return 0;
}

int
dump_entry(struct ipt_entry *e, const iptc_handle_t handle)
{
	size_t i;
	struct ipt_entry_target *t;

	printf("Entry %u (%lu):\n", entry2index(handle, e),
	       entry2offset(handle, e));
	printf("SRC IP: %u.%u.%u.%u/%u.%u.%u.%u\n",
	       IP_PARTS(e->ip.src.s_addr),IP_PARTS(e->ip.smsk.s_addr));
	printf("DST IP: %u.%u.%u.%u/%u.%u.%u.%u\n",
	       IP_PARTS(e->ip.dst.s_addr),IP_PARTS(e->ip.dmsk.s_addr));
	printf("Interface: `%s'/", e->ip.iniface);
	for (i = 0; i < IFNAMSIZ; i++)
		printf("%c", e->ip.iniface_mask[i] ? 'X' : '.');
	printf("to `%s'/", e->ip.outiface);
	for (i = 0; i < IFNAMSIZ; i++)
		printf("%c", e->ip.outiface_mask[i] ? 'X' : '.');
	printf("\nProtocol: %u\n", e->ip.proto);
	printf("Flags: %02X\n", e->ip.flags);
	printf("Invflags: %02X\n", e->ip.invflags);
	printf("Counters: %llu packets, %llu bytes\n",
	       e->counters.pcnt, e->counters.bcnt);
	printf("Cache: %08X ", e->nfcache);
	if (e->nfcache & NFC_ALTERED) printf("ALTERED ");
	if (e->nfcache & NFC_UNKNOWN) printf("UNKNOWN ");
	if (e->nfcache & NFC_IP_SRC) printf("IP_SRC ");
	if (e->nfcache & NFC_IP_DST) printf("IP_DST ");
	if (e->nfcache & NFC_IP_IF_IN) printf("IP_IF_IN ");
	if (e->nfcache & NFC_IP_IF_OUT) printf("IP_IF_OUT ");
	if (e->nfcache & NFC_IP_TOS) printf("IP_TOS ");
	if (e->nfcache & NFC_IP_PROTO) printf("IP_PROTO ");
	if (e->nfcache & NFC_IP_OPTIONS) printf("IP_OPTIONS ");
	if (e->nfcache & NFC_IP_TCPFLAGS) printf("IP_TCPFLAGS ");
	if (e->nfcache & NFC_IP_SRC_PT) printf("IP_SRC_PT ");
	if (e->nfcache & NFC_IP_DST_PT) printf("IP_DST_PT ");
	if (e->nfcache & NFC_IP_PROTO_UNKNOWN) printf("IP_PROTO_UNKNOWN ");
	printf("\n");

	IPT_MATCH_ITERATE(e, print_match);

	t = ipt_get_target(e);
	printf("Target name: `%s' [%u]\n", t->u.name, t->target_size);
	if (strcmp(t->u.name, IPT_STANDARD_TARGET) == 0) {
		int pos = *(int *)t->data;
		if (pos < 0)
			printf("verdict=%s\n",
			       pos == -NF_ACCEPT-1 ? "NF_ACCEPT"
			       : pos == -NF_DROP-1 ? "NF_DROP"
			       : pos == -NF_QUEUE-1 ? "NF_QUEUE"
			       : pos == IPT_RETURN ? "RETURN"
			       : "UNKNOWN");
		else
			printf("verdict=%u\n", pos);
	} else if (strcmp(t->u.name, IPT_ERROR_TARGET) == 0)
		printf("error=`%s'\n", t->data);

	printf("\n");
	return 0;
}

void
dump_entries(const iptc_handle_t handle)
{
	CHECK(handle);

	printf("libiptc v%s.  %u entries, %u bytes.\n",
	       NETFILTER_VERSION,
	       handle->new_number, handle->entries.size);
	printf("Table `%s'\n", handle->info.name);
	printf("Hooks: pre/in/fwd/out/post = %u/%u/%u/%u/%u\n",
	       handle->info.hook_entry[NF_IP_PRE_ROUTING],
	       handle->info.hook_entry[NF_IP_LOCAL_IN],
	       handle->info.hook_entry[NF_IP_FORWARD],
	       handle->info.hook_entry[NF_IP_LOCAL_OUT],
	       handle->info.hook_entry[NF_IP_POST_ROUTING]);
	printf("Underflows: pre/in/fwd/out/post = %u/%u/%u/%u/%u\n",
	       handle->info.underflow[NF_IP_PRE_ROUTING],
	       handle->info.underflow[NF_IP_LOCAL_IN],
	       handle->info.underflow[NF_IP_FORWARD],
	       handle->info.underflow[NF_IP_LOCAL_OUT],
	       handle->info.underflow[NF_IP_POST_ROUTING]);

	IPT_ENTRY_ITERATE(handle->entries.entries, handle->entries.size,
			  dump_entry, handle);
}

static inline int
find_user_label(struct ipt_entry *e, unsigned int *off, const char *name)
{
	/* Increment first: they want offset of entry AFTER label */
	(*off) += e->next_offset;

	if (strcmp(ipt_get_target(e)->u.name, IPT_ERROR_TARGET) == 0
	    && strcmp(ipt_get_target(e)->data, name) == 0)
		return 1;

	return 0;
}

/* Returns offset of label. */
static int
find_label(unsigned int *off,
	   const char *name,
	   const iptc_handle_t handle)
{
	unsigned int i;

	/* Cached? */
	if (handle->cache_label_name[0]
	    && strcmp(name, handle->cache_label_name) == 0) {
		*off = handle->cache_label_offset;
		return handle->cache_label_return;
	}

	/* Builtin chain name? */
	i = iptc_builtin(name, handle);
	if (i != 0) {
		*off = handle->info.hook_entry[i-1];
		return 1;
	}

	/* User chain name? */
	*off = 0;
	if (IPT_ENTRY_ITERATE(handle->entries.entries, handle->entries.size,
			      find_user_label, off, name) != 0) {
		/* last error node doesn't count */
		if (*off != handle->entries.size) {
			strcpy(handle->cache_label_name, name);
			handle->cache_label_offset = *off;
			handle->cache_label_return = 1;
			return 1;
		}
	}

	strcpy(handle->cache_label_name, name);
	handle->cache_label_return = 0;
	return 0;
}

/* Does this chain exist? */
int iptc_is_chain(const char *chain, const iptc_handle_t handle)
{
	unsigned int dummy;

	/* avoid infinite recursion */
#if 0
	CHECK(handle);
#endif

	return find_label(&dummy, chain, handle);
}

/* Returns the position of the final (ie. unconditional) element. */
static unsigned int
get_chain_end(const iptc_handle_t handle, unsigned int start)
{
	unsigned int last_off, off;
	struct ipt_entry *e;

	last_off = start;
	e = get_entry(handle, start);

	/* Terminate when we meet a error label or a hook entry. */
	for (off = start + e->next_offset;
	     off < handle->entries.size;
	     last_off = off, off += e->next_offset) {
		struct ipt_entry_target *t;
		unsigned int i;

		e = get_entry(handle, off);

		/* We hit an entry point. */
		for (i = 0; i < NF_IP_NUMHOOKS; i++) {
			if ((handle->info.valid_hooks & (1 << i))
			    && off == handle->info.hook_entry[i])
				return last_off;
		}

		/* We hit a user chain label */
		t = ipt_get_target(e);
		if (strcmp(t->u.name, IPT_ERROR_TARGET) == 0)
			return last_off;
	}
	/* SHOULD NEVER HAPPEN */
	fprintf(stderr, "ERROR: Off end (%u) of chain from %u!\n",
		handle->entries.size, off);
	abort();
}

/* Iterator functions to run through the chains; prev = NULL means
   first chain.  Returns NULL at end. */
const char *
iptc_next_chain(const char *prev, iptc_handle_t *handle)
{
	unsigned int pos;
	unsigned int i;
	struct ipt_entry *e;

	CHECK(*handle);
	if (!prev)
		pos = 0;
	else {
		if (!find_label(&pos, prev, *handle)) {
			errno = ENOENT;
			return NULL;
		}
		pos = get_chain_end(*handle, pos);
		/* Next entry. */
		e = get_entry(*handle, pos);
		pos += e->next_offset;
	}
	e = get_entry(*handle, pos);

	/* Return names of entry points if it is one. */
	for (i = 0; i < NF_IP_NUMHOOKS; i++) {
		if (((*handle)->info.valid_hooks & (1 << i))
		    && pos == (*handle)->info.hook_entry[i])
			return (*handle)->hooknames[i];
	}
	/* If this is the last element, iteration finished */
	if (pos + e->next_offset == (*handle)->entries.size)
		return NULL;

	if (strcmp(ipt_get_target(e)->u.name, IPT_ERROR_TARGET) != 0) {
		/* SHOULD NEVER HAPPEN */
		fprintf(stderr, "ERROR: position %u/%u not an error label\n",
			pos, (*handle)->entries.size);
		abort();
	}

	return (const char *)ipt_get_target(e)->data;
}

/* How many rules in this chain? */
unsigned int
iptc_num_rules(const char *chain, iptc_handle_t *handle)
{
	unsigned int off = 0;
	struct ipt_entry *start, *end;

	CHECK(*handle);
	if (!find_label(&off, chain, *handle)) {
		errno = ENOENT;
		return (unsigned int)-1;
	}

	start = get_entry(*handle, off);
	end = get_entry(*handle, get_chain_end(*handle, off));

	return entry2index(*handle, end) - entry2index(*handle, start);
}

/* Get n'th rule in this chain. */
const struct ipt_entry *iptc_get_rule(const char *chain,
				      unsigned int n,
				      iptc_handle_t *handle)
{
	unsigned int pos = 0, chainindex;

	CHECK(*handle);
	if (!find_label(&pos, chain, *handle)) {
		errno = ENOENT;
		return NULL;
	}

	chainindex = entry2index(*handle, get_entry(*handle, pos));

	return index2entry(*handle, chainindex + n);
}

static const char *target_name(iptc_handle_t handle, struct ipt_entry *e)
{
	int spos;
	unsigned int labelidx;
	struct ipt_entry *jumpto;

	if (strcmp(ipt_get_target(e)->u.name, IPT_STANDARD_TARGET) != 0)
		return ipt_get_target(e)->u.name;

	/* Standard target: evaluate */
	spos = *(int *)ipt_get_target(e)->data;
	if (spos < 0) {
		if (spos == IPT_RETURN)
			return IPTC_LABEL_RETURN;
		else if (spos == -NF_ACCEPT-1)
			return IPTC_LABEL_ACCEPT;
		else if (spos == -NF_DROP-1)
			return IPTC_LABEL_DROP;
		else if (spos == -NF_QUEUE-1)
			return IPTC_LABEL_QUEUE;

		fprintf(stderr, "ERROR: off %lu/%u not a valid target (%i)\n",
			entry2offset(handle, e), handle->entries.size,
			spos);
		abort();
	}

	jumpto = get_entry(handle, spos);

	/* Fall through rule */
	if (jumpto == (void *)e + e->next_offset)
		return "";

	/* Must point to head of a chain: ie. after error rule */
	labelidx = entry2index(handle, jumpto) - 1;
	return get_errorlabel(handle, index2offset(handle, labelidx));
}

/* Returns a pointer to the target name of this position. */
const char *iptc_get_target(const char *chain,
			    unsigned int n,
			    iptc_handle_t *handle)
{
	unsigned int pos = 0, chainindex;
	struct ipt_entry *e;

	CHECK(*handle);
	if (!find_label(&pos, chain, *handle)) {
		errno = ENOENT;
		return NULL;
	}

	chainindex = entry2index(*handle, get_entry(*handle, pos));
	e = index2entry(*handle, chainindex + n);

	return target_name(*handle, e);
}

/* Is this a built-in chain?  Actually returns hook + 1. */
int
iptc_builtin(const char *chain, const iptc_handle_t handle)
{
	unsigned int i;

	for (i = 0; i < NF_IP_NUMHOOKS; i++) {
		if ((handle->info.valid_hooks & (1 << i))
		    && handle->hooknames[i]
		    && strcmp(handle->hooknames[i], chain) == 0)
			return i+1;
	}
	return 0;
}

/* Get the policy of a given built-in chain */
const char *
iptc_get_policy(const char *chain,
		struct ipt_counters *counters,
		iptc_handle_t *handle)
{
	unsigned int start;
	struct ipt_entry *e;
	int hook;

	CHECK(*handle);
	hook = iptc_builtin(chain, *handle);
	if (hook != 0)
		start = (*handle)->info.hook_entry[hook-1];
	else
		return NULL;

	e = get_entry(*handle, get_chain_end(*handle, start));
	*counters = e->counters;

	return target_name(*handle, e);
}

static int
correct_verdict(struct ipt_entry *e,
		unsigned char *base,
		unsigned int offset, int delta_offset)
{
	struct ipt_standard_target *t = (void *)ipt_get_target(e);
	unsigned int curr = (unsigned char *)e - base;

	/* Trap: insert of fall-through rule.  Don't change fall-through
	   verdict to jump-over-next-rule. */
	if (strcmp(t->target.u.name, IPT_STANDARD_TARGET) == 0
	    && t->verdict > (int)offset
	    && !(curr == offset &&
		 t->verdict == curr + e->next_offset)) {
		t->verdict += delta_offset;
	}

	return 0;
}

/* Adjusts standard verdict jump positions after an insertion/deletion. */
static int
set_verdict(unsigned int offset, int delta_offset, iptc_handle_t *handle)
{
	IPT_ENTRY_ITERATE((*handle)->entries.entries,
			  (*handle)->entries.size,
			  correct_verdict, (*handle)->entries.entries,
			  offset, delta_offset);

	set_changed(*handle);
	return 1;
}

/* If prepend is set, then we are prepending to a chain: if the
 * insertion position is an entry point, keep the entry point. */
static int
insert_rules(unsigned int num_rules, unsigned int rules_size,
	     const struct ipt_entry *insert,
	     unsigned int offset, unsigned int num_rules_offset,
	     int prepend,
	     iptc_handle_t *handle)
{
	iptc_handle_t newh;
	struct ipt_getinfo newinfo;
	unsigned int i;

	if (offset >= (*handle)->entries.size) {
		errno = EINVAL;
		return 0;
	}

	newinfo = (*handle)->info;

	/* Fix up entry points. */
	for (i = 0; i < NF_IP_NUMHOOKS; i++) {
		/* Entry points to START of chain, so keep same if
                   inserting on at that point. */
		if ((*handle)->info.hook_entry[i] > offset)
			newinfo.hook_entry[i] += rules_size;

		/* Underflow always points to END of chain (policy),
		   so if something is inserted at same point, it
		   should be advanced. */
		if ((*handle)->info.underflow[i] >= offset)
			newinfo.underflow[i] += rules_size;
	}

	newh = alloc_handle((*handle)->info.name,
			    (*handle)->info.size + rules_size,
			    (*handle)->info.num_entries + num_rules);
	if (!newh)
		return 0;
	newh->info = newinfo;

	/* Copy pre... */
	memcpy(newh->entries.entries, (*handle)->entries.entries, offset);
	/* ... Insert new ... */
	memcpy(newh->entries.entries + offset, insert, rules_size);
	/* ... copy post */
	memcpy(newh->entries.entries + offset + rules_size,
	       (*handle)->entries.entries + offset,
	       (*handle)->entries.size - offset);

	/* Move counter map. */
	/* Copy pre... */
	memcpy(newh->counter_map, (*handle)->counter_map,
	       sizeof(struct counter_map) * num_rules_offset);
	/* ... copy post */
	memcpy(newh->counter_map + num_rules_offset + num_rules,
	       (*handle)->counter_map + num_rules_offset,
	       sizeof(struct counter_map) * ((*handle)->new_number
					     - num_rules_offset));
	/* Set intermediates to no counter copy */
	for (i = 0; i < num_rules; i++)
		newh->counter_map[num_rules_offset+i]
			= ((struct counter_map){ COUNTER_MAP_NOMAP, 0 });

	newh->new_number = (*handle)->new_number + num_rules;
	newh->entries.size = (*handle)->entries.size + rules_size;
	newh->hooknames = (*handle)->hooknames;

	free(*handle);
	*handle = newh;

	return set_verdict(offset, rules_size, handle);
}

static int
delete_rules(unsigned int num_rules, unsigned int rules_size,
	     unsigned int offset, unsigned int num_rules_offset,
	     iptc_handle_t *handle)
{
	unsigned int i;

	if (offset + rules_size > (*handle)->entries.size) {
		errno = EINVAL;
		return 0;
	}

	/* Fix up entry points. */
	for (i = 0; i < NF_IP_NUMHOOKS; i++) {
		/* In practice, we never delete up to a hook entry,
		   since the built-in chains are always first,
		   so these two are never equal */
		if ((*handle)->info.hook_entry[i] >= offset + rules_size)
			(*handle)->info.hook_entry[i] -= rules_size;
		else if ((*handle)->info.hook_entry[i] > offset) {
			fprintf(stderr, "ERROR: Deleting entry %u %u %u\n",
				i, (*handle)->info.hook_entry[i], offset);
			abort();
		}

		/* Underflow points to policy (terminal) rule in
                   built-in, so sequality is valid here (when deleting
                   the last rule). */
		if ((*handle)->info.underflow[i] >= offset + rules_size)
			(*handle)->info.underflow[i] -= rules_size;
		else if ((*handle)->info.underflow[i] > offset) {
			fprintf(stderr, "ERROR: Deleting uflow %u %u %u\n",
				i, (*handle)->info.underflow[i], offset);
			abort();
		}
	}

	/* Move the rules down. */
	memmove((*handle)->entries.entries + offset,
		(*handle)->entries.entries + offset + rules_size,
		(*handle)->entries.size - (offset + rules_size));

	/* Move the counter map down. */
	memmove(&(*handle)->counter_map[num_rules_offset],
		&(*handle)->counter_map[num_rules_offset + num_rules],
		sizeof(struct counter_map)
		* ((*handle)->new_number - (num_rules + num_rules_offset)));

	/* Fix numbers */
	(*handle)->new_number -= num_rules;
	(*handle)->entries.size -= rules_size;

	return set_verdict(offset, -(int)rules_size, handle);
}

static int
standard_map(struct ipt_entry *e, int verdict)
{
	struct ipt_standard_target *t;

	t = (struct ipt_standard_target *)ipt_get_target(e);

	if (t->target.target_size != IPT_ALIGN(sizeof(struct ipt_standard_target))) {
		errno = EINVAL;
		return 0;
	}
	/* memset for memcmp convenience on delete/replace */
	memset(t->target.u.name, 0, IPT_FUNCTION_MAXNAMELEN);
	strcpy(t->target.u.name, IPT_STANDARD_TARGET);
	t->verdict = verdict;

	return 1;
}

static int
map_target(const iptc_handle_t handle,
	   struct ipt_entry *e,
	   unsigned int offset,
	   struct ipt_entry_target *old)
{
	struct ipt_entry_target *t = ipt_get_target(e);

	/* Save old target (except data, which we don't change, except for
	   standard case, where we don't care). */
	*old = *t;

	/* Maybe it's empty (=> fall through) */
	if (strcmp(t->u.name, "") == 0)
		return standard_map(e, offset + e->next_offset);
	/* Maybe it's a standard target name... */
	else if (strcmp(t->u.name, IPTC_LABEL_ACCEPT) == 0)
		return standard_map(e, -NF_ACCEPT - 1);
	else if (strcmp(t->u.name, IPTC_LABEL_DROP) == 0)
		return standard_map(e, -NF_DROP - 1);
	else if (strcmp(t->u.name, IPTC_LABEL_QUEUE) == 0)
		return standard_map(e, -NF_QUEUE - 1);
	else if (strcmp(t->u.name, IPTC_LABEL_RETURN) == 0)
		return standard_map(e, IPT_RETURN);
	else if (iptc_builtin(t->u.name, handle)) {
		/* Can't jump to builtins. */
		errno = EINVAL;
		return 0;
	} else {
		/* Maybe it's an existing chain name. */
		unsigned int exists;

		if (find_label(&exists, t->u.name, handle))
			return standard_map(e, exists);
	}

	/* Must be a module?  If not, kernel will reject... */
	/* memset to all 0 for your memcmp convenience. */
	memset(t->u.name + strlen(t->u.name),
	       0,
	       IPT_FUNCTION_MAXNAMELEN - strlen(t->u.name));
	return 1;
}

static void
unmap_target(struct ipt_entry *e, struct ipt_entry_target *old)
{
	struct ipt_entry_target *t = ipt_get_target(e);

	/* Save old target (except data, which we don't change, except for
	   standard case, where we don't care). */
	*t = *old;
}

/* Insert the entry `fw' in chain `chain' into position `rulenum'. */
int
iptc_insert_entry(const ipt_chainlabel chain,
		  const struct ipt_entry *e,
		  unsigned int rulenum,
		  iptc_handle_t *handle)
{
	unsigned int chainoff, chainindex, offset;
	struct ipt_entry_target old;
	int ret;

	CHECK(*handle);
	iptc_fn = iptc_insert_entry;
	if (!find_label(&chainoff, chain, *handle)) {
		errno = ENOENT;
		return 0;
	}

	chainindex = entry2index(*handle, get_entry(*handle, chainoff));

	if (index2entry(*handle, chainindex + rulenum)
	    > get_entry(*handle, get_chain_end(*handle, chainoff))) {
		errno = E2BIG;
		return 0;
	}
	offset = index2offset(*handle, chainindex + rulenum);

	/* Mapping target actually alters entry, but that's
           transparent to the caller. */
	if (!map_target(*handle, (struct ipt_entry *)e, offset, &old))
		return 0;

	ret = insert_rules(1, e->next_offset, e, offset,
			   chainindex + rulenum, rulenum == 0, handle);
	unmap_target((struct ipt_entry *)e, &old);
	CHECK(*handle);
	return ret;
}

/* Atomically replace rule `rulenum' in `chain' with `fw'. */
int
iptc_replace_entry(const ipt_chainlabel chain,
		   const struct ipt_entry *e,
		   unsigned int rulenum,
		   iptc_handle_t *handle)
{
	unsigned int chainoff, chainindex, offset;
	struct ipt_entry_target old;
	int ret;

	CHECK(*handle);
	iptc_fn = iptc_replace_entry;

	if (!find_label(&chainoff, chain, *handle)) {
		errno = ENOENT;
		return 0;
	}

	chainindex = entry2index(*handle, get_entry(*handle, chainoff));

	if (index2entry(*handle, chainindex + rulenum)
	    >= get_entry(*handle, get_chain_end(*handle, chainoff))) {
		errno = E2BIG;
		return 0;
	}

	offset = index2offset(*handle, chainindex + rulenum);
	/* Replace = delete and insert. */
	if (!delete_rules(1, get_entry(*handle, offset)->next_offset,
			  offset, chainindex + rulenum, handle))
		return 0;

	if (!map_target(*handle, (struct ipt_entry *)e, offset, &old))
		return 0;
	CHECK(*handle);

	ret = insert_rules(1, e->next_offset, e, offset,
			   chainindex + rulenum, 1, handle);
	unmap_target((struct ipt_entry *)e, &old);
	CHECK(*handle);
	return ret;
}

/* Append entry `fw' to chain `chain'.  Equivalent to insert with
   rulenum = length of chain. */
int
iptc_append_entry(const ipt_chainlabel chain,
		  const struct ipt_entry *e,
		  iptc_handle_t *handle)
{
	unsigned int startoff, endoff;
	struct ipt_entry_target old;
	int ret;

	CHECK(*handle);
	iptc_fn = iptc_append_entry;
	if (!find_label(&startoff, chain, *handle)) {
		errno = ENOENT;
		return 0;
	}

	endoff = get_chain_end(*handle, startoff);
	if (!map_target(*handle, (struct ipt_entry *)e, endoff, &old))
		return 0;

	ret = insert_rules(1, e->next_offset, e, endoff,
			   entry2index(*handle, get_entry(*handle, endoff)),
			   0, handle);
	unmap_target((struct ipt_entry *)e, &old);
	CHECK(*handle);
	return ret;
}

static inline int
match_different(const struct ipt_entry_match *a,
		const unsigned char *a_elems,
		const unsigned char *b_elems,
		unsigned char **maskptr)
{
	const struct ipt_entry_match *b;
	unsigned int i;

	/* Offset of b is the same as a. */
	b = (void *)b_elems + ((unsigned char *)a-a_elems);

	if (a->match_size != b->match_size)
		return 1;

	if (strcmp(a->u.name, b->u.name) != 0)
		return 1;

	*maskptr += sizeof(*a);

	for (i = 0; i < a->match_size - sizeof(*a); i++)
		if (((a->data[i] ^ b->data[i]) & (*maskptr)[i]) != 0)
			return 1;
	*maskptr += i;
	return 0;
}

static inline int
target_different(const unsigned char *a_targdata,
		 const unsigned char *b_targdata,
		 unsigned int tdatasize,
		 const unsigned char *mask)
{
	unsigned int i;
	for (i = 0; i < tdatasize; i++)
		if (((a_targdata[i] ^ b_targdata[i]) & mask[i]) != 0)
			return 1;

	return 0;
}

static inline int
is_same(const struct ipt_entry *a, const struct ipt_entry *b,
	unsigned char *matchmask)
{
	unsigned int i;
	struct ipt_entry_target *ta, *tb;
	unsigned char *mptr;

	/* Always compare head structures: ignore mask here. */
	if (a->ip.src.s_addr != b->ip.src.s_addr
	    || a->ip.dst.s_addr != b->ip.dst.s_addr
	    || a->ip.smsk.s_addr != b->ip.smsk.s_addr
	    || a->ip.smsk.s_addr != b->ip.smsk.s_addr
	    || a->ip.proto != b->ip.proto
	    || a->ip.flags != b->ip.flags
	    || a->ip.invflags != b->ip.invflags)
		return 0;

	for (i = 0; i < IFNAMSIZ; i++) {
		if (a->ip.iniface_mask[i] != b->ip.iniface_mask[i])
			return 0;
		if ((a->ip.iniface[i] & a->ip.iniface_mask[i])
		    != (b->ip.iniface[i] & b->ip.iniface_mask[i]))
			return 0;
		if (a->ip.outiface_mask[i] != b->ip.outiface_mask[i])
			return 0;
		if ((a->ip.outiface[i] & a->ip.outiface_mask[i])
		    != (b->ip.outiface[i] & b->ip.outiface_mask[i]))
			return 0;
	}

	if (a->nfcache != b->nfcache
	    || a->target_offset != b->target_offset
	    || a->next_offset != b->next_offset)
		return 0;

	mptr = matchmask + sizeof(struct ipt_entry);
	if (IPT_MATCH_ITERATE(a, match_different, a->elems, b->elems, &mptr))
		return 0;

	ta = ipt_get_target((struct ipt_entry *)a);
	tb = ipt_get_target((struct ipt_entry *)b);
	if (ta->target_size != tb->target_size)
		return 0;
	if (strcmp(ta->u.name, tb->u.name) != 0)
		return 0;

	mptr += sizeof(*ta);
	if (target_different(ta->data, tb->data,
			     ta->target_size - sizeof(*ta), mptr))
		return 0;

   	return 1;
}

/* Delete the first rule in `chain' which matches `fw'. */
int
iptc_delete_entry(const ipt_chainlabel chain,
		  const struct ipt_entry *origfw,
		  unsigned char *matchmask,
		  iptc_handle_t *handle)
{
	unsigned int offset, lastoff;
	struct ipt_entry *e, *fw;

	CHECK(*handle);
	iptc_fn = iptc_delete_entry;
	if (!find_label(&offset, chain, *handle)) {
		errno = ENOENT;
		return 0;
	}

	fw = malloc(origfw->next_offset);
	if (fw == NULL) {
		errno = ENOMEM;
		return 0;
	}
	lastoff = get_chain_end(*handle, offset);

	for (; offset < lastoff; offset += e->next_offset) {
		struct ipt_entry_target discard;

		memcpy(fw, origfw, origfw->next_offset);

		/* FIXME: handle this in is_same --RR */
		if (!map_target(*handle, fw, offset, &discard)) {
			free(fw);
			return 0;
		}
		e = get_entry(*handle, offset);

#if 0
		printf("Deleting:\n");
		dump_entry(newe);
#endif
		if (is_same(e, fw, matchmask)) {
			int ret;
			ret = delete_rules(1, e->next_offset,
					   offset, entry2index(*handle, e),
					   handle);
			free(fw);
			CHECK(*handle);
			return ret;
		}
	}

	free(fw);
	errno = ENOENT;
	return 0;
}

/* Delete the rule in position `rulenum' in `chain'. */
int
iptc_delete_num_entry(const ipt_chainlabel chain,
		      unsigned int rulenum,
		      iptc_handle_t *handle)
{
	unsigned int chainstart;
	unsigned int index;
	int ret;
	struct ipt_entry *e;

	CHECK(*handle);
	iptc_fn = iptc_delete_num_entry;
	if (!find_label(&chainstart, chain, *handle)) {
		errno = ENOENT;
		return 0;
	}

	index = entry2index(*handle, get_entry(*handle, chainstart))
		+ rulenum;

	if (index
	    >= entry2index(*handle,
			  get_entry(*handle,
				    get_chain_end(*handle, chainstart)))) {
		errno = E2BIG;
		return 0;
	}

	e = index2entry(*handle, index);
	if (e == NULL) {
		errno = EINVAL;
		return 0;
	}

	ret = delete_rules(1, e->next_offset, entry2offset(*handle, e),
			   index, handle);
	CHECK(*handle);
	return ret;
}

/* Check the packet `fw' on chain `chain'.  Returns the verdict, or
   NULL and sets errno. */
const char *
iptc_check_packet(const ipt_chainlabel chain,
			      struct ipt_entry *entry,
			      iptc_handle_t *handle)
{
	errno = ENOSYS;
	return NULL;
}

/* Flushes the entries in the given chain (ie. empties chain). */
int
iptc_flush_entries(const ipt_chainlabel chain, iptc_handle_t *handle)
{
	unsigned int startoff, endoff, startindex, endindex;
	int ret;

	CHECK(*handle);
	iptc_fn = iptc_flush_entries;
	if (!find_label(&startoff, chain, *handle)) {
		errno = ENOENT;
		return 0;
	}
	endoff = get_chain_end(*handle, startoff);
	startindex = entry2index(*handle, get_entry(*handle, startoff));
	endindex = entry2index(*handle, get_entry(*handle, endoff));

	ret = delete_rules(endindex - startindex,
			   endoff - startoff, startoff, startindex,
			   handle);
	CHECK(*handle);
	return ret;
}

/* Zeroes the counters in a chain. */
int
iptc_zero_entries(const ipt_chainlabel chain, iptc_handle_t *handle)
{
	unsigned int i, end;

	CHECK(*handle);
	if (!find_label(&i, chain, *handle)) {
		errno = ENOENT;
		return 0;
	}
	end = get_chain_end(*handle, i);

	i = entry2index(*handle, get_entry(*handle, i));
	end = entry2index(*handle, get_entry(*handle, end));

	for (; i <= end; i++) {
		if ((*handle)->counter_map[i].maptype ==COUNTER_MAP_NORMAL_MAP)
			(*handle)->counter_map[i].maptype = COUNTER_MAP_ZEROED;
	}
	set_changed(*handle);

	CHECK(*handle);
	return 1;
}

/* Creates a new chain. */
/* To create a chain, create two rules: error node and unconditional
 * return. */
int
iptc_create_chain(const ipt_chainlabel chain, iptc_handle_t *handle)
{
	unsigned int pos;
	int ret;
	struct {
		struct ipt_entry head;
		struct ipt_error_target name;
		struct ipt_entry ret;
		struct ipt_standard_target target;
	} newc;

	CHECK(*handle);
	iptc_fn = iptc_create_chain;

	/* find_label doesn't cover built-in targets: DROP, ACCEPT,
           QUEUE, RETURN. */
	if (find_label(&pos, chain, *handle)
	    || strcmp(chain, IPTC_LABEL_DROP) == 0
	    || strcmp(chain, IPTC_LABEL_ACCEPT) == 0
	    || strcmp(chain, IPTC_LABEL_QUEUE) == 0
	    || strcmp(chain, IPTC_LABEL_RETURN) == 0) {
		errno = EEXIST;
		return 0;
	}

	if (strlen(chain)+1 > sizeof(ipt_chainlabel)) {
		errno = EINVAL;
		return 0;
	}

	memset(&newc, 0, sizeof(newc));
	newc.head.target_offset = sizeof(struct ipt_entry);
	newc.head.next_offset
		= sizeof(struct ipt_entry) + sizeof(struct ipt_error_target);
	strcpy(newc.name.t.u.name, IPT_ERROR_TARGET);
	newc.name.t.target_size = sizeof(struct ipt_error_target);
	strcpy(newc.name.error, chain);

	newc.ret.target_offset = sizeof(struct ipt_entry);
	newc.ret.next_offset
		= sizeof(struct ipt_entry)+sizeof(struct ipt_standard_target);
	strcpy(newc.target.target.u.name, IPT_STANDARD_TARGET);
	newc.target.target.target_size = sizeof(struct ipt_standard_target);
	newc.target.verdict = IPT_RETURN;

	/* Add just before terminal entry */
	ret = insert_rules(2, sizeof(newc), &newc.head,
			   index2offset(*handle, (*handle)->new_number - 1),
			   (*handle)->new_number - 1,
			   0, handle);
	CHECK(*handle);
	return ret;
}

static int
count_ref(struct ipt_entry *e, unsigned int offset, unsigned int *ref)
{
	struct ipt_standard_target *t;

	if (strcmp(ipt_get_target(e)->u.name, IPT_STANDARD_TARGET) == 0) {
		t = (struct ipt_standard_target *)ipt_get_target(e);

		if (t->verdict == offset)
			(*ref)++;
	}

	return 0;
}

/* Get the number of references to this chain. */
int
iptc_get_references(unsigned int *ref, const ipt_chainlabel chain,
		    iptc_handle_t *handle)
{
	unsigned int offset;

	CHECK(*handle);
	if (!find_label(&offset, chain, *handle)) {
		errno = ENOENT;
		return 0;
	}

	*ref = 0;
	IPT_ENTRY_ITERATE((*handle)->entries.entries,
			  (*handle)->entries.size,
			  count_ref, offset, ref);
	return 1;
}

/* Deletes a chain. */
int
iptc_delete_chain(const ipt_chainlabel chain, iptc_handle_t *handle)
{
	unsigned int chainoff, labelidx, labeloff;
	unsigned int references;
	struct ipt_entry *e;
	int ret;

	CHECK(*handle);
	if (!iptc_get_references(&references, chain, handle))
		return 0;

	iptc_fn = iptc_delete_chain;

	if (iptc_builtin(chain, *handle)) {
		errno = EINVAL;
		return 0;
	}

	if (references > 0) {
		errno = EMLINK;
		return 0;
	}

	if (!find_label(&chainoff, chain, *handle)) {
		errno = ENOENT;
		return 0;
	}

	e = get_entry(*handle, chainoff);
	if (get_chain_end(*handle, chainoff) != chainoff) {
		errno = ENOTEMPTY;
		return 0;
	}

	/* Need label index: preceeds chain start */
	labelidx = entry2index(*handle, e) - 1;
	labeloff = index2offset(*handle, labelidx);

	ret = delete_rules(2,
			   get_entry(*handle, labeloff)->next_offset
			   + e->next_offset,
			   labeloff, labelidx, handle);
	CHECK(*handle);
	return ret;
}

/* Renames a chain. */
int iptc_rename_chain(const ipt_chainlabel oldname,
		      const ipt_chainlabel newname,
		      iptc_handle_t *handle)
{
	unsigned int chainoff, labeloff, labelidx;
	struct ipt_error_target *t;

	CHECK(*handle);
	iptc_fn = iptc_rename_chain;

	/* find_label doesn't cover built-in targets: DROP, ACCEPT
           RETURN. */
	if (find_label(&chainoff, newname, *handle)
	    || strcmp(newname, IPTC_LABEL_DROP) == 0
	    || strcmp(newname, IPTC_LABEL_ACCEPT) == 0
	    || strcmp(newname, IPTC_LABEL_RETURN) == 0) {
		errno = EEXIST;
		return 0;
	}

	if (!find_label(&chainoff, oldname, *handle)
	    || iptc_builtin(oldname, *handle)) {
		errno = ENOENT;
		return 0;
	}

	if (strlen(newname)+1 > sizeof(ipt_chainlabel)) {
		errno = EINVAL;
		return 0;
	}

	/* Need label index: preceeds chain start */
	labelidx = entry2index(*handle, get_entry(*handle, chainoff)) - 1;
	labeloff = index2offset(*handle, labelidx);

	t = (struct ipt_error_target *)
		ipt_get_target(get_entry(*handle, labeloff));

	memset(t->error, 0, sizeof(t->error));
	strcpy(t->error, newname);
	set_changed(*handle);

	CHECK(*handle);
	return 1;
}

/* Sets the policy on a built-in chain. */
int
iptc_set_policy(const ipt_chainlabel chain,
		const ipt_chainlabel policy,
		iptc_handle_t *handle)
{
	unsigned int hook;
	unsigned int policyoff;
	struct ipt_entry *e;
	struct ipt_standard_target *t;

	CHECK(*handle);
	/* Figure out which chain. */
	hook = iptc_builtin(chain, *handle);
	if (hook == 0) {
		errno = EINVAL;
		return 0;
	} else
		hook--;

	policyoff = get_chain_end(*handle, (*handle)->info.hook_entry[hook]);
	if (policyoff != (*handle)->info.underflow[hook]) {
		printf("ERROR: Policy for `%s' offset %u != underflow %u\n",
		       chain, policyoff, (*handle)->info.underflow[hook]);
		return 0;
	}

	e = get_entry(*handle, policyoff);
	t = (struct ipt_standard_target *)ipt_get_target(e);

	if (strcmp(policy, IPTC_LABEL_ACCEPT) == 0)
		t->verdict = -NF_ACCEPT - 1;
	else if (strcmp(policy, IPTC_LABEL_DROP) == 0)
		t->verdict = -NF_DROP - 1;
	else {
		errno = EINVAL;
		return 0;
	}
	(*handle)->counter_map[entry2index(*handle, e)]
		= ((struct counter_map){ COUNTER_MAP_NOMAP, 0 });
	set_changed(*handle);

	CHECK(*handle);
	return 1;
}

/* Without this, on gcc 2.7.2.3, we get:
   libiptc.c: In function `iptc_commit':
   libiptc.c:833: fixed or forbidden register was spilled.
   This may be due to a compiler bug or to impossible asm
   statements or clauses.
*/
static void
subtract_counters(struct ipt_counters *answer,
		  const struct ipt_counters *a,
		  const struct ipt_counters *b)
{
	answer->pcnt = a->pcnt - b->pcnt;
	answer->bcnt = a->bcnt - b->bcnt;
}

int
iptc_commit(iptc_handle_t *handle)
{
	/* Replace, then map back the counters. */
	struct ipt_replace *repl;
	struct ipt_counters_info *newcounters;
	unsigned int i;
	size_t counterlen
		= sizeof(struct ipt_counters_info)
		+ sizeof(struct ipt_counters) * (*handle)->new_number;

	CHECK(*handle);
#if 0
	dump_entries(*handle);
#endif

	/* Don't commit if nothing changed. */
	if (!(*handle)->changed)
		goto finished;

	repl = malloc(sizeof(*repl) + (*handle)->entries.size);
	if (!repl) {
		errno = ENOMEM;
		return 0;
	}

	/* These are the old counters we will get from kernel */
	repl->counters = malloc(sizeof(struct ipt_counters)
				* (*handle)->info.num_entries);
	if (!repl->counters) {
		free(repl);
		errno = ENOMEM;
		return 0;
	}

	/* These are the counters we're going to put back, later. */
	newcounters = malloc(counterlen);
	if (!newcounters) {
		free(repl->counters);
		free(repl);
		errno = ENOMEM;
		return 0;
	}

	strcpy(repl->name, (*handle)->info.name);
	repl->num_entries = (*handle)->new_number;
	repl->size = (*handle)->entries.size;
	memcpy(repl->hook_entry, (*handle)->info.hook_entry,
	       sizeof(repl->hook_entry));
	memcpy(repl->underflow, (*handle)->info.underflow,
	       sizeof(repl->underflow));
	repl->num_counters = (*handle)->info.num_entries;
	repl->valid_hooks = (*handle)->info.valid_hooks;
	memcpy(repl->entries, (*handle)->entries.entries,
	       (*handle)->entries.size);

	if (setsockopt(sockfd, IPPROTO_IP, IPT_SO_SET_REPLACE, repl,
		       sizeof(*repl) + (*handle)->entries.size) < 0) {
		free(repl->counters);
		free(repl);
		free(newcounters);
		return 0;
	}

	/* Put counters back. */
	strcpy(newcounters->name, (*handle)->info.name);
	newcounters->num_counters = (*handle)->new_number;
	for (i = 0; i < (*handle)->new_number; i++) {
		unsigned int mappos = (*handle)->counter_map[i].mappos;
		switch ((*handle)->counter_map[i].maptype) {
		case COUNTER_MAP_NOMAP:
			newcounters->counters[i]
				= ((struct ipt_counters){ 0, 0 });
			break;

		case COUNTER_MAP_NORMAL_MAP:
			/* Original read: X.
			 * Atomic read on replacement: X + Y.
			 * Currently in kernel: Z.
			 * Want in kernel: X + Y + Z.
			 * => Add in X + Y
			 * => Add in replacement read.
			 */
			newcounters->counters[i] = repl->counters[mappos];
			break;

		case COUNTER_MAP_ZEROED:
			/* Original read: X.
			 * Atomic read on replacement: X + Y.
			 * Currently in kernel: Z.
			 * Want in kernel: Y + Z.
			 * => Add in Y.
			 * => Add in (replacement read - original read).
			 */
			subtract_counters(&newcounters->counters[i],
					  &repl->counters[mappos],
					  &index2entry(*handle, i)->counters);
			break;
		}
	}

	if (setsockopt(sockfd, IPPROTO_IP, IPT_SO_SET_ADD_COUNTERS,
	       newcounters, counterlen) < 0) {
		free(repl->counters);
		free(repl);
		free(newcounters);
		return 0;
	}

	free(repl->counters);
	free(repl);
	free(newcounters);

 finished:
	free(*handle);
	*handle = NULL;
	return 1;
}

/* Get raw socket. */
int
iptc_get_raw_socket()
{
	return sockfd;
}

/* Translates errno numbers into more human-readable form than strerror. */
const char *
iptc_strerror(int err)
{
	unsigned int i;
	struct table_struct {
		void *fn;
		int err;
		const char *message;
	} table [] =
	  { { NULL, 0, "Incompatible with this kernel" },
	    { NULL, ENOPROTOOPT, "iptables who? (do you need to insmod?)" },
	    { NULL, ENOSYS, "Will be implemented real soon.  I promise." },
	    { NULL, ENOMEM, "Memory allocation problem" },
	    { iptc_init, EPERM, "Permission denied (you must be root)" },
	    { iptc_init, EINVAL, "Module is wrong version" },
	    { iptc_delete_chain, ENOTEMPTY, "Chain is not empty" },
	    { iptc_delete_chain, EINVAL, "Can't delete built-in chain" },
	    { iptc_delete_chain, EMLINK,
	      "Can't delete chain with references left" },
	    { iptc_create_chain, EEXIST, "Chain already exists" },
	    { iptc_insert_entry, E2BIG, "Index of insertion too big" },
	    { iptc_replace_entry, E2BIG, "Index of replacement too big" },
	    { iptc_delete_num_entry, E2BIG, "Index of deletion too big" },
	    { iptc_insert_entry, ELOOP, "Loop found in table" },
	    { iptc_insert_entry, EINVAL, "Target problem" },
	    /* EINVAL for CHECK probably means bad interface. */
	    { iptc_check_packet, EINVAL,
	      "bad arguments (does that interface exist?)" },
	    /* ENOENT for DELETE probably means no matching rule */
	    { iptc_delete_entry, ENOENT,
	      "bad rule (does a matching rule exist in that chain?)" },
	    { NULL, ENOENT, "No extended target/match by that name" }
	  };

	for (i = 0; i < sizeof(table)/sizeof(struct table_struct); i++) {
		if ((!table[i].fn || table[i].fn == iptc_fn)
		    && table[i].err == err)
			return table[i].message;
	}

	return strerror(err);
}

/***************************** DEBUGGING ********************************/
static inline int
unconditional(const struct ipt_ip *ip)
{
	unsigned int i;

	for (i = 0; i < sizeof(*ip)/sizeof(u_int32_t); i++)
		if (((u_int32_t *)ip)[i])
			return 0;

	return 1;
}

static inline int
check_match(const struct ipt_entry_match *m, unsigned int *off)
{
	assert(m->match_size >= sizeof(struct ipt_entry_match));

	(*off) += m->match_size;
	return 0;
}

static inline int
check_entry(const struct ipt_entry *e, unsigned int *i, unsigned int *off,
	    unsigned int user_offset, int *was_return,
	    iptc_handle_t h)
{
	unsigned int toff;
	struct ipt_standard_target *t;

	assert(e->target_offset >= sizeof(struct ipt_entry));
	assert(e->next_offset >= e->target_offset
	       + sizeof(struct ipt_entry_target));
	toff = sizeof(struct ipt_entry);
	IPT_MATCH_ITERATE(e, check_match, &toff);

	assert(toff == e->target_offset);

	t = (struct ipt_standard_target *)
		ipt_get_target((struct ipt_entry *)e);
	assert(t->target.target_size == e->next_offset - e->target_offset);
	assert(!iptc_is_chain(t->target.u.name, h));

	if (strcmp(t->target.u.name, IPT_STANDARD_TARGET) == 0) {
		assert(t->target.target_size
		       == IPT_ALIGN(sizeof(struct ipt_standard_target)));

		assert(t->verdict == -NF_DROP-1
		       || t->verdict == -NF_ACCEPT-1
		       || t->verdict == IPT_RETURN
		       || t->verdict < (int)h->entries.size);

		if (t->verdict >= 0) {
			struct ipt_entry *te = get_entry(h, t->verdict);
			int idx;

			idx = entry2index(h, te);
			assert(strcmp(ipt_get_target(te)->u.name,
				      IPT_ERROR_TARGET)
			       != 0);
			assert(te != e);

			/* Prior node must be error node, or this node. */
			assert(t->verdict == entry2offset(h, e)+e->next_offset
			       || strcmp(ipt_get_target(index2entry(h, idx-1))
					 ->u.name, IPT_ERROR_TARGET)
			       == 0);
		}

		if (t->verdict == IPT_RETURN
		    && unconditional(&e->ip)
		    && e->target_offset == sizeof(*e))
			*was_return = 1;
		else
			*was_return = 0;
	} else if (strcmp(t->target.u.name, IPT_ERROR_TARGET) == 0) {
		assert(t->target.target_size
		       == IPT_ALIGN(sizeof(struct ipt_error_target)));

		/* If this is in user area, previous must have been return */
		if (*off > user_offset)
			assert(*was_return);

		*was_return = 0;
	}
	else *was_return = 0;

	if (*off == user_offset)
		assert(strcmp(t->target.u.name, IPT_ERROR_TARGET) == 0);

	(*off) += e->next_offset;
	(*i)++;
	return 0;
}

/* Do every conceivable sanity check on the handle */
static void
do_check(iptc_handle_t h, unsigned int line)
{
	unsigned int i, n;
	unsigned int user_offset; /* Offset of first user chain */
	int was_return;

	assert(h->changed == 0 || h->changed == 1);
	if (strcmp(h->info.name, "filter") == 0) {
		assert(h->info.valid_hooks
		       == (1 << NF_IP_LOCAL_IN
			   | 1 << NF_IP_FORWARD
			   | 1 << NF_IP_LOCAL_OUT));

		/* Hooks should be first three */
		assert(h->info.hook_entry[NF_IP_LOCAL_IN] == 0);

		n = get_chain_end(h, 0);
		n += get_entry(h, n)->next_offset;
		assert(h->info.hook_entry[NF_IP_FORWARD] == n);

		n = get_chain_end(h, n);
		n += get_entry(h, n)->next_offset;
		assert(h->info.hook_entry[NF_IP_LOCAL_OUT] == n);

		user_offset = h->info.hook_entry[NF_IP_LOCAL_OUT];
	} else if (strcmp(h->info.name, "nat") == 0) {
		assert(h->info.valid_hooks
		       == (1 << NF_IP_PRE_ROUTING
			   | 1 << NF_IP_POST_ROUTING
			   | 1 << NF_IP_LOCAL_OUT));

		assert(h->info.hook_entry[NF_IP_PRE_ROUTING] == 0);

		n = get_chain_end(h, 0);
		n += get_entry(h, n)->next_offset;
		assert(h->info.hook_entry[NF_IP_POST_ROUTING] == n);

		n = get_chain_end(h, n);
		n += get_entry(h, n)->next_offset;
		assert(h->info.hook_entry[NF_IP_LOCAL_OUT] == n);

		user_offset = h->info.hook_entry[NF_IP_LOCAL_OUT];
	} else if (strcmp(h->info.name, "mangle") == 0) {
		assert(h->info.valid_hooks
		       == (1 << NF_IP_PRE_ROUTING
			   | 1 << NF_IP_LOCAL_OUT));

		/* Hooks should be first three */
		assert(h->info.hook_entry[NF_IP_PRE_ROUTING] == 0);

		n = get_chain_end(h, 0);
		n += get_entry(h, n)->next_offset;
		assert(h->info.hook_entry[NF_IP_LOCAL_OUT] == n);

		user_offset = h->info.hook_entry[NF_IP_LOCAL_OUT];
	} else
		abort();

	/* User chain == end of last builtin + policy entry */
	user_offset = get_chain_end(h, user_offset);
	user_offset += get_entry(h, user_offset)->next_offset;

	/* Overflows should be end of entry chains, and unconditional
           policy nodes. */
	for (i = 0; i < NF_IP_NUMHOOKS; i++) {
		struct ipt_entry *e;
		struct ipt_standard_target *t;

		if (!(h->info.valid_hooks & (1 << i)))
			continue;
		assert(h->info.underflow[i]
		       == get_chain_end(h, h->info.hook_entry[i]));

		e = get_entry(h, get_chain_end(h, h->info.hook_entry[i]));
		assert(unconditional(&e->ip));
		assert(e->target_offset == sizeof(*e));
		assert(e->next_offset == sizeof(*e) + sizeof(*t));
		t = (struct ipt_standard_target *)ipt_get_target(e);

		assert(strcmp(t->target.u.name, IPT_STANDARD_TARGET) == 0);
		assert(t->verdict == -NF_DROP-1 || t->verdict == -NF_ACCEPT-1);

		/* Hooks and underflows must be valid entries */
		entry2index(h, get_entry(h, h->info.hook_entry[i]));
		entry2index(h, get_entry(h, h->info.underflow[i]));
	}

	assert(h->info.size
	       >= h->info.num_entries * (sizeof(struct ipt_entry)
					 +sizeof(struct ipt_standard_target)));

	assert(h->entries.size
	       >= (h->new_number
		   * (sizeof(struct ipt_entry)
		      + sizeof(struct ipt_standard_target))));
	assert(strcmp(h->info.name, h->entries.name) == 0);

	i = 0; n = 0;
	was_return = 0;
	/* Check all the entries. */
	IPT_ENTRY_ITERATE(h->entries.entries, h->entries.size,
			  check_entry, &i, &n, user_offset, &was_return, h);

	assert(i == h->new_number);
	assert(n == h->entries.size);

	/* Final entry must be error node */
	assert(strcmp(ipt_get_target(index2entry(h, h->new_number-1))->u.name,
		      IPT_ERROR_TARGET) == 0);
}
