/* Shared library add-on to iptables for SCTP matching
 *
 * (C) 2003 by Harald Welte <laforge@gnumonks.org>
 *
 * This program is distributed under the terms of GNU GPL v2, 1991
 *
 * libipt_ecn.c borrowed heavily from libipt_dscp.c
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <netdb.h>

#include <iptables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_sctp.h>

/* Initialize the match. */
static void
init(struct ipt_entry_match *m, unsigned int *nfcache)
{
	struct ipt_sctp_info *einfo = (struct ipt_sctp_info *)m->data;

	einfo->spts[1] = einfo->dpts[1] = 0xFFFF;
}

static void help(void) 
{
	printf(
"SCTP match v%s options\n"
" --sctp-chunks [!] mask comp	match when SCTP chunks & mask == comp\n"
" --source-port [!] port[:port]\n"
" --sport ...\n"
"                               match source port(s)"
" --destination-port [!] port[:port]\n"
" --dport ...\n\n",
	IPTABLES_VERSION);
}

static struct option opts[] = {
	{ .name = "source-port", .has_arg = 1, .flag = 0, .val = '1' },
	{ .name = "sport", .has_arg = 1, .flag = 0, .val = '1' },
	{ .name = "destination-port", .has_arg = 1, .flag = 0, .val = '2' },
	{ .name = "dport", .has_arg = 1, .flag = 0, .val = '2' },
	{ .name = "sctp-chunks", .has_arg = 1, .flag = 0, .val = '3' },
	{ .name = 0 }
};

static int
service_to_port(const char *name)
{
	struct servent *service;

	if ((service = getservbyname(name, "sctp")) != NULL)
		return ntohs((unsigned short) service->s_port);

	return -1;
}

static u_int16_t
parse_sctp_port(const char *port)
{
	unsigned int portnum;

	if (string_to_number(port, 0, 65535, &portnum) != -1 ||
	    (portnum = service_to_port(port)) != -1)
		return (u_int16_t)portnum;

	exit_error(PARAMETER_PROBLEM,
		   "invalid TCP port/service `%s' specified", port);
}


static void
parse_sctp_ports(const char *portstring, u_int16_t *ports)
{
	char *buffer;
	char *cp;

	buffer = strdup(portstring);
	if ((cp = strchr(buffer, ':')) == NULL)
		ports[0] = ports[1] = parse_sctp_port(buffer);
	else {
		*cp = '\0';
		cp++;

		ports[0] = buffer[0] ? parse_sctp_port(buffer) : 0;
		ports[1] = cp[0] ? parse_sctp_port(cp) : 0xFFFF;

		if (ports[0] > ports[1])
			exit_error(PARAMETER_PROBLEM,
				   "invalid portrange (min > max)");
	}
	free(buffer);
}

struct sctp_chunk_names {
	const char *name;
	unsigned int flag;
};

/* FIXME: */
#define ALL_CHUNKS	0xabcdef
static struct sctp_chunk_names sctp_chunk_names[]
= { { .name = "DATA", 		.flag = (1 << 0) },
    { .name = "INIT", 		.flag = (1 << 1) },
    { .name = "INIT_ACK", 	.flag = (1 << 2) },
    { .name = "SACK",		.flag = (1 << 3) },
    { .name = "HEARTBEAT",	.flag = (1 << 4) },
    { .name = "HEARTBEAT_ACK",	.flag = (1 << 5) },
    { .name = "ABORT",		.flag = (1 << 6) },
    { .name = "SHUTDOWN",	.flag = (1 << 7) },
    { .name = "SHUTDOWN_ACK",	.flag = (1 << 8) },
    { .name = "ERROR",		.flag = (1 << 9) },
    { .name = "COOKIE_ECHO",	.flag = (1 << 10) },
    { .name = "COOKIE_ACK",	.flag = (1 << 11) },
    { .name = "ECN_ECNE",	.flag = (1 << 12) },
    { .name = "ECN_CWR",	.flag = (1 << 13) },
    { .name = "SHUTDOWN_COMPLETE", .flag = (1 << 14) },
    { .name = "ASCONF",		.flag = (1 << 31) },
    { .name = "ASCONF_ACK",	.flag = (1 << 30) },
    { .name = "ALL", 		.flag = ALL_CHUNKS },
    { .name = "NONE",		.flag = 0 },
};


static unsigned int
parse_sctp_chunk(const char *flags)
{
	unsigned int ret = 0;
	char *ptr;
	char *buffer;

	buffer = strdup(flags);

	for (ptr = strtok(buffer, ","); ptr; ptr = strtok(NULL, ",")) {
		unsigned int i;
		int found = 0;
		for (i = 0;
		     i < sizeof(sctp_chunk_names)/sizeof(struct sctp_chunk_names);
		     i++) {
			if (strcasecmp(sctp_chunk_names[i].name, ptr) == 0) {
				ret |= sctp_chunk_names[i].flag;
				found = 1;
				break;
			}
		}
		if (!found)
			exit_error(PARAMETER_PROBLEM,
				   "Unknown sctp chunk `%s'", ptr);
	}

	free(buffer);
	return ret;
}

static void
parse_sctp_chunks(struct ipt_sctp_info *einfo,
		const char *mask,
		const char *cmp,
		int invert)
{
	einfo->chunks = parse_sctp_chunk(mask);
	einfo->chunk_mask = parse_sctp_chunk(cmp);

	if (invert)
		einfo->invflags |= IPT_SCTP_INV_CHUNKS;
}

#define SCTP_SRC_PORTS	0x01
#define SCTP_DST_PORTS	0x02
#define SCTP_CHUNKS	0x03

static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      unsigned int *nfcache,
      struct ipt_entry_match **match)
{
	struct ipt_sctp_info *einfo
		= (struct ipt_sctp_info *)(*match)->data;

	switch (c) {
	case '1':
		if (*flags & SCTP_SRC_PORTS)
			exit_error(PARAMETER_PROBLEM,
			           "Only one `--source-port' allowed");
		check_inverse(optarg, &invert, &optind, 0);
		parse_sctp_ports(argv[optind-1], einfo->spts);
		if (invert)
			einfo->invflags |= IPT_SCTP_INV_SRCPT;
		*flags |= SCTP_SRC_PORTS;
		*nfcache |= NFC_IP_SRC_PT;
		break;

	case '2':
		if (*flags & SCTP_DST_PORTS)
			exit_error(PARAMETER_PROBLEM,
				   "Only one `--destination-port' allowed");
		check_inverse(optarg, &invert, &optind, 0);
		parse_sctp_ports(argv[optind-1], einfo->dpts);
		if (invert)
			einfo->invflags |= IPT_SCTP_INV_DSTPT;
		*flags |= SCTP_DST_PORTS;
		*nfcache |= NFC_IP_DST_PT;
		break;

	case '3':
		if (*flags & SCTP_CHUNKS)
			exit_error(PARAMETER_PROBLEM,
				   "Only one `--sctp-chunks' allowed");
		check_inverse(optarg, &invert, &optind, 0);

		if (!argv[optind] 
		    || argv[optind][0] == '-' || argv[optind][0] == '!')
			exit_error(PARAMETER_PROBLEM,
				   "--sctp-chunks requires two args");

		parse_sctp_chunks(einfo, argv[optind-1], argv[optind], invert);
		optind++;
		*flags |= SCTP_CHUNKS;
		break;
	default:
		return 0;
	}

	return 1;
}

static void
final_check(unsigned int flags)
{
}

static char *
port_to_service(int port)
{
	struct servent *service;

	if ((service = getservbyport(htons(port), "sctp")))
		return service->s_name;

	return NULL;
}

static void
print_port(u_int16_t port, int numeric)
{
	char *service;

	if (numeric || (service = port_to_service(port)) == NULL)
		printf("%u", port);
	else
		printf("%s", service);
}

static void
print_ports(const char *name, u_int16_t min, u_int16_t max,
	    int invert, int numeric)
{
	const char *inv = invert ? "!" : "";

	if (min != 0 || max != 0xFFFF || invert) {
		printf("%s", name);
		if (min == max) {
			printf(":%s", inv);
			print_port(min, numeric);
		} else {
			printf("s:%s", inv);
			print_port(min, numeric);
			printf(":");
			print_port(max, numeric);
		}
		printf(" ");
	}
}

static void
print_chunk(u_int32_t chunks)
{
	unsigned int have_flag = 0;

	while (chunks) {
		unsigned int i;

		for (i = 0; (chunks & sctp_chunk_names[i].flag) == 0; i++);

		if (have_flag)
			printf(",");
		printf("%s", sctp_chunk_names[i].name);
		have_flag = 1;

		chunks &= ~sctp_chunk_names[i].flag;
	}

	if (!have_flag)
		printf("NONE");
}

static void
print_chunks(u_int32_t mask, u_int32_t cmp, int invert, int numeric)
{
	if (mask || invert) {
		printf("flags:%s", invert ? "!" : "");
		if (numeric)
			printf("0x%04X/0x%04X ", mask, cmp);
		else {
			print_chunk(mask);
			printf("/");
			print_chunk(cmp);
			printf(" ");
		}
	}
}

/* Prints out the matchinfo. */
static void
print(const struct ipt_ip *ip,
      const struct ipt_entry_match *match,
      int numeric)
{
	const struct ipt_sctp_info *einfo =
		(const struct ipt_sctp_info *)match->data;

	printf("sctp ");

	print_ports("spt", einfo->spts[0], einfo->spts[1],
		    einfo->invflags & IPT_SCTP_INV_SRCPT,
		    numeric);
	print_ports("dpt", einfo->dpts[0], einfo->dpts[1],
		    einfo->invflags & IPT_SCTP_INV_DSTPT,
		    numeric);

	print_chunks(einfo->chunks, einfo->chunk_mask,
		     einfo->invflags & ~IPT_SCTP_INV_MASK,
		     numeric);
}

/* Saves the union ipt_matchinfo in parsable form to stdout. */
static void
save(const struct ipt_ip *ip, const struct ipt_entry_match *match)
{
	const struct ipt_sctp_info *einfo =
		(const struct ipt_sctp_info *)match->data;

	if (einfo->spts[0] != 0
	    || einfo->spts[1] != 0xFFFF) {
		if (einfo->invflags & IPT_SCTP_INV_SRCPT)
			printf("! ");
		if (einfo->spts[0] != einfo->spts[1])
			printf("--sport %u:%u ", 
			       einfo->spts[0], einfo->spts[1]);
		else
			printf("--sport %u ", einfo->spts[0]);
	}

	if (einfo->dpts[0] != 0
	    || einfo->dpts[1] != 0xFFFF) {
		if (einfo->invflags & IPT_SCTP_INV_DSTPT)
			printf("! ");
		if (einfo->dpts[0] != einfo->dpts[1])
			printf("--dport %u:%u ",
			       einfo->dpts[0], einfo->dpts[1]);
		else
			printf("--dport %u ", einfo->dpts[0]);
	}

	if (einfo->chunks
	    || (einfo->invflags & IPT_SCTP_INV_CHUNKS)) {
		if (einfo->invflags & IPT_SCTP_INV_CHUNKS)
			printf("! ");
		printf("--sctp-chunks ");
		if (einfo->chunks != ALL_CHUNKS) {
			print_chunk(einfo->chunks);
		}
		printf(" ");
		print_chunk(einfo->chunk_mask);
		printf(" ");
	}
}

static
struct iptables_match sctp
= { .name          = "sctp",
    .version       = IPTABLES_VERSION,
    .size          = IPT_ALIGN(sizeof(struct ipt_sctp_info)),
    .userspacesize = IPT_ALIGN(sizeof(struct ipt_sctp_info)),
    .help          = &help,
    .init          = &init,
    .parse         = &parse,
    .final_check   = &final_check,
    .print         = &print,
    .save          = &save,
    .extra_opts    = opts
};

void _init(void)
{
	register_match(&sctp);
}
