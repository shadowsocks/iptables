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

#if 0
#define DEBUGP(format, first...) printf(format, ##first)
#define static
#else
#define DEBUGP(format, fist...) 
#endif

/*static void
print_chunks(u_int32_t chunk_match_type, const u_int32_t *chunkmap, int numeric);*/

/* Initialize the match. */
static void
init(struct ipt_entry_match *m, 
     unsigned int *nfcache)
{
	struct ipt_sctp_info *einfo = (struct ipt_sctp_info *)m->data;

	einfo->flags = einfo->invflags = 0;

	/*einfo->spts[0] = einfo->dpts[0] = 0;
	einfo->spts[1] = einfo->dpts[1] = 0xFFFF;
	SCTP_CHUNKMAP_RESET(einfo->chunkmap);*/
}

static void help(void)
{
	printf(
"SCTP match v%s options\n"
" --source-port [!] port[:port]                          match source port(s)\n"
" --sport ...\n"
" --destination-port [!] port[:port]                     match destination port(s)\n"
" --dport ...\n" 
" --chunk-types [!] (all|any|none) (chunktype[:flags])+	match if all, any or none of\n"
"						        chunktypes are present\n"
"chunktypes - DATA INIT INIT_ACK SACK HEARTBEAT HEARTBEAT_ACK ABORT SHUTDOWN SHUTDOWN_ACK ERROR COOKIE_ECHO COOKIE_ACK ECN_ECNE ECN_CWR SHUTDOWN_COMPLETE ASCONF ASCONF_ACK ALL NONE\n",
	IPTABLES_VERSION);
}

static struct option opts[] = {
	{ .name = "source-port", .has_arg = 1, .flag = 0, .val = '1' },
	{ .name = "sport", .has_arg = 1, .flag = 0, .val = '1' },
	{ .name = "destination-port", .has_arg = 1, .flag = 0, .val = '2' },
	{ .name = "dport", .has_arg = 1, .flag = 0, .val = '2' },
	{ .name = "chunk-types", .has_arg = 1, .flag = 0, .val = '3' },
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

	DEBUGP("%s\n", port);
	if (string_to_number(port, 0, 65535, &portnum) != -1 ||
	    (portnum = service_to_port(port)) != -1)
		return (u_int16_t)portnum;

	exit_error(PARAMETER_PROBLEM,
		   "invalid SCTP port/service `%s' specified", port);
}

static void
parse_sctp_ports(const char *portstring, 
		 u_int16_t *ports)
{
	char *buffer;
	char *cp;

	buffer = strdup(portstring);
	DEBUGP("%s\n", portstring);
	if ((cp = strchr(buffer, ':')) == NULL) {
		ports[0] = ports[1] = parse_sctp_port(buffer);
	}
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
	unsigned int chunk_type;
};

/*'ALL' and 'NONE' will be treated specially. */
static struct sctp_chunk_names sctp_chunk_names[]
= { { .name = "DATA", 		.chunk_type = 0 },
    { .name = "INIT", 		.chunk_type = 1 },
    { .name = "INIT_ACK", 	.chunk_type = 2 },
    { .name = "SACK",		.chunk_type = 3 },
    { .name = "HEARTBEAT",	.chunk_type = 4 },
    { .name = "HEARTBEAT_ACK",	.chunk_type = 5 },
    { .name = "ABORT",		.chunk_type = 6 },
    { .name = "SHUTDOWN",	.chunk_type = 7 },
    { .name = "SHUTDOWN_ACK",	.chunk_type = 8 },
    { .name = "ERROR",		.chunk_type = 9 },
    { .name = "COOKIE_ECHO",	.chunk_type = 10 },
    { .name = "COOKIE_ACK",	.chunk_type = 11 },
    { .name = "ECN_ECNE",	.chunk_type = 12 },
    { .name = "ECN_CWR",	.chunk_type = 13 },
    { .name = "SHUTDOWN_COMPLETE", .chunk_type = 14 },
    { .name = "ASCONF",		.chunk_type = 31 },
    { .name = "ASCONF_ACK",	.chunk_type = 30 },
};

static void
parse_sctp_chunk(struct ipt_sctp_info *einfo, 
		 const char *chunks)
{
	char *ptr;
	char *buffer;
	unsigned int i;
	int found = 0;

	buffer = strdup(chunks);
	DEBUGP("Buffer: %s\n", buffer);

	SCTP_CHUNKMAP_RESET(einfo->chunkmap);

	if (!strcasecmp(buffer, "ALL")) {
		SCTP_CHUNKMAP_SET_ALL(einfo->chunkmap);
		goto out;
	}
	
	if (!strcasecmp(buffer, "NONE")) {
		SCTP_CHUNKMAP_RESET(einfo->chunkmap);
		goto out;
	}

	for (ptr = strtok(buffer, ","); ptr; ptr = strtok(NULL, ",")) {
		found = 0;
		DEBUGP("Next Chunk type %s\n", ptr);
		for (i = 0; i < ELEMCOUNT(sctp_chunk_names); i++) {
			if (strcasecmp(sctp_chunk_names[i].name, ptr) == 0) {
				DEBUGP("Chunk num %d\n", sctp_chunk_names[i].chunk_type);
				SCTP_CHUNKMAP_SET(einfo->chunkmap, 
					sctp_chunk_names[i].chunk_type);
				found = 1;
				break;
			}
		}
		if (!found)
			exit_error(PARAMETER_PROBLEM,
				   "Unknown sctp chunk `%s'", ptr);
	}
out:
	free(buffer);
}

static void
parse_sctp_chunks(struct ipt_sctp_info *einfo,
		  const char *match_type,
		  const char *chunks)
{
	DEBUGP("Match type: %s Chunks: %s\n", match_type, chunks);
	if (!strcasecmp(match_type, "ANY")) {
		einfo->chunk_match_type = SCTP_CHUNK_MATCH_ANY;
	} else 	if (!strcasecmp(match_type, "ALL")) {
		einfo->chunk_match_type = SCTP_CHUNK_MATCH_ALL;
	} else 	if (!strcasecmp(match_type, "ONLY")) {
		einfo->chunk_match_type = SCTP_CHUNK_MATCH_ONLY;
	} else {
		exit_error (PARAMETER_PROBLEM, 
			"Match type has to be one of \"ALL\", \"ANY\" or \"ONLY\"");
	}

	SCTP_CHUNKMAP_RESET(einfo->chunkmap);
	parse_sctp_chunk(einfo, chunks);
}

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
		if (*flags & IPT_SCTP_SRC_PORTS)
			exit_error(PARAMETER_PROBLEM,
			           "Only one `--source-port' allowed");
		einfo->flags |= IPT_SCTP_SRC_PORTS;
		check_inverse(optarg, &invert, &optind, 0);
		parse_sctp_ports(argv[optind-1], einfo->spts);
		if (invert)
			einfo->invflags |= IPT_SCTP_SRC_PORTS;
		*flags |= IPT_SCTP_SRC_PORTS;
		*nfcache |= NFC_IP_SRC_PT;
		break;

	case '2':
		if (*flags & IPT_SCTP_DEST_PORTS)
			exit_error(PARAMETER_PROBLEM,
				   "Only one `--destination-port' allowed");
		einfo->flags |= IPT_SCTP_DEST_PORTS;
		check_inverse(optarg, &invert, &optind, 0);
		parse_sctp_ports(argv[optind-1], einfo->dpts);
		if (invert)
			einfo->invflags |= IPT_SCTP_DEST_PORTS;
		*flags |= IPT_SCTP_DEST_PORTS;
		*nfcache |= NFC_IP_DST_PT;
		break;

	case '3':
		if (*flags & IPT_SCTP_CHUNK_TYPES)
			exit_error(PARAMETER_PROBLEM,
				   "Only one `--chunk-types' allowed");
		check_inverse(optarg, &invert, &optind, 0);

		if (!argv[optind] 
		    || argv[optind][0] == '-' || argv[optind][0] == '!')
			exit_error(PARAMETER_PROBLEM,
				   "--chunk-types requires two args");

		einfo->flags |= IPT_SCTP_CHUNK_TYPES;
		parse_sctp_chunks(einfo, argv[optind-1], argv[optind]);
		if (invert)
			einfo->invflags |= IPT_SCTP_CHUNK_TYPES;
		optind++;
		*flags |= IPT_SCTP_CHUNK_TYPES;
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
print_chunk(u_int32_t chunknum, int numeric)
{
	if (numeric) {
		printf("0x%04X", chunknum);
	}
	else {
		printf("%s", sctp_chunk_names[chunknum].name);
	}
}

static void
print_chunks(u_int32_t chunk_match_type, 
	     const u_int32_t *chunkmap, 
	     int numeric)
{
	int i;
	int flag;

	switch (chunk_match_type) {
		case SCTP_CHUNK_MATCH_ANY:	printf("any "); break;
		case SCTP_CHUNK_MATCH_ALL:	printf("all "); break;
		case SCTP_CHUNK_MATCH_ONLY:	printf("only "); break;
		default:	printf("Never reach herer\n"); break;
	}

	if (SCTP_CHUNKMAP_IS_CLEAR(chunkmap)) {
		printf("NONE ");
		goto out;
	}
	
	if (SCTP_CHUNKMAP_IS_ALL_SET(chunkmap)) {
		printf("ALL ");
		goto out;
	}
	
	flag = 0;
	for (i = 0; i < 256; i++) {
		if (SCTP_CHUNKMAP_IS_SET(chunkmap, i)) {
			flag && printf(",");
			flag = 1;
			print_chunk(i, numeric);
		}
	}

	flag && printf(" ");
out:
	return;
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

	if (einfo->flags & IPT_SCTP_SRC_PORTS) {
		print_ports("spt", einfo->spts[0], einfo->spts[1],
			einfo->invflags & IPT_SCTP_SRC_PORTS,
			numeric);
	}

	if (einfo->flags & IPT_SCTP_DEST_PORTS) {
		print_ports("dpt", einfo->dpts[0], einfo->dpts[1],
			einfo->invflags & IPT_SCTP_DEST_PORTS,
			numeric);
	}

	if (einfo->flags & IPT_SCTP_CHUNK_TYPES) {
		/* FIXME: print_chunks() is used in save() where the printing of '!'
		s taken care of, so we need to do that here as well */
		if (einfo->invflags & IPT_SCTP_CHUNK_TYPES) {
			printf("! ");
		}
		print_chunks(einfo->chunk_match_type, einfo->chunkmap, numeric);
	}
}

/* Saves the union ipt_matchinfo in parsable form to stdout. */
static void
save(const struct ipt_ip *ip, 
     const struct ipt_entry_match *match)
{
	const struct ipt_sctp_info *einfo =
		(const struct ipt_sctp_info *)match->data;

	if (einfo->flags & IPT_SCTP_SRC_PORTS) {
		if (einfo->invflags & IPT_SCTP_SRC_PORTS)
			printf("! ");
		if (einfo->spts[0] != einfo->spts[1])
			printf("--sport %u:%u ", 
			       einfo->spts[0], einfo->spts[1]);
		else
			printf("--sport %u ", einfo->spts[0]);
	}

	if (einfo->flags & IPT_SCTP_DEST_PORTS) {
		if (einfo->invflags & IPT_SCTP_DEST_PORTS)
			printf("! ");
		if (einfo->dpts[0] != einfo->dpts[1])
			printf("--dport %u:%u ",
			       einfo->dpts[0], einfo->dpts[1]);
		else
			printf("--dport %u ", einfo->dpts[0]);
	}

	if (einfo->flags & IPT_SCTP_CHUNK_TYPES) {
		if (einfo->invflags & IPT_SCTP_CHUNK_TYPES)
			printf("! ");
		printf("--chunk-types ");

		print_chunks(einfo->chunk_match_type, einfo->chunkmap, 0);
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

