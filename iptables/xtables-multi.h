#ifndef _XTABLES_MULTI_H
#define _XTABLES_MULTI_H 1

extern int iptables_xml_main(int, char **);
#ifdef ENABLE_NFTABLES
extern int xtables_ip4_main(int, char **);
extern int xtables_ip4_save_main(int, char **);
extern int xtables_ip4_restore_main(int, char **);
extern int xtables_ip6_main(int, char **);
extern int xtables_ip6_save_main(int, char **);
extern int xtables_ip6_restore_main(int, char **);
extern int xtables_arp_main(int, char **);
extern int xtables_eb_main(int, char **);
extern int xtables_config_main(int, char **);
extern int xtables_events_main(int, char **);
#endif

#endif /* _XTABLES_MULTI_H */
