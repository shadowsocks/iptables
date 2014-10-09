# -*- Makefile -*-

AM_CFLAGS        = ${regular_CFLAGS}
AM_CPPFLAGS      = ${regular_CPPFLAGS} -I${top_builddir}/include -I${top_srcdir}/include ${kinclude_CPPFLAGS} ${libmnl_CFLAGS} ${libnftnl_CFLAGS}
AM_YFLAGS = -d

xtables_multi_SOURCES  = xtables-multi.c iptables-xml.c
xtables_multi_CFLAGS   = ${AM_CFLAGS}
xtables_multi_LDADD    = ../extensions/libext.a
if ENABLE_STATIC
xtables_multi_CFLAGS  += -DALL_INCLUSIVE
endif
if ENABLE_IPV4
xtables_multi_SOURCES += iptables-save.c iptables-restore.c \
                         iptables-standalone.c iptables.c
xtables_multi_CFLAGS  += -DENABLE_IPV4
xtables_multi_LDADD   += ../libiptc/libip4tc.la ../extensions/libext4.a
endif
if ENABLE_IPV6
xtables_multi_SOURCES += ip6tables-save.c ip6tables-restore.c \
                          ip6tables-standalone.c ip6tables.c
xtables_multi_CFLAGS  += -DENABLE_IPV6
xtables_multi_LDADD   += ../libiptc/libip6tc.la ../extensions/libext6.a
endif
xtables_multi_SOURCES += xshared.c
xtables_multi_LDADD   += ../libxtables/libxtables.la -lm

# nftables compatibility layer
if ENABLE_NFTABLES
xtables_compat_multi_SOURCES  = xtables-compat-multi.c iptables-xml.c
xtables_compat_multi_CFLAGS   = ${AM_CFLAGS}
xtables_compat_multi_LDADD    = ../extensions/libext.a
if ENABLE_STATIC
xtables_compat_multi_CFLAGS  += -DALL_INCLUSIVE
endif
xtables_compat_multi_CFLAGS  += -DENABLE_NFTABLES -DENABLE_IPV4 -DENABLE_IPV6
xtables_compat_multi_SOURCES += xtables-config-parser.y xtables-config-syntax.l
xtables_compat_multi_SOURCES += xtables-save.c xtables-restore.c \
				xtables-standalone.c xtables.c nft.c \
				nft-shared.c nft-ipv4.c nft-ipv6.c nft-arp.c \
				xtables-config.c xtables-events.c \
				xtables-arp-standalone.c xtables-arp.c \
				getethertype.c nft-bridge.c \
				xtables-eb-standalone.c xtables-eb.c
xtables_compat_multi_LDADD   += ${libmnl_LIBS} ${libnftnl_LIBS} ../extensions/libext4.a ../extensions/libext6.a
# yacc and lex generate dirty code
xtables_compat_multi-xtables-config-parser.o xtables_compat_multi-xtables-config-syntax.o: AM_CFLAGS += -Wno-missing-prototypes -Wno-missing-declarations -Wno-implicit-function-declaration -Wno-nested-externs -Wno-undef -Wno-redundant-decls
xtables_compat_multi_SOURCES += xshared.c
xtables_compat_multi_LDADD   += ../libxtables/libxtables.la -lm
endif

sbin_PROGRAMS    = xtables-multi
if ENABLE_NFTABLES
sbin_PROGRAMS	+= xtables-compat-multi
endif
man_MANS         = iptables.8 iptables-restore.8 iptables-save.8 \
                   iptables-xml.1 ip6tables.8 ip6tables-restore.8 \
                   ip6tables-save.8 iptables-extensions.8
CLEANFILES       = iptables.8 \
		   xtables-config-parser.c xtables-config-syntax.c

vx_bin_links   = iptables-xml
if ENABLE_IPV4
v4_sbin_links  = iptables iptables-restore iptables-save
endif
if ENABLE_IPV6
v6_sbin_links  = ip6tables ip6tables-restore ip6tables-save
endif
if ENABLE_NFTABLES
x_sbin_links  = iptables-compat iptables-compat-restore iptables-compat-save \
		ip6tables-compat ip6tables-compat-restore ip6tables-compat-save \
		arptables-compat ebtables-compat xtables-config xtables-events
endif

iptables-extensions.8: iptables-extensions.8.tmpl ../extensions/matches.man ../extensions/targets.man
	${AM_VERBOSE_GEN} sed \
		-e '/@MATCH@/ r ../extensions/matches.man' \
		-e '/@TARGET@/ r ../extensions/targets.man' $< >$@;

pkgconfig_DATA = xtables.pc

# Using if..fi avoids an ugly "error (ignored)" message :)
install-exec-hook:
	-if test -z "${DESTDIR}"; then /sbin/ldconfig; fi;
	${INSTALL} -dm0755 "${DESTDIR}${bindir}";
	for i in ${vx_bin_links}; do ${LN_S} -f "${sbindir}/xtables-multi" "${DESTDIR}${bindir}/$$i"; done;
	for i in ${v4_sbin_links}; do ${LN_S} -f xtables-multi "${DESTDIR}${sbindir}/$$i"; done;
	for i in ${v6_sbin_links}; do ${LN_S} -f xtables-multi "${DESTDIR}${sbindir}/$$i"; done;
	for i in ${x_sbin_links}; do ${LN_S} -f xtables-compat-multi "${DESTDIR}${sbindir}/$$i"; done;
