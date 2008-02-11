# -*- Makefile -*-

AUTOMAKE_OPTIONS = foreign subdir-objects

regular_CFLAGS  := @regular_CFLAGS@
kinclude_CFLAGS := @kinclude_CFLAGS@
AM_CFLAGS        = ${regular_CFLAGS} -I${top_builddir}/include -I${top_srcdir}/include ${kinclude_CFLAGS}
SUBDIRS         := extensions
if ENABLE_LIBIPQ
SUBDIRS         += libipq
endif

# libiptc
libiptc_libiptc_a_SOURCES = libiptc/libip4tc.c libiptc/libip6tc.c

# iptables, dynamic
iptables_SOURCES          = iptables-standalone.c iptables.c xtables.c
iptables_LDFLAGS          = -rdynamic
iptables_LDADD            = -ldl -lm libiptc/libiptc.a extensions/libext4.a

iptables_multi_SOURCES    = iptables-multi.c iptables-save.c \
                            iptables-restore.c iptables-xml.c \
                            iptables-standalone.c iptables.c xtables.c
iptables_multi_CFLAGS     = ${AM_CFLAGS} -DIPTABLES_MULTI
iptables_multi_LDFLAGS    = ${iptables_LDFLAGS}
iptables_multi_LDADD      = ${iptables_LDADD}

iptables_restore_SOURCES  = iptables-restore.c iptables.c xtables.c
iptables_restore_LDFLAGS  = ${iptables_LDFLAGS}
iptables_restore_LDADD    = ${iptables_LDADD}

iptables_save_SOURCES     = iptables-save.c iptables.c xtables.c
iptables_save_LDFLAGS     = ${iptables_LDFLAGS}
iptables_save_LDADD       = ${iptables_LDADD}

# iptables-multi, semi-static
iptables_static_SOURCES   = ${iptables_multi_SOURCES}
iptables_static_CFLAGS    = ${iptables_multi_CFLAGS} -DNO_SHARED_LIBS=1
iptables_static_LDADD     = -lm libiptc/libiptc.a extensions/libext4.a

iptables_xml_SOURCES      = iptables-xml.c

# ip6tables, dynamic
ip6tables_SOURCES         = ip6tables-standalone.c ip6tables.c xtables.c
ip6tables_LDFLAGS         = -rdynamic
ip6tables_LDADD           = -ldl -lm libiptc/libiptc.a extensions/libext6.a

ip6tables_multi_SOURCES   = ip6tables-multi.c ip6tables-save.c \
                            ip6tables-restore.c ip6tables-standalone.c \
                            ip6tables.c xtables.c
ip6tables_multi_CFLAGS    = ${AM_CFLAGS} -DIPTABLES_MULTI
ip6tables_multi_LDFLAGS   = ${ip6tables_LDFLAGS}
ip6tables_multi_LDADD     = ${ip6tables_LDADD}

ip6tables_restore_SOURCES = ip6tables-restore.c ip6tables.c xtables.c
ip6tables_restore_LDFLAGS = ${ip6tables_LDFLAGS}
ip6tables_restore_LDADD   = ${ip6tables_LDADD}

ip6tables_save_SOURCES    = ip6tables-save.c ip6tables.c xtables.c
ip6tables_save_LDFLAGS    = ${ip6tables_LDFLAGS}
ip6tables_save_LDADD      = ${ip6tables_LDADD}

# iptables-multi, semi-static
ip6tables_static_SOURCES    = ${ip6tables_multi_SOURCES}
ip6tables_static_CFLAGS     = ${ip6tables_multi_CFLAGS} -DNO_SHARED_LIBS=1
ip6tables_static_LDADD      = -lm libiptc/libiptc.a extensions/libext6.a

noinst_LIBRARIES := libiptc/libiptc.a
bin_PROGRAMS     := iptables-xml
sbin_PROGRAMS    :=
noinst_PROGRAMS  :=
man_MANS         := iptables.8 iptables-restore.8 iptables-save.8 \
                    iptables-xml.8 ip6tables.8 ip6tables-restore.8 \
                    ip6tables-save.8
CLEANFILES       := iptables.8 ip6tables.8
if ENABLE_DEVEL
include_HEADERS  := include/xtables.h include/iptables.h include/ip6tables.h
iptcdir          := ${includedir}/libiptc
iptc_HEADERS     := include/libiptc/libxtc.h \
                    include/libiptc/ipt_kernel_headers.h
endif

if ENABLE_STATIC
sbin_PROGRAMS += iptables-static ip6tables-static
endif
if ENABLE_SHARED
sbin_PROGRAMS += iptables iptables-multi iptables-restore iptables-save \
                 ip6tables ip6tables-multi ip6tables-restore ip6tables-save
endif

iptables.8: ${srcdir}/iptables.8.in extensions/matches4.man extensions/targets4.man
	${AM_VERBOSE_GEN} sed -e '/@MATCH@/ r extensions/matches4.man' -e '/@TARGET@/ r extensions/targets4.man' $< >$@;

ip6tables.8: ${srcdir}/ip6tables.8.in extensions/matches6.man extensions/targets6.man
	${AM_VERBOSE_GEN} sed -e '/@MATCH@/ r extensions/matches6.man' -e '/@TARGET@/ r extensions/targets6.man' $< >$@;

extensions/%:
	${MAKE} ${AM_MAKEFLAGS} -C $(@D) $(@F)

.PHONY: tarball
tarball:
	rm -Rf /tmp/xtables-${PACKAGE_VERSION};
	pushd ${top_srcdir} && git-archive --prefix=xtables-${PACKAGE_VERSION}/ HEAD | tar -C /tmp -x && popd;
	pushd /tmp/xtables-${PACKAGE_VERSION} && ./autogen.sh && popd;
	tar -C /tmp -cjf xtables-${PACKAGE_VERSION}.tar.bz2 --owner=root --group=root xtables-${PACKAGE_VERSION}/;
	rm -Rf /tmp/xtables-${PACKAGE_VERSION};
