# Standard part of Makefile for topdir.
TOPLEVEL_INCLUDED=YES

# uncomment this to get a fully statically linked version
# NO_SHARED_LIBS = 1

ifndef KERNEL_DIR
KERNEL_DIR=/usr/src/linux
endif
NETFILTER_VERSION:=1.2.2
OLD_NETFILTER_VERSION:=1.2.1a

# Waiting for inclusions in the kernel tree.
PENDING_PATCHES:=
# These went in previous kernels.
PENDING_PATCHES+=2.4.1.patch tos-fix.patch tcp-MSS.patch 2.4.4.patch ip6tables-export-symbols.patch

LIBDIR:=/usr/local/lib
BINDIR:=/usr/local/sbin
MANDIR:=/usr/local/man
INCDIR:=/usr/local/include

# Need libc6 for this.  FIXME: Should covert to autoconf.
ifeq ($(shell [ -f /usr/include/netinet/ip6.h ] && echo YES), YES)
DO_IPV6=1
endif

COPT_FLAGS:=-O2 -DNDEBUG
CFLAGS:=$(COPT_FLAGS) -Wall -Wunused -I$(KERNEL_DIR)/include -Iinclude/ -DNETFILTER_VERSION=\"$(NETFILTER_VERSION)\" #-g #-pg

ifdef NO_SHARED_LIBS
CFLAGS += -DNO_SHARED_LIBS=1
endif

ifndef NO_SHARED_LIBS
DEPFILES = $(SHARED_LIBS:%.so=%.d)
SH_CFLAGS:=$(CFLAGS) -fPIC
STATIC_LIBS  =
STATIC6_LIBS =
LDFLAGS      = -rdynamic
LDLIBS       = -ldl
else
DEPFILES = $(EXT_OBJS:%.o=%.d)
STATIC_LIBS  = extensions/libext.a
STATIC6_LIBS = extensions/libext6.a
LDFLAGS      =
LDLIBS       =
endif

EXTRAS+=iptables iptables.o
EXTRA_INSTALLS+=$(DESTDIR)$(BINDIR)/iptables $(DESTDIR)$(MANDIR)/man8/iptables.8

# Still experimental.
EXTRAS_EXP+=iptables-save iptables-restore
EXTRA_INSTALLS_EXP+=$(DESTDIR)$(BINDIR)/iptables-save $(DESTDIR)$(BINDIR)/iptables-restore $(DESTDIR)$(MANDIR)/man8/iptables-restore.8 $(DESTDIR)$(MANDIR)/man8/iptables-save.8

ifdef DO_IPV6
EXTRAS+=ip6tables ip6tables.o
EXTRA_INSTALLS+=$(DESTDIR)$(BINDIR)/ip6tables
EXTRAS_EXP+=ip6tables-save ip6tables-restore
EXTRA_INSTALLS_EXP+=$(DESTDIR)$(BINDIR)/ip6tables-save $(DESTDIR)$(BINDIR)/ip6tables-restore # $(DESTDIR)$(MANDIR)/man8/iptables-restore.8 $(DESTDIR)$(MANDIR)/man8/iptables-save.8 $(DESTDIR)$(MANDIR)/man8/ip6tables-save.8 $(DESTDIR)$(MANDIR)/man8/ip6tables-restore.8
endif

# Sparc64 hack
ifeq ($(shell uname -m),sparc64)
# The kernel is 64-bit, even though userspace is 32.
CFLAGS+=-DIPT_MIN_ALIGN=8 -DKERNEL_64_USERSPACE_32
endif

# HPPA hack
ifeq ($(shell uname -m),parisc64)
# The kernel is 64-bit, even though userspace is 32.
CFLAGS+=-DIPT_MIN_ALIGN=8 -DKERNEL_64_USERSPACE_32
endif

ifndef IPT_LIBDIR
IPT_LIBDIR:=$(LIBDIR)/iptables
endif

.PHONY: default
default: print-extensions all

.PHONY: print-extensions
print-extensions:
	@[ -n "$(OPTIONALS)" ] && echo Extensions found: $(OPTIONALS)

.PHONY: pending-patches
pending-patches:
	@cd patch-o-matic && KERNEL_DIR=$(KERNEL_DIR) ./runme $(PENDING_PATCHES)

iptables.o: iptables.c
	$(CC) $(CFLAGS) -DIPT_LIB_DIR=\"$(IPT_LIBDIR)\" -c -o $@ $<

iptables: iptables-standalone.c iptables.o $(STATIC_LIBS) libiptc/libiptc.a
	$(CC) $(CFLAGS) -DIPT_LIB_DIR=\"$(IPT_LIBDIR)\" $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(DESTDIR)$(BINDIR)/iptables: iptables
	@[ -d $(DESTDIR)$(BINDIR) ] || mkdir -p $(DESTDIR)$(BINDIR)
	cp $< $@

iptables-save: iptables-save.c iptables.o $(STATIC_LIBS) libiptc/libiptc.a
	$(CC) $(CFLAGS) -DIPT_LIB_DIR=\"$(IPT_LIBDIR)\" $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(DESTDIR)$(BINDIR)/iptables-save: iptables-save
	@[ -d $(DESTDIR)$(BINDIR) ] || mkdir -p $(DESTDIR)$(BINDIR)
	cp $< $@

iptables-restore: iptables-restore.c iptables.o $(STATIC_LIBS) libiptc/libiptc.a
	$(CC) $(CFLAGS) -DIPT_LIB_DIR=\"$(IPT_LIBDIR)\" $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(DESTDIR)$(BINDIR)/iptables-restore: iptables-restore
	@[ -d $(DESTDIR)$(BINDIR) ] || mkdir -p $(DESTDIR)$(BINDIR)
	cp $< $@

ip6tables.o: ip6tables.c
	$(CC) $(CFLAGS) -DIP6T_LIB_DIR=\"$(IPT_LIBDIR)\" -c -o $@ $<

ip6tables: ip6tables-standalone.c ip6tables.o $(STATIC6_LIBS) libiptc/libiptc.a
	$(CC) $(CFLAGS) -DIP6T_LIB_DIR=\"$(IPT_LIBDIR)\" -rdynamic -o $@ $^ $(LDLIBS)

$(DESTDIR)$(BINDIR)/ip6tables: ip6tables
	@[ -d $(DESTDIR)$(BINDIR) ] || mkdir -p $(DESTDIR)$(BINDIR)
	cp $< $@

ip6tables-save: ip6tables-save.c ip6tables.o $(STATIC6_LIBS) libiptc/libiptc.a
	$(CC) $(CFLAGS) -DIP6T_LIB_DIR=\"$(IPT_LIBDIR)\" -rdynamic -o $@ $^ $(LDLIBS)

$(DESTDIR)$(BINDIR)/ip6tables-save: ip6tables-save
	@[ -d $(DESTDIR)$(BINDIR) ] || mkdir -p $(DESTDIR)$(BINDIR)
	cp $< $@

ip6tables-restore: ip6tables-restore.c ip6tables.o $(STATIC6_LIBS) libiptc/libiptc.a
	$(CC) $(CFLAGS) -DIP6T_LIB_DIR=\"$(IPT_LIBDIR)\" -rdynamic -o $@ $^ $(LDLIBS)

$(DESTDIR)$(BINDIR)/ip6tables-restore: ip6tables-restore
	@[ -d $(DESTDIR)$(BINDIR) ] || mkdir -p $(DESTDIR)$(BINDIR)
	cp $< $@

$(DESTDIR)$(MANDIR)/man8/%.8: %.8
	@[ -d $(DESTDIR)$(MANDIR)/man8 ] || mkdir -p $(DESTDIR)$(MANDIR)/man8
	cp $< $@

EXTRA_DEPENDS+=iptables-standalone.d iptables.d

iptables-standalone.d iptables.d: %.d: %.c
	@-$(CC) -M -MG $(CFLAGS) $< | sed -e 's@^.*\.o:@$*.d $*.o:@' > $@


# Development Targets
.PHONY: install-devel-man3
install-devel-man3: $(DEVEL_MAN3)
	@[ -d $(DESTDIR)$(MANDIR)/man3 ] || mkdir -p $(DESTDIR)$(MANDIR)/man3
	@cp -v $(DEVEL_MAN3) $(DESTDIR)$(MANDIR)/man3

.PHONY: install-devel-headers
install-devel-headers: $(DEVEL_HEADERS)
	@[ -d $(DESTDIR)$(INCDIR) ] || mkdir -p $(DESTDIR)$(INCDIR)
	@cp -v $(DEVEL_HEADERS) $(DESTDIR)$(INCDIR)

.PHONY: install-devel-libs
install-devel-libs: $(DEVEL_LIBS)
	@[ -d $(DESTDIR)$(LIBDIR) ] || mkdir -p $(DESTDIR)$(LIBDIR)
	@cp -v $(DEVEL_LIBS) $(DESTDIR)$(LIBDIR)

.PHONY: install-devel
install-devel: all install-devel-man3 install-devel-headers install-devel-libs

.PHONY: distclean
distclean: clean
	@rm -f TAGS `find . -name '*~' -o -name '.*~'` `find . -name '*.rej'` `find . -name '*.d'` .makefirst

.PHONY: patch-o-matic
patch-o-matic/ patch-o-matic:
	@cd $@ && KERNEL_DIR=$(KERNEL_DIR) ./runme

# Rusty's distro magic.
.PHONY: distrib
distrib: check distclean delrelease /home/public/netfilter/iptables-$(NETFILTER_VERSION).tar.bz2 diff md5sums # nowhitespace

# Makefile must not define:
# -g -pg
# And must define -NDEBUG
.PHONY: check
check:
	@if echo $(CFLAGS) | egrep -e '-g|-pg' >/dev/null; then echo Remove debugging flags; exit 1; else exit 0; fi
	@if echo $(CFLAGS) | egrep -e NDEBUG >/dev/null; then exit 0; else echo Define -DNDEBUG; exit 1; fi

.PHONY: nowhitespace
nowhitespace:
	@if grep -n '[ 	]$$' `find . -name 'Makefile' -o -name '*.[ch]'`; then exit 1; else exit 0; fi

.PHONY: delrelease
delrelease:
	rm -f /home/public/netfilter/iptables-$(NETFILTER_VERSION).tar.bz2

/home/public/netfilter/iptables-$(NETFILTER_VERSION).tar.bz2:
	cd .. && ln -sf userspace iptables-$(NETFILTER_VERSION) && tar cvf - --exclude CVS iptables-$(NETFILTER_VERSION)/. | bzip2 -9 > $@ && rm iptables-$(NETFILTER_VERSION)

.PHONY: diff
diff: /home/public/netfilter/iptables-$(NETFILTER_VERSION).tar.bz2
	@mkdir /tmp/diffdir
	@cd /tmp/diffdir && tar -x --bzip2 -f /home/public/netfilter/iptables-$(NETFILTER_VERSION).tar.bz2
	@set -e; cd /tmp/diffdir; tar -x --bzip2 -f /home/public/netfilter/iptables-$(OLD_NETFILTER_VERSION).tar.bz2; echo Creating patch-iptables-$(OLD_NETFILTER_VERSION)-$(NETFILTER_VERSION).bz2; diff -urN iptables-$(OLD_NETFILTER_VERSION) iptables-$(NETFILTER_VERSION) | bzip2 -9 > /home/public/netfilter/patch-iptables-$(OLD_NETFILTER_VERSION)-$(NETFILTER_VERSION).bz2
	@rm -rf /tmp/diffdir

.PHONY: md5sums
md5sums:
	cd /home/public/netfilter/ && md5sum patch-iptables-*-$(NETFILTER_VERSION).bz2 iptables-$(NETFILTER_VERSION).tar.bz2

# $(wildcard) fails wierdly with make v.3.78.1.
include $(shell echo */Makefile)
include Rules.make
