# Standard part of Makefile for topdir.
TOPLEVEL_INCLUDED=YES

ifndef KERNEL_DIR
KERNEL_DIR=/usr/src/linux
endif
NETFILTER_VERSION:=1.1.2
OLD_NETFILTER_VERSION:=1.1.1

LIBDIR:=/usr/local/lib
BINDIR:=/usr/local/bin
MANDIR:=/usr/local/man

COPT_FLAGS:=-O2 -DNDEBUG
CFLAGS:=$(COPT_FLAGS) -Wall -Wunused -Iinclude/ -I$(KERNEL_DIR)/include -DNETFILTER_VERSION=\"$(NETFILTER_VERSION)\" #-g #-pg

DEPFILES = $(SHARED_LIBS:%.so=%.d)
SH_CFLAGS:=$(CFLAGS) -fPIC

EXTRAS+=iptables iptables.o ip6tables ip6tables.o #iptables-save iptables-restore
EXTRA_INSTALLS+=$(DESTDIR)$(BINDIR)/iptables $(DESTDIR)$(BINDIR)/ip6tables $(DESTDIR)$(MANDIR)/man8/iptables.8 #$(DESTDIR)$(BINDIR)/iptables-save $(DESTDIR)$(BINDIR)/iptables-restore

# Sparc64 hack
ifeq ($(shell uname -m),sparc64)
# The kernel is 64-bit, even though userspace is 32.
CFLAGS+=-DIPT_MIN_MATCH_ALIGN=8 -DIPT_MIN_ENTRY_ALIGN=8
endif

ifndef IPT_LIBDIR
IPT_LIBDIR:=$(LIBDIR)/iptables
endif

default: print-extensions all

print-extensions:
	@echo Extensions found: $(OPTIONALS)

iptables.o: iptables.c
	$(CC) $(CFLAGS) -DIPT_LIB_DIR=\"$(IPT_LIBDIR)\" -c -o $@ $<

iptables: iptables-standalone.c iptables.o libiptc/libiptc.a
	$(CC) $(CFLAGS) -DIPT_LIB_DIR=\"$(IPT_LIBDIR)\" -rdynamic -o $@ $^ -ldl

$(DESTDIR)$(BINDIR)/iptables: iptables
	@[ -d $(DESTDIR)$(BINDIR) ] || mkdir -p $(DESTDIR)$(BINDIR)
	cp $< $@

iptables-save: iptables-save.c iptables.o libiptc/libiptc.a
	$(CC) $(CFLAGS) -DIPT_LIB_DIR=\"$(IPT_LIBDIR)\" -rdynamic -o $@ $^ -ldl

$(DESTDIR)$(BINDIR)/iptables-save: iptables-save
	@[ -d $(DESTDIR)$(BINDIR) ] || mkdir -p $(DESTDIR)$(BINDIR)
	cp $< $@

iptables-restore: iptables-restore.c iptables.o libiptc/libiptc.a
	$(CC) $(CFLAGS) -DIPT_LIB_DIR=\"$(IPT_LIBDIR)\" -rdynamic -o $@ $^ -ldl

$(DESTDIR)$(BINDIR)/iptables-restore: iptables-restore
	@[ -d $(DESTDIR)$(BINDIR) ] || mkdir -p $(DESTDIR)$(BINDIR)
	cp $< $@

ip6tables.o: ip6tables.c
	$(CC) $(CFLAGS) -DIPT_LIB_DIR=\"$(IPT_LIBDIR)\" -c -o $@ $<

ip6tables: ip6tables-standalone.c ip6tables.o libiptc/libiptc.a
	$(CC) $(CFLAGS) -DIPT_LIB_DIR=\"$(IPT_LIBDIR)\" -rdynamic -o $@ $^ -ldl

$(DESTDIR)$(BINDIR)/ip6tables: ip6tables
	@[ -d $(DESTDIR)$(BINDIR) ] || mkdir -p $(DESTDIR)$(BINDIR)
	cp $< $@

ip6tables-save: ip6tables-save.c ip6tables.o libiptc/libiptc.a
	$(CC) $(CFLAGS) -DIPT_LIB_DIR=\"$(IPT_LIBDIR)\" -rdynamic -o $@ $^ -ldl

$(DESTDIR)$(BINDIR)/ip6tables-save: ip6tables-save
	@[ -d $(DESTDIR)$(BINDIR) ] || mkdir -p $(DESTDIR)$(BINDIR)
	cp $< $@

ip6tables-restore: ip6tables-restore.c ip6tables.o libiptc/libiptc.a
	$(CC) $(CFLAGS) -DIPT_LIB_DIR=\"$(IPT_LIBDIR)\" -rdynamic -o $@ $^ -ldl

$(DESTDIR)$(BINDIR)/ip6tables-restore: ip6tables-restore
	@[ -d $(DESTDIR)$(BINDIR) ] || mkdir -p $(DESTDIR)$(BINDIR)
	cp $< $@

$(DESTDIR)$(MANDIR)/man8/iptables.8: iptables.8
	@[ -d $(DESTDIR)$(MANDIR)/man8 ] || mkdir -p $(DESTDIR)$(MANDIR)/man8
	cp $< $@

EXTRA_DEPENDS+=iptables-standalone.d iptables.d

iptables-standalone.d iptables.d: %.d: %.c
	@-$(CC) -M -MG $(CFLAGS) $< | sed -e 's@^.*\.o:@$*.d $*.o:@' > $@

distclean: clean
	@rm -f TAGS `find . -name '*~'` `find . -name '*.rej'` `find . -name '*.d'` .makefirst

.PHONY: patch-o-matic
patch-o-matic:
	@cd $@ && KERNEL_DIR=$(KERNEL_DIR) ./runme

# Rusty's distro magic.
distrib: check nowhitespace distclean delrelease /home/public/netfilter/iptables-$(NETFILTER_VERSION).tar.bz2 diff md5sums

# Makefile must not define:
# -g -pg
# And must define -NDEBUG
check:
	@if echo $(CFLAGS) | egrep -e '-g|-pg' >/dev/null; then echo Remove debugging flags; exit 1; else exit 0; fi
	@if echo $(CFLAGS) | egrep -e NDEBUG >/dev/null; then exit 0; else echo Define -DNDEBUG; exit 1; fi

nowhitespace:
	@if grep -n ' 	$$' `find . -name 'Makefile' -o -name '*.[ch]'`; then exit 1; else exit 0; fi

delrelease:
	rm -f /home/public/netfilter/iptables-$(NETFILTER_VERSION).tar.bz2

/home/public/netfilter/iptables-$(NETFILTER_VERSION).tar.bz2:
	cd .. && ln -sf userspace iptables-$(NETFILTER_VERSION) && tar cvf - --exclude CVS iptables-$(NETFILTER_VERSION)/. | bzip2 -9 > $@ && rm iptables-$(NETFILTER_VERSION)

diff: /home/public/netfilter/iptables-$(NETFILTER_VERSION).tar.bz2
	@mkdir /tmp/diffdir
	@cd /tmp/diffdir && tar xfI /home/public/netfilter/iptables-$(NETFILTER_VERSION).tar.bz2
	@set -e; cd /tmp/diffdir; tar xfI /home/public/netfilter/iptables-$(OLD_NETFILTER_VERSION).tar.bz2; echo Creating patch-iptables-$(OLD_NETFILTER_VERSION)-$(NETFILTER_VERSION).bz2; diff -urN iptables-$(OLD_NETFILTER_VERSION) iptables-$(NETFILTER_VERSION) | bzip2 -9 > /home/public/netfilter/patch-iptables-$(OLD_NETFILTER_VERSION)-$(NETFILTER_VERSION).bz2
	@rm -rf /tmp/diffdir

md5sums:
	cd /home/public/netfilter/ && md5sum patch-iptables-*-$(NETFILTER_VERSION).bz2 iptables-$(NETFILTER_VERSION).tar.bz2

# $(wildcard) fails wierdly with make v.3.78.1.
include $(shell echo */Makefile)
include Rules.make
