# Standard part of Makefile for topdir.
TOPLEVEL_INCLUDED=YES

ifndef KERNEL_DIR
KERNEL_DIR=/usr/src/linux
endif
NETFILTER_VERSION:=1.0.0alpha

LIBDIR:=/usr/local/lib
BINDIR:=/usr/local/bin
MANDIR:=/usr/local/man

COPT_FLAGS:=-O
CFLAGS:=$(COPT_FLAGS) -Wall -Wunused -Iinclude/ -I$(KERNEL_DIR)/include -DNETFILTER_VERSION=\"$(NETFILTER_VERSION)\" -g

DEPFILES := $(SHARED_LIBS:%.so=%.d)
SH_CFLAGS:=$(CFLAGS) -fPIC
DEPFILES := $(SHARED_LIBS:%.so=%.d)

EXTRAS+=iptables iptables.o #iptables-save iptables-restore
EXTRA_INSTALLS+=$(DESTDIR)$(BINDIR)/iptables $(DESTDIR)$(MANDIR)/man8/iptables.8 #$(DESTDIR)$(BINDIR)/iptables-save $(DESTDIR)$(BINDIR)/iptables-restore

ifndef IPT_LIBDIR
IPT_LIBDIR:=$(LIBDIR)/iptables
endif

default: all

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

$(DESTDIR)$(MANDIR)/man8/iptables.8: iptables.8
	@[ -d $(DESTDIR)$(MANDIR)/man8 ] || mkdir -p $(DESTDIR)$(MANDIR)/man8
	cp $< $@

EXTRA_DEPENDS+=iptables-standalone.d iptables.d

iptables-standalone.d iptables.d: %.d: %.c
	@-$(CC) -M -MG $(CFLAGS) $< | sed -e 's@^.*\.o:@$*.d $*.o:@' > $@

# $(wildcard) fails wierdly with make v.3.78.1.
include $(shell echo */Makefile)
include Rules.make
