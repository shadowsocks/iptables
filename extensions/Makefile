#! /usr/bin/make

# WARNING:
# only add extensions here that are either present in the kernel, or whose
# header files are present in the include/linux directory of this iptables
# package (HW)
#
PF_EXT_SLIB:=ah connlimit conntrack dscp ecn esp helper icmp iprange length limit mac mark multiport owner physdev pkttype realm rpc standard state tcp tcpmss tos ttl udp unclean CLASSIFY CONNMARK DNAT DSCP ECN LOG MARK MASQUERADE MIRROR NETMAP REDIRECT REJECT SAME SNAT TARPIT TCPMSS TOS TTL ULOG
PF6_EXT_SLIB:=eui64 hl icmpv6 length limit mac mark multiport owner standard tcp udp HL LOG MARK

# Optionals
PF_EXT_SLIB_OPTS:=$(foreach T,$(wildcard extensions/.*-test),$(shell KERNEL_DIR=$(KERNEL_DIR) $(T)))
PF6_EXT_SLIB_OPTS:=$(foreach T,$(wildcard extensions/.*-test6),$(shell KERNEL_DIR=$(KERNEL_DIR) $(T)))

PF_EXT_SLIB+=$(PF_EXT_SLIB_OPTS)
PF6_EXT_SLIB+=$(PF6_EXT_SLIB_OPTS)

OPTIONALS+=$(patsubst %,IPv4:%,$(PF_EXT_SLIB_OPTS))
OPTIONALS+=$(patsubst %,IPv6:%,$(PF6_EXT_SLIB_OPTS))

ifndef NO_SHARED_LIBS
SHARED_LIBS+=$(foreach T,$(PF_EXT_SLIB),extensions/libipt_$(T).so)
EXTRA_INSTALLS+=$(foreach T, $(PF_EXT_SLIB), $(DESTDIR)$(LIBDIR)/iptables/libipt_$(T).so)

ifeq ($(DO_IPV6), 1)
SHARED_LIBS+=$(foreach T,$(PF6_EXT_SLIB),extensions/libip6t_$(T).so)
EXTRA_INSTALLS+=$(foreach T, $(PF6_EXT_SLIB), $(DESTDIR)$(LIBDIR)/iptables/libip6t_$(T).so)
endif
else 	# NO_SHARED_LIBS
EXT_OBJS+=$(foreach T,$(PF_EXT_SLIB),extensions/libipt_$(T).o)
EXT_FUNC+=$(foreach T,$(PF_EXT_SLIB),ipt_$(T))
EXT_OBJS+= extensions/initext.o
ifeq ($(DO_IPV6), 1)
EXT6_OBJS+=$(foreach T,$(PF6_EXT_SLIB),extensions/libip6t_$(T).o)
EXT6_FUNC+=$(foreach T,$(PF6_EXT_SLIB),ip6t_$(T))
EXT6_OBJS+= extensions/initext6.o
endif	# DO_IPV6
endif	# NO_SHARED_LIBS

ifndef TOPLEVEL_INCLUDED
local:
	cd .. && $(MAKE) $(SHARED_LIBS)
endif

ifdef NO_SHARED_LIBS
extensions/libext.a: $(EXT_OBJS)
	rm -f $@; ar crv $@ $(EXT_OBJS)

extensions/libext6.a: $(EXT6_OBJS)
	rm -f $@; ar crv $@ $(EXT6_OBJS)

extensions/initext.o: extensions/initext.c
extensions/initext6.o: extensions/initext6.c

extensions/initext.c: extensions/Makefile
	echo "" > $@
	for i in $(EXT_FUNC); do \
		echo "extern void $${i}_init(void);" >> $@; \
	done
	echo "void init_extensions(void) {" >> $@
	for i in $(EXT_FUNC); do \
		echo "	$${i}_init();" >> $@; \
	done
	echo "}" >> $@

extensions/initext6.c: extensions/Makefile
	echo "" > $@
	for i in $(EXT6_FUNC); do \
		echo "extern void $${i}_init(void);" >> $@; \
	done
	echo "void init_extensions(void) {" >> $@
	for i in $(EXT6_FUNC); do \
		echo "	$${i}_init();" >> $@; \
	done
	echo "}" >> $@

extensions/lib%.o: extensions/lib%.c
	$(CC) $(CFLAGS) -D_INIT=$*_init -c -o $@ $<

endif
 
$(DESTDIR)$(LIBDIR)/iptables/libipt_%.so: extensions/libipt_%.so
	@[ -d $(DESTDIR)$(LIBDIR)/iptables ] || mkdir -p $(DESTDIR)$(LIBDIR)/iptables
	cp $< $@

$(DESTDIR)$(LIBDIR)/iptables/libip6t_%.so: extensions/libip6t_%.so
	@[ -d $(DESTDIR)$(LIBDIR)/iptables ] || mkdir -p $(DESTDIR)$(LIBDIR)/iptables
	cp $< $@
