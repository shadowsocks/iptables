#! /usr/bin/make

PF_EXT_SLIB:=tcp udp icmp mac limit standard REJECT LOG unclean state multiport tos TOS mark MARK owner SNAT DNAT MASQUERADE REDIRECT MIRROR
PF6_EXT_SLIB:=tcp udp icmp standard MARK mark

# The following may not be present, but compile them anyway.
PF_EXT_SLIB+=FTOS TCPMSS TTL ULOG ah esp iplimit tcpmss ttl

# Optionals
PF_EXT_SLIB_OPTS:=$(foreach T,$(wildcard extensions/.*-test),$(shell KERNEL_DIR=$(KERNEL_DIR) $(T)))
PF6_EXT_SLIB_OPTS:=$(foreach T,$(wildcard extensions/.*-test6),$(shell KERNEL_DIR=$(KERNEL_DIR) $(T)))

PF_EXT_SLIB+=$(PF_EXT_SLIB_OPTS)
PF6_EXT_SLIB+=$(PF6_EXT_SLIB_OPTS)

OPTIONALS+=$(patsubst %,IPv4:%,$(PF_EXT_SLIB_OPTS))
OPTIONALS+=$(patsubst %,IPv6:%,$(PF6_EXT_SLIB_OPTS))

SHARED_LIBS+=$(foreach T,$(PF_EXT_SLIB),extensions/libipt_$(T).so)
SHARED_LIBS+=$(foreach T,$(PF6_EXT_SLIB),extensions/libip6t_$(T).so)
EXTRA_INSTALLS+=$(foreach T, $(PF_EXT_SLIB), $(DESTDIR)$(LIBDIR)/iptables/libipt_$(T).so)
EXTRA_INSTALLS+=$(foreach T, $(PF6_EXT_SLIB), $(DESTDIR)$(LIBDIR)/iptables/libip6t_$(T).so)

ifndef TOPLEVEL_INCLUDED
local:
	cd .. && $(MAKE) $(SHARED_LIBS)
endif

$(DESTDIR)$(LIBDIR)/iptables/libipt_%.so: extensions/libipt_%.so
	@[ -d $(DESTDIR)$(LIBDIR)/iptables ] || mkdir -p $(DESTDIR)$(LIBDIR)/iptables
	cp $< $@

$(DESTDIR)$(LIBDIR)/iptables/libip6t_%.so: extensions/libip6t_%.so
	@[ -d $(DESTDIR)$(LIBDIR)/iptables ] || mkdir -p $(DESTDIR)$(LIBDIR)/iptables
	cp $< $@
