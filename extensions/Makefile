#! /usr/bin/make

PF_EXT_SLIB:=tcp udp icmp mac limit standard REJECT LOG unclean state multiport tos TOS mark MARK owner SNAT DNAT MASQUERADE REDIRECT
SHARED_LIBS+=$(foreach T,$(PF_EXT_SLIB),extensions/libipt_$(T).so)
EXTRA_INSTALLS+=$(foreach T, $(PF_EXT_SLIB), $(DESTDIR)$(LIBDIR)/iptables/libipt_$(T).so)

ifndef TOPLEVEL_INCLUDED
local:
	cd .. && $(MAKE) $(SHARED_LIBS)
endif

$(DESTDIR)$(LIBDIR)/iptables/libipt_%.so: extensions/libipt_%.so
	@[ -d $(DESTDIR)$(LIBDIR)/iptables ] || mkdir -p $(DESTDIR)$(LIBDIR)/iptables
	cp $< $@
