#! /usr/bin/make

all: $(SHARED_LIBS) $(EXTRAS)

clean: $(EXTRA_CLEANS)
	rm -f $(SHARED_LIBS) $(EXTRAS) $(SHARED_LIBS:%.so=%_sh.o)

install: all $(EXTRA_INSTALLS)

TAGS:
	@rm -f $@
	find . -name '*.[ch]' | xargs etags -a

dep: $(DEPFILES) $(EXTRA_DEPENDS)
	@echo Dependencies will be generated on next make.
	@rm -f $(DEPFILES) $(EXTRA_DEPENDS) .makefirst

$(SHARED_LIBS:%.so=%.d): %.d: %.c
	@-$(CC) -M -MG $(CFLAGS) $< | \
	    sed -e 's@^.*\.o:@$*.d $*.o:@' > $@

$(SHARED_LIBS): %.so : %_sh.o
	$(LD) -shared -o $@ $<

%_sh.o : %.c
	$(CC) $(SH_CFLAGS) -o $@ -c $<

distrib: nowhitespace distclean delrelease /home/public/netfilter/netfilter-$(NETFILTER_VERSION).tar.bz2 #diff md5sums

delrelease:
	rm -f /home/public/netfilter/netfilter-$(NETFILTER_VERSION).tar.bz2

distclean: clean
	@rm -f TAGS `find . -name '*~' -o -name '*.[do]' -o -name '*.rej'` .makefirst

nowhitespace:
	@if grep -n '[	 ]$$' `find . -name 'Makefile' -o -name '*.[ch]'`; then exit 1; else exit 0; fi

/home/public/netfilter/netfilter-$(NETFILTER_VERSION).tar.bz2:
	cd .. && ln -sfn netfilter netfilter-$(NETFILTER_VERSION) && tar cvf - --exclude install-kernel --exclude transfer --exclude netfilter-$(NETFILTER_VERSION)/bugs --exclude CVS --exclude .depend --exclude netfilter-$(NETFILTER_VERSION)/./NAT/userspace/.depend --exclude netfilter-$(NETFILTER_VERSION)/linux-netfilter netfilter-$(NETFILTER_VERSION)/. | bzip2 -9 > $@ && rm netfilter-$(NETFILTER_VERSION)

diff: /home/public/netfilter/netfilter-$(NETFILTER_VERSION).tar.bz2
	@mkdir /tmp/diffdir
	@cd /tmp/diffdir && tar xfI /home/public/netfilter/netfilter-$(NETFILTER_VERSION).tar.bz2
	@set -e; cd /tmp/diffdir; tar xfI /home/public/netfilter/netfilter-$(OLD_NETFILTER_VERSION).tar.bz2; echo Creating patch-netfilter-$(OLD_NETFILTER_VERSION)-$(NETFILTER_VERSION).bz2; diff -urN netfilter-$(OLD_NETFILTER_VERSION) netfilter-$(NETFILTER_VERSION) | bzip2 -9 > /home/public/netfilter/patch-netfilter-$(OLD_NETFILTER_VERSION)-$(NETFILTER_VERSION).bz2
	@rm -rf /tmp/diffdir

md5sums:
	cd /home/public/netfilter/ && md5sum patch-netfilter-*-$(NETFILTER_VERSION).bz2 netfilter-$(NETFILTER_VERSION).tar.bz2

.makefirst:
	@echo Making dependencies: please wait...
	@touch .makefirst

-include $(DEPFILES) $(EXTRA_DEPENDS)
-include .makefirst
