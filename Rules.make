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
	rm -f $(DEPFILES) $(EXTRA_DEPENDS) .makefirst

$(SHARED_LIBS:%.so=%.d): %.d: %.c
	@-$(CC) -M -MG $(CFLAGS) $< | \
	    sed -e 's@^.*\.o:@$*.d $*_sh.o:@' > $@

$(SHARED_LIBS): %.so : %_sh.o
	$(LD) -shared -o $@ $<

%_sh.o : %.c
	$(CC) $(SH_CFLAGS) -o $@ -c $<

.makefirst:
	@echo Making dependencies: please wait...
	@touch .makefirst

# This is useful for when dependencies completely screwed
%.h::
	@echo Something wrong... deleting dependencies.
	-rm -f $(DEPFILES) $(EXTRA_DEPENDS) .makefirst
	@exit 1

-include $(DEPFILES) $(EXTRA_DEPENDS)
-include .makefirst
