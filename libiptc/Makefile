#! /usr/bin/make

EXTRAS+=libiptc/libiptc.a

ifndef TOPLEVEL_INCLUDED
local:
	cd .. && $(MAKE) $(KERN_TARGETS) $(SHARED_LIBS) $(EXTRAS)

else
EXTRA_DEPENDS+=libiptc/libiptc.d

libiptc/libiptc.a: libiptc/libiptc.a(libiptc/libip4tc.o libiptc/libip6tc.o)
#libiptc/libiptc.a: libiptc/libiptc.a(libiptc/libip4tc.o)

libiptc/libiptc.d: %.d: %.c
	@-$(CC) -M -MG $(CFLAGS) $< | sed -e 's@^.*\.o:@$*.d $*.a($*.o):@' > $@
endif
