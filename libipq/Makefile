#! /usr/bin/make

EXTRAS+=libipq/libipq.a
#CFLAGS+=-DDEBUG_LIBIPTQ

ifndef TOPLEVEL_INCLUDED
local:
	cd .. && $(MAKE) $(SHARED_LIBS) $(EXTRAS)
else
libipq/libipq.a: libipq/libipq.a(libipq/libipq.o)
endif
