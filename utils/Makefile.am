# -*- Makefile -*-

AM_CFLAGS = ${regular_CFLAGS} -I${top_builddir}/include -I${top_srcdir}/include
AM_CPPFLAGS = ${regular_CPPFLAGS}

sbin_PROGRAMS = nfnl_osf
pkgdata_DATA = pf.os

nfnl_osf_LDADD = -lnfnetlink
