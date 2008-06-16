define([_XTABLES_VERSION_MAJOR], 1)
define([_XTABLES_VERSION_MINOR], 4)
define([_XTABLES_VERSION_PATCH], 1)
define([_XTABLES_VERSION_EXTRA], .1)

define([_XTABLES_VERSION],_XTABLES_VERSION_MAJOR._XTABLES_VERSION_MINOR._XTABLES_VERSION_PATCH[]_XTABLES_VERSION_EXTRA)

AC_INIT([iptables], _XTABLES_VERSION)
AC_CONFIG_HEADERS([config.h])
AC_PROG_INSTALL
AM_INIT_AUTOMAKE
AC_PROG_CC
AM_PROG_CC_C_O
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_ARG_WITH([kernel],
	AS_HELP_STRING([--with-kernel=PATH],
	[Path to kernel source/build directory]),
	[kbuilddir="$withval"; ksourcedir="$withval";])
AC_ARG_WITH([kbuild],
	AS_HELP_STRING([--with-kbuild=PATH],
	[Path to kernel build directory [[/lib/modules/CURRENT/build]]]),
	[kbuilddir="$withval"])
AC_ARG_WITH([ksource],
	AS_HELP_STRING([--with-ksource=PATH],
	[Path to kernel source directory [[/lib/modules/CURRENT/source]]]),
	[ksourcedir="$withval"])
AC_ARG_WITH([xtlibdir],
	AS_HELP_STRING([--with-xtlibdir=PATH],
	[Path where to install Xtables extensions [[LIBEXECDIR/xtables]]]),
	[xtlibdir="$withval"],
	[xtlibdir="${libexecdir}/xtables"])
AC_ARG_ENABLE([devel],
	AS_HELP_STRING([--enable-devel],
	[Install Xtables development headers]),
	[enable_devel="$enableval"], [enable_devel="yes"])
AC_ARG_ENABLE([libipq],
	AS_HELP_STRING([--enable-libipq], [Build and install libipq]))

AC_CHECK_HEADER([netinet/ip6.h], [], [AC_MSG_ERROR(but we need that for IPv6)])
AC_CHECK_HEADER([linux/dccp.h])

blacklist_modules="";
if test "$ac_cv_header_linux_dccp_h" != "yes"; then
	blacklist_modules="$blacklist_modules dccp";
fi;
AC_SUBST([blacklist_modules])

AM_CONDITIONAL([ENABLE_STATIC], [test "$enable_static" == "yes"])
AM_CONDITIONAL([ENABLE_SHARED], [test "$enable_shared" == "yes"])
AM_CONDITIONAL([ENABLE_DEVEL], [test "$enable_devel" == "yes"])
AM_CONDITIONAL([ENABLE_LIBIPQ], [test "$enable_libipq" == "yes"])

regular_CFLAGS="-D_LARGEFILE_SOURCE=1 -D_LARGE_FILES -D_FILE_OFFSET_BITS=64 \
	-D_REENTRANT -Wall -Waggregate-return -Wmissing-declarations \
	-Wmissing-prototypes -Wredundant-decls -Wshadow -Wstrict-prototypes \
	-Winline -pipe \
	-DXTABLES_LIBDIR=\\\"\${xtlibdir}\\\" -DXTABLES_INTERNAL";
kinclude_CFLAGS="";
if [[ -n "$kbuilddir" ]]; then
	kinclude_CFLAGS="$kinclude_CFLAGS -I $kbuilddir/include";
fi;
if [[ -n "$ksourcedir" ]]; then
	kinclude_CFLAGS="$kinclude_CFLAGS -I $ksourcedir/include";
fi;

AC_SUBST([regular_CFLAGS])
AC_SUBST([kinclude_CFLAGS])
AC_SUBST([kbuilddir])
AC_SUBST([ksourcedir])
AC_SUBST([xtlibdir])

XTABLES_VERSION_MAJOR=_XTABLES_VERSION_MAJOR
XTABLES_VERSION_MINOR=_XTABLES_VERSION_MINOR
XTABLES_VERSION_PATCH=_XTABLES_VERSION_PATCH
XTABLES_VERSION_EXTRA=_XTABLES_VERSION_EXTRA
AC_SUBST([XTABLES_VERSION_MAJOR])
AC_SUBST([XTABLES_VERSION_MINOR])
AC_SUBST([XTABLES_VERSION_PATCH])
AC_SUBST([XTABLES_VERSION_EXTRA])

AC_OUTPUT([Makefile extensions/GNUmakefile libipq/Makefile include/xtables.h])
