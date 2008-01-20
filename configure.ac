
AC_INIT([iptables], [1.4.0])
AC_CONFIG_HEADERS([config.h])
AC_PROG_INSTALL
AM_INIT_AUTOMAKE
AC_PROG_CC
AM_PROG_CC_C_O
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

kbuilddir="/lib/modules/$(uname -r)/build";
ksourcedir="/lib/modules/$(uname -r)/source";
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
AC_ARG_WITH([iptdir],
	AS_HELP_STRING([--with-iptdir=PATH],
	[Path to iptables modules [[LIBEXECDIR/iptables]]]),
	[iptdir="$withval"],
	[iptdir="${libexecdir}/iptables"])
AC_ARG_ENABLE([devel],
	AS_HELP_STRING([--enable-devel],
	[Build and install development files (libipq, libipq-devel, iptables-devel)]))

AC_CHECK_HEADER([netinet/ip6.h], [], [AC_MSG_ERROR(but we need that for IPv6)])
AM_CONDITIONAL([ENABLE_STATIC], [test "$enable_static" == "yes"])
AM_CONDITIONAL([ENABLE_SHARED], [test "$enable_shared" == "yes"])
AM_CONDITIONAL([ENABLE_DEVEL], [test "$enable_devel" == "yes"])

regular_CFLAGS="-D_LARGEFILE_SOURCE=1 -D_LARGE_FILES -D_FILE_OFFSET_BITS=64 \
	-D_REENTRANT -Wall -Waggregate-return -Wmissing-declarations \
	-Wmissing-prototypes -Wredundant-decls -Wshadow -Wstrict-prototypes \
	-Winline -pipe -DIPTABLES_VERSION=\\\"$PACKAGE_VERSION\\\" \
	-DIPT_LIB_DIR=\\\"\${iptdir}\\\" \
	-I\"$kbuilddir/include\" -I\"$ksourcedir/include\""

# Remove workarounds soon
regular_CFLAGS="$regular_CFLAGS -Wno-aggregate-return \
	-Wno-missing-declarations -Wno-missing-prototypes \
	-Wno-redundant-decls -Wno-shadow -Wno-strict-prototypes -Wno-inline"

AC_SUBST([regular_CFLAGS])
AC_SUBST([kbuilddir])
AC_SUBST([ksourcedir])
AC_SUBST([iptdir])
AC_OUTPUT([Makefile extensions/GNUmakefile libipq/Makefile])
