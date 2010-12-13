#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([flexisip], [0.2.2], [simon.morlat@linphone.org])
AC_CONFIG_SRCDIR([src/agent.cc])
dnl AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX

if test -f /etc/debian_version ; then
	use_deb=true;
else
	use_rpm=true;
fi

CFLAGS="-g -O2 -pthread"
CXXFLAGS="-g -O2 -pthread"
LDFLAGS="$LDFLAGS -pthread"

if test x$GCC = xyes ; then
	CFLAGS="$CFLAGS -Wall -Werror -fno-strict-aliasing"
	CXXFLAGS="$CXXFLAGS -Wall -Werror -fno-strict-aliasing"
fi

# Checks for libraries.


# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL

PKG_CHECK_MODULES(SOFIA,[sofia-sip-ua >= 1.12.10])
PKG_CHECK_MODULES(MEDIASTREAMER,[mediastreamer >= 2.1.0])
# Checks for library functions.

AM_CONDITIONAL(USE_DEB,test x$use_deb = xtrue)
AM_CONDITIONAL(USE_RPM,test x$use_rpm = xtrue)


# Export path to configuration directory

CONFIG_DIR="\$(sysconfdir)/flexisip"

AC_SUBST(CONFIG_DIR)


AC_CONFIG_FILES(
[
Makefile
scripts/Makefile
scripts/debian/Makefile
scripts/redhat/Makefile
src/Makefile
flexisip.spec
])
AC_OUTPUT
