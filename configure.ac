#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([flexisip], [0.0.1], [simon.morlat@linphone.org])
AC_CONFIG_SRCDIR([src/agent.cc])
dnl AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX

CFLAGS="-ggdb"
CXXFLAGS="-ggdb"

if test x$GCC = xyes ; then
	CFLAGS="$CFLAGS -Wall -Werror"
	CXXFLAGS="$CXXFLAGS -Wall -Werror"
fi

# Checks for libraries.

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL

PKG_CHECK_MODULES(SOFIA,[sofia-sip-ua >= 1.12.10])
PKG_CHECK_MODULES(MEDIASTREAMER,[mediastreamer >= 2.1.0])
# Checks for library functions.

AC_CONFIG_FILES(
[
Makefile
scripts/Makefile
scripts/debian/Makefile
src/Makefile
])
AC_OUTPUT
