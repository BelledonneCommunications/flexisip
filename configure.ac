#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([flexisip], [0.3.2], [simon.morlat@linphone.org])
AC_CONFIG_SRCDIR([src/agent.cc])
AC_CONFIG_HEADERS([flexisip-config.h])

AM_INIT_AUTOMAKE
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],)

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

AC_ARG_ENABLE(strict,
	AC_HELP_STRING([--enable-strict],
		       [Build with stricter options (gcc only) @<:@yes@:>@]),[
	strictness="${enableval}"],[strictness=yes]
)


if test x$GCC$strictness = xyesyes ; then
	CFLAGS="$CFLAGS -Wall -Werror -fno-strict-aliasing"
	CXXFLAGS="$CXXFLAGS -Wall -Werror -fno-strict-aliasing"
fi

# Checks for libraries.
AC_CHECK_HEADERS([sql.h sqlext.h sqltypes.h],,[AC_MSG_ERROR("unixodbc headers missing.")])
AC_CHECK_LIB(odbc, main,[ODBC_LIBS=-lodbc], [AC_MSG_ERROR("Linking against odbc failed.")])
AC_SUBST(ODBC_LIBS)
AC_CHECK_HEADERS(sys/prctl.h)

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
