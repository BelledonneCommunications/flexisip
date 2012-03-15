#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([flexisip], [0.3.2], [simon.morlat@linphone.org])
AC_CONFIG_SRCDIR([src/agent.cc])
AC_CONFIG_HEADERS([flexisip-config.h])

AM_INIT_AUTOMAKE
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],)

# Checks for programs.
#prefer clang for macosx
AC_PROG_CC([clang gcc])
AC_PROG_CXX([clang++ g++])


case $CXX in
	*clang*) 
		CXXFLAGS="$CXXFLAGS -stdlib=libc++"
		;;
		*)
		CFLAGS="$CFLAGS -pthread"
		CXXFLAGS="$CXXFLAGS -std=c++0x -pthread"
		LDFLAGS="$LDFLAGS -pthread"
	;;
esac

AC_MSG_NOTICE([$CXXFLAGS])

AC_PATH_PROG([NET_SNMP_CONFIG],[net-snmp-config])
if test -z "$NET_SNMP_CONFIG"; then
   build_snmp=false;
   AC_MSG_WARN(['net-snmp-config' is required to build snmp management])
else
	AC_CHECK_HEADERS([net-snmp/net-snmp-config.h]
					,[build_snmp=true]
					,[AC_MSG_WARN("netsnmp headers missing.")])
	if test $build_snmp = true; then
		build_snmp=false;
		AC_CHECK_LIB(netsnmpagent, init_agent,[build_snmp=true], [AC_MSG_WARN("Linking against netsnmpagent failed.")], -lnetsnmphelpers)
	fi
	if test $build_snmp = true; then
		NETSNMPAGENT_LIBS=`${NET_SNMP_CONFIG} --agent-libs`;
		AC_SUBST(NETSNMPAGENT_LIBS)
		AC_DEFINE(ENABLE_SNMP,1,[Tells whether snmp is usable])
		AC_MSG_NOTICE([snmp support enabled])
	fi
fi
AM_CONDITIONAL(BUILD_SNMP,test x$build_snmp = xtrue)
AC_DEFINE(SNMP_COMPANY_OID,100000,[Company OID to used for prefixing felxisip MIB])


if test -f /etc/debian_version ; then
	use_deb=true;
else
	use_rpm=true;
fi



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
