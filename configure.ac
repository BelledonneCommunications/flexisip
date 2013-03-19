#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])

AC_INIT([flexisip], [0.6.0], [simon.morlat@linphone.org])

AC_CONFIG_SRCDIR([src/agent.cc])
AC_CONFIG_HEADERS([flexisip-config.h])

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],)
m4_include([m4/ax_compare_version.m4])

# Checks for programs.
# Favor g++ 4.4 as (the one in Debian and centos stable versions).
# Use ./configure CXX=path to override.
AC_PROG_CC
AC_PROG_CXX([clang++ g++-4.4 g++])
AC_PROG_LIBTOOL

build_snmp=true
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
AC_DEFINE(SNMP_COMPANY_OID,100000,[Company OID used for prefixing flexisip MIB])


if test -f /etc/debian_version ; then
	use_deb=true;
else
	use_rpm=true;
fi

strictness=yes
case $CXX in
	*clang++*)
	CXXFLAGS="$CXXFLAGS -g -O2 -std=c++0x -stdlib=libc++"
	strictness=no;
	;;
	*g++*)
	# Use only -O1 due to a compile-time bug in gcc 4.4.6 from centos6.
	CFLAGS="-g -O2 -pthread $CFLAGS"
	CXXFLAGS="-g -O1 -pthread -std=c++0x"
	LDFLAGS="-pthread $LDFLAGS"
	;;
esac

AC_ARG_ENABLE(strict,
	AC_HELP_STRING([--enable-strict],
		       [Build with stricter options (gcc only) @<:@yes@:>@]),[
	strictness="${enableval}"],[foo=bar])


# Checks for libraries.
AC_CHECK_HEADERS([sql.h sqlext.h sqltypes.h],,[AC_MSG_ERROR("unixodbc headers missing.")])
AC_CHECK_LIB(odbc, main,[ODBC_LIBS="-lodbc -lltdl"], [AC_MSG_ERROR("Linking against odbc failed.")])
AC_SUBST(ODBC_LIBS)
AC_CHECK_HEADERS(sys/prctl.h)

PKG_PROG_PKG_CONFIG()

# Checks for header files.

AC_ARG_ENABLE(doc,
    AC_HELP_STRING([--disable-doc],
        [Build documentation @<:@yes@:>@]),
        [doc="${enableval}"],[doc=yes]
)

AC_ARG_ENABLE(transcoder,
	AC_HELP_STRING([--disable-transcoder],
	    [Build transcoder support @<:@yes@:>@]),
        [transcoder="${enableval}"],[transcoder=yes]
)
AM_CONDITIONAL(BUILD_TRANSCODER,test x$transcoder = xyes)

AC_ARG_ENABLE(specific-features,
	AC_HELP_STRING([--enable-specific-features],
	    [Enable specific features @<:no:>@]),
        [specific_features="${enableval}"],[specific_features=no]
)
if test $specific_features = "yes"; then
	AC_DEFINE([MEDIARELAY_SPECIFIC_FEATURES_ENABLED],1,[Enable specific features.])
fi

AC_ARG_ENABLE(monotonic-clock-registrations,
	AC_HELP_STRING([--enable-monotonic-clock-registrations],
	    [Enable monotonic clock for registrations @<:no:>@]),
        [monotonic_clock_registrations="${enableval}"],[monotonic_clock_registrations=no]
)
if test $monotonic_clock_registrations = "yes"; then
	AC_DEFINE([MONOTONIC_CLOCK_REGISTRATIONS],1,[Enable monotonic clock for registrations.])
fi

AC_DEFUN([CHECK_BOOST],[$1
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[[
        #ifndef $2
            fail
        #endif
        return 0;
    ]])], [$3], [$4])
])


# Monotonic clock was not included in c++11x
AC_LANG_PUSH([C++])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM([
    #include <chrono>
    using namespace ::std;
    using namespace chrono;
    steady_clock::time_point test;
    ],[]
  )],
  [use_monotonic_clock=no],
  [use_monotonic_clock=yes]
)
AC_LANG_POP([C++])
AM_CONDITIONAL(USE_MONOTONIC_CLOCK,test x$use_monotonic_clock = xyes)


#AC_COMPILE_IFELSE(
#  [AC_LANG_PROGRAM([
#    #include "hiredis/async.h"
#    void connectCb(const struct redisAsyncContext* ctx, int status){};
#    ], [redisConnectCallback *cbNewUi=connectCb]
#   )],
#   [use_old_hiredis=no],
#   [use_old_hiredis=yes]
#)
#AM_CONDITIONAL(WITHOUT_HIREDIS_CONNECT_CALLBACK,test x$use_old_hiredis = xyes)




AC_ARG_ENABLE(pushnotification,
	AC_HELP_STRING([--disable-pushnotification],
	    [Build pushnotification support @<:@yes@:>@]),
        [pushnotification="${enableval}"],[pushnotification=yes]
)

if test x$pushnotification = xyes ; then
	AX_BOOST_BASE([1.41],[pushnotification=yes],[pushnotification=no])
	if test "$pushnotification" = "no" ; then
		AC_MSG_ERROR([boost not found. This is required for push notification. Use --disable-pushnotification if you don''t need this feature.])
	fi
	CHECK_BOOST([AX_BOOST_SYSTEM], [HAVE_BOOST_SYSTEM], [], [AC_MSG_ERROR([boost system not found.])])
	CHECK_BOOST([AX_BOOST_ASIO], [HAVE_BOOST_ASIO], [], [AC_MSG_ERROR([boost asio not found.])])
fi

AM_CONDITIONAL(BUILD_PUSHNOTIFICATION,test x$pushnotification = xyes)

AC_ARG_ENABLE(datehandler,
	AC_HELP_STRING([--enable-datehandler],
	    [Build DateHandler module @<:@no@:>@]),
        [datehandler="${enableval}"],[datehandler=no]
)

if test "$datehandler" = "yes" ; then
	AC_DEFINE([HAVE_DATEHANDLER],1,[Defined when the DateHandler module is compiled in.])
fi
AM_CONDITIONAL(BUILD_DATEHANDLER,test x$datehandler = xyes)

AC_ARG_ENABLE(redis,
	AC_HELP_STRING([--enable-redis],
	    [Build with redis key/value datastore @<:@no@:>@]),
        [redis="${enableval}"],[redis=no]
)
if test x$redis = xyes ; then
	PKG_CHECK_MODULES(HIREDIS,[hiredis >= 0.10.0],[redis=yes],[redis=no])
	if test "$redis" = "no" ; then
		AC_CHECK_HEADERS(hiredis/hiredis.h,[redis=yes],[redis=no])
		AC_CHECK_LIB(hiredis,redisAsyncCommand)
	fi
	if test "$redis" = "no" ; then
		AC_MSG_ERROR([hiredis not found.])
	fi
fi
AM_CONDITIONAL(BUILD_REDIS,test x$redis = xyes)

PKG_CHECK_MODULES(HIREDISNEW,[hiredis >= 0.10.2],[use_old_hiredis=no],[use_old_hiredis=yes])
AM_CONDITIONAL(WITHOUT_HIREDIS_CONNECT_CALLBACK,test x$use_old_hiredis = xyes)
if test x$use_old_hiredis = xyes ; then
    AC_MSG_WARN([Using hiredis without connect callback!])
fi


AC_ARG_ENABLE(protobuf,
	AC_HELP_STRING([--enable-protobuf],
	    [Build registrar contact serializer using protobuf @<:@no@:>@]),
        [protobuf="${enableval}"],[protobuf=no]
)
if test x$protobuf = xyes ; then
    PKG_CHECK_MODULES(PROTOBUF,[protobuf >= 2.3.0])
fi
AM_CONDITIONAL(BUILD_PROTOBUF,test x$protobuf = xyes)



# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL

PKG_CHECK_MODULES(SOFIA,[sofia-sip-ua >= 1.12.11])
PKG_CHECK_MODULES(MEDIASTREAMER,[mediastreamer >= 2.1.0])
PKG_CHECK_MODULES(ORTP,[ortp >= 0.16.3])

ORTP_VERSION=`$PKG_CONFIG --modversion ortp 2>&1`
AX_COMPARE_VERSION([$ORTP_VERSION], [ge], [0.21.0],ORTP_ABI_VERSION=">=9",ORTP_ABI_VERSION="<9")
if test "x$ORTP_ABI_VERSION" = "x>=9"; then
        AC_DEFINE([ORTP_ABI_VERSION],9,[oRTP ABI version])
fi



AX_COMPARE_VERSION([$ORTP_VERSION], [ge], [0.21.1],
	AC_DEFINE([ORTP_HAS_REUSEADDR],1, [oRTP rtp_session_set_reuseaddr availabled]),
	AC_MSG_WARN([Ports allocated inside relay/transcoder will be messed up!])
)


# Checks for library functions.

AM_CONDITIONAL(USE_DEB,test x$use_deb = xtrue)
AM_CONDITIONAL(USE_RPM,test x$use_rpm = xtrue)
dnl $cross_compiling is set by autoconf if we are in a cross-compile environment.
AM_CONDITIONAL(CROSS_COMPILING, test x$cross_compiling = xyes)

# Checks for programs

if test x$protobuf = xyes ; then
    AC_PATH_PROG([PROTOC],[protoc])
    if test -z "$PROTOC"; then
        AC_MSG_ERROR(['protoc' is required to generate protobuf serializer classes])
    fi
fi


# Generates documentation pdf only if pdflatex is found
AC_CHECK_PROG([pdflatex], [pdflatex], [yes], [no])
AM_CONDITIONAL([GENERATE_DOC], [test "x$pdflatex$doc" = xyesyes])


# Export path to configuration directory

CONFIG_DIR="\$(sysconfdir)/flexisip"

AC_SUBST(CONFIG_DIR)

#Keep this at the end
if test x$GCC$strictness = xyesyes ; then
        CFLAGS="$CFLAGS -Wall -Werror -fno-strict-aliasing"
        CXXFLAGS="$CXXFLAGS -Wall -Werror -fno-strict-aliasing"
fi


AC_CONFIG_FILES(
[
Makefile
scripts/Makefile
scripts/debian/Makefile
scripts/redhat/Makefile
src/Makefile
src/test/Makefile
doc/Makefile
debian/Makefile
flexisip.spec
])
AC_OUTPUT
