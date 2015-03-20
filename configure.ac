#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])

AC_INIT([flexisip], [0.8.0], [simon.morlat@linphone.org])

AC_CONFIG_SRCDIR([src/agent.cc])
AC_CONFIG_HEADERS([flexisip-config.h])

AM_INIT_AUTOMAKE([-Wno-portability])
AC_CONFIG_MACRO_DIR([m4])

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],)
m4_include([m4/ax_compare_version.m4])
m4_include([m4/ax_xsdcxx.m4])

# Checks for programs.
# Favor g++ 4.4 (the one in centos stable version)
# or g++ 4.7 (the one in Debian stable version).
# Use ./configure CXX=path to override.
AC_PROG_CC(["xcrun clang" gcc-4.4 gcc-4.7 gcc])
AC_PROG_CXX(["xcrun clang++" g++-4.4 g++-4.7 g++ ])
AC_PROG_LIBTOOL
# use for xml data binding
AX_XSDCXX

AC_ARG_ENABLE(snmp,
    AC_HELP_STRING([--enable-snmp], [Build snmp support [yes]]),
    [snmp="${enableval}"],
    [snmp=yes]
)

if test x$snmp = xyes ; then
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
fi
AM_CONDITIONAL(BUILD_SNMP,test x$build_snmp = xtrue)
AC_DEFINE(SNMP_COMPANY_OID,100000,[Company OID used for prefixing flexisip MIB])


if test -f /etc/debian_version ; then
	use_deb=true;
else
	use_rpm=true;
fi


AC_ARG_ENABLE(strict,
	AC_HELP_STRING([--enable-strict],[Build with stricter options (gcc only) [default=yes]]),
	[strictness="${enableval}"],
	[strictness=yes]
)

case $CXX in
	*clang++*)
	CXXFLAGS="$CXXFLAGS -std=c++11 -Qunused-arguments"
	strictness=no;
	# libc++ is only required on apple
	case $host in
		*apple-darwin*)
			CXXFLAGS="$CXXFLAGS -stdlib=libc++"
			LDFLAGS="$LDFLAGS -framework SystemConfiguration"
		;;
	esac
	;;
esac

if test $GCC = yes ; then
	# Use only -O1 due to a compile-time bug in gcc 4.4.6 from centos6.
	CFLAGS="-g -O2 $CFLAGS"
	CXXFLAGS="-g -O1 -std=c++0x $CXXFLAGS"

	case $host in
		*apple-darwin*)
			# on OSX, pthread is always enabled (see http://lists.apple.com/archives/Unix-porting/2005/Mar/msg00019.html)
			# If enabled, the compiler reports "unrecognized option '-pthread'"
		;;
		*)
			CFLAGS="-pthread $CFLAGS"
			CXXFLAGS="-pthread $CXXFLAGS"
			LDFLAGS="-pthread $LDFLAGS"
		;;
	esac
fi

PKG_PROG_PKG_CONFIG()


# 
# UNIXODBC HANDLING
#

AC_ARG_ENABLE(odbc,
	AC_HELP_STRING([--enable-odbc],
	[Build with odbc support [default=yes]]),
	[odbc="${enableval}"],[odbc=yes]
)
AM_CONDITIONAL(BUILD_ODBC,test x$odbc = xyes)


# You can specify the odbc_config place to get the correct CFLAGS
AC_ARG_WITH(odbc,
	AC_HELP_STRING([--with-odbc], [Specify the odbc_config binary directory, which is used to find the ODBC libs and includes (eg: /usr/local) [default=/usr]]),
	[odbc_prefix=$withval],	
	[odbc_prefix=/usr]
)

if test x$odbc = "xyes"; then

	# Use the odbc_config tool to get odbc libs and includes
	AC_CHECK_PROG([odbc_config],[odbc_config], [yes], [no], [$odbc_prefix/bin])
	if test $odbc_config = no; then
		AC_MSG_ERROR(['odbc_config' not found in $odbc_prefix/bin, maybe use --with-odbc ?])
	else
		ODBC_CFLAGS="`$odbc_prefix/bin/odbc_config --cflags`"
		ODBC_LIBS="`$odbc_prefix/bin/odbc_config --libs`"
	fi

	# Checks for libraries.
	CPPFLAGS_save=$CPPFLAGS
	CPPFLAGS="$CPPFLAGS $ODBC_CFLAGS"
	AC_CHECK_HEADERS([sql.h sqlext.h sqltypes.h],,[AC_MSG_ERROR([unixodbc headers missing. This is required for odbc. Maybe install the development package of ODBC?])])
	CPPFLAGS=$CPPFLAGS_save

	LIBS_save=$LIBS
	LIBS="$LIBS $ODBC_LIBS"
	AC_CHECK_LIB(odbc, SQLConnect,[foo=bar], [AC_MSG_ERROR([Linking against odbc failed.])])
	LIBS=$LIBS_save

	AC_SUBST(ODBC_LIBS)
	AC_SUBST(ODBC_CFLAGS)
fi


# Check for odb compiler
AC_PATH_PROG([ODB],[odb],[no])
if test $ODB != no; then
	have_odb=yes
else
	have_odb=no
fi

# Check for libodb
AC_ARG_ENABLE(libodb,
	[AC_HELP_STRING([--enable-libodb=[yes/no]],[Compilation of libodb (default=auto)])],
    [case "${enableval}" in
		yes)	enable_libodb=true ;;
		no)	enable_libodb=false ;;
		*)	AC_MSG_ERROR(bad value ${enableval} for --enable-libodb) ;;
	esac],
	[enable_libodb=auto]
)

if test x$enable_libodb != xfalse ; then
	PKG_CHECK_MODULES(LIBODB,[libodb >= 2.3.0],[have_libodb=yes],[have_libodb=no])
fi

AM_CONDITIONAL(BUILD_ODB,test x$have_libodb$have_odb = xyesyes)
if test "$have_libodb$have_odb" = "yesyes"; then
	AC_DEFINE([HAVE_ODB],1,[Enable odb.])
else
	enable_libodb=false
fi

# Check for libodb-mysql
AC_ARG_ENABLE(libodb-mysql,
	AC_HELP_STRING([--enable-libodb-mysql],
	    [Build libodb-mysql [yes]]),
        [libodb_mysql="${enableval}"],[libodb_mysql=yes]
)
if test x$libodb_mysql = xyes ; then
	PKG_CHECK_MODULES(LIBODB_MYSQL,[libodb-mysql >= 2.3.0],[libodb_mysql=yes],[libodb_mysql=no])
fi


AM_CONDITIONAL(BUILD_LIBODB_MYSQL,test x$libodb_mysql = xyes)
if test "$libodb_mysql" = "yes"; then
	AC_DEFINE([ENABLE_LIBODB_MYSQL],1,[Enable libodb-mysql.])
fi

# Check for mysql
AC_ARG_WITH(mysql,
	AC_HELP_STRING([--with-mysql], [Set prefix where MySQL can be found or "none" to disable (ex:/usr or /usr/local) [[default=/usr]]]),
	[mysql_prefix=$withval],
	[mysql_prefix=/usr]
)
if test "${mysql_prefix}" != "none" ; then
	if test "${mysql_prefix}" != "/usr" ; then
		MYSQL_CFLAGS="-I${mysql_prefix}/include"
	fi

	dnl check mysql headers
	have_mysql=no
	CPPFLAGS_save=$CPPFLAGS
	CPPFLAGS="$CPPFLAGS $MYSQL_CFLAGS"
	AC_CHECK_HEADER([mysql/mysql.h],have_mysql_headers=yes)
	CPPFLAGS=$CPPFLAGS_save

	if test "$have_mysql_headers" = "yes" ; then
		have_mysql=yes
	else
		AC_MSG_NOTICE([Could not find mysql headers or lib])
		MYSQL_CFLAGS=
	fi

	AM_CONDITIONAL(BUILD_MYSQL,test x$have_mysql = xyes)

	AC_SUBST(MYSQL_CFLAGS)
else
	have_mysql=no
	MYSQL_CFLAGS=
fi


# Checks for header files.

AC_CHECK_HEADERS(sys/prctl.h)

AC_ARG_ENABLE(doc,
    AC_HELP_STRING([--enable-doc],
        [Build documentation [yes]]),
        [doc="${enableval}"],[doc=yes]
)

AC_ARG_ENABLE(transcoder,
	AC_HELP_STRING([--enable-transcoder],
	    [Build transcoder support [yes]]),
        [transcoder="${enableval}"],[transcoder=yes]
)
if test $transcoder = "yes"; then
	PKG_CHECK_MODULES(MEDIASTREAMER,[mediastreamer >= 2.9.0])
fi

AM_CONDITIONAL(BUILD_TRANSCODER,test x$transcoder = xyes)
if test "$transcoder" = "yes"; then
	AC_DEFINE([ENABLE_TRANSCODER],1,[Enable transcoder module.])
fi

AC_ARG_ENABLE(specific-features,
	AC_HELP_STRING([--enable-specific-features],
	    [Enable specific features [no]]),
        [specific_features="${enableval}"],[specific_features=no]
)
if test $specific_features = "yes"; then
	AC_DEFINE([MEDIARELAY_SPECIFIC_FEATURES_ENABLED],1,[Enable specific features.])
fi

AC_ARG_ENABLE(monotonic-clock-registrations,
	AC_HELP_STRING([--enable-monotonic-clock-registrations],
	    [Enable monotonic clock for registrations [no]]),
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


AX_BOOST_BASE([1.41],[],[AC_MSG_WARN([boost base not found.])])
AC_ARG_ENABLE(boostlog,
    AC_HELP_STRING([--enable-boostlog], [Build boost log support [no]]),
    [boostlog="${enableval}"],
    [boostlog=no]
)

if test x$boostlog = xyes ; then
CHECK_BOOST([AX_BOOST_LOG], [HAVE_BOOST_LOG], [found_boost_log=yes], [AC_MSG_ERROR([boost log not found.])])
if test x$found_boost_log = xyes ; then
	CHECK_BOOST([AX_BOOST_REGEX], [HAVE_BOOST_LOG], [], [AC_MSG_ERROR([boost regex not found.])])
	CHECK_BOOST([AX_BOOST_THREAD], [HAVE_BOOST_LOG], [], [AC_MSG_ERROR([boost thread not found.])])
	CHECK_BOOST([AX_BOOST_SYSTEM], [HAVE_BOOST_LOG], [], [AC_MSG_ERROR([boost system not found.])])
fi
fi
AM_CONDITIONAL(BUILD_BOOSTLOG, test x$found_boost_log = xyes)


AC_ARG_ENABLE(pushnotification,
	AC_HELP_STRING([--enable-pushnotification], [Build pushnotification support [yes]]),
    [pushnotification="${enableval}"],
    [pushnotification=yes]
)

if test x$pushnotification = xyes ; then
	AX_BOOST_BASE([1.41],[pushnotification=yes],[pushnotification=no])
	if test "$pushnotification" = "no" ; then
		AC_MSG_ERROR([boost not found. This is required for push notification. Use --disable-pushnotification if you don''t need this feature.])
	fi
	CHECK_BOOST([AX_BOOST_SYSTEM], [HAVE_BOOST_SYSTEM], [], [AC_MSG_ERROR([boost system not found.])])
	CHECK_BOOST([AX_BOOST_ASIO], [HAVE_BOOST_ASIO], [], [AC_MSG_ERROR([boost asio not found.])])
	PKG_CHECK_MODULES(OPENSSL,[openssl >= 0.9.8])
fi

AM_CONDITIONAL(BUILD_PUSHNOTIFICATION,test x$pushnotification = xyes)

AC_ARG_ENABLE(datehandler,
	AC_HELP_STRING([--enable-datehandler], [Build DateHandler module [no]]),
    [datehandler="${enableval}"],
    [datehandler=no]
)

if test "$datehandler" = "yes" ; then
	AC_DEFINE([HAVE_DATEHANDLER],1,[Defined when the DateHandler module is compiled in.])
fi
AM_CONDITIONAL(BUILD_DATEHANDLER,test x$datehandler = xyes)

AC_ARG_ENABLE(redis,
	AC_HELP_STRING([--enable-redis], [Build with redis key/value datastore [no]]),
    [redis="${enableval}"],
    [redis=no]
)

AC_ARG_WITH(redis, 
	AC_HELP_STRING([--with-redis], [Specify where to find the redis libraries. Will force enable redis build if specified. [default=/usr]]),
	[
		redis_prefix="${withval}"
		redis=yes
	],
	[redis_prefix=/usr]
)

if test x$redis = xyes ; then

	PKG_CHECK_MODULES(HIREDIS,[hiredis >= 0.11.0],[redis=yes],[redis=no])
	if test "$redis" = "no" ; then

		if test "$redis_prefix" != "/usr"; then
			HIREDIS_CFLAGS="-I$redis_prefix/include"
			HIREDIS_LIBS="-L$redis_prefix/lib -lhiredis"
		else
			# default value should have a lib anyway
			HIREDIS_LIBS="-lhiredis"
		fi

		CPPFLAGS_save=$CPPFLAGS
		CPPFLAGS="$CPPFLAGS $HIREDIS_CFLAGS"
		AC_CHECK_HEADERS(hiredis/hiredis.h,[redis=yes],[AC_MSG_ERROR([hiredis library not found.])])
		CPPFLAGS=$CPPFLAGS_save

		LIBS_save=$LIBS
		LIBS="$LIBS $HIREDIS_LIBS"
		AC_CHECK_LIB(hiredis,redisAsyncCommand)
		LIBS=$LIBS_save

		AC_SUBST(HIREDIS_CFLAGS)
		AC_SUBST(HIREDIS_LIBS)

		# when redis is not detected through pkgconfig, we can't know whether the 
		# connect callback uses 1 or 2 args. Better not using it at all.
		redis_no_callback=yes
	fi
fi

AM_CONDITIONAL(BUILD_REDIS,test x$redis = xyes)

AM_CONDITIONAL(WITHOUT_HIREDIS_CONNECT_CALLBACK,test x$redis_no_callback = xyes)
if test x$redis_no_callback = xyes ; then
    AC_MSG_WARN([Using hiredis without connect callback!])
fi

AC_ARG_ENABLE(protobuf,
	AC_HELP_STRING([--enable-protobuf],
	    [Build registrar contact serializer using protobuf [no]]),
        [protobuf="${enableval}"],[protobuf=no]
)
if test x$protobuf = xyes ; then
    PKG_CHECK_MODULES(PROTOBUF,[protobuf >= 2.3.0])
fi
AM_CONDITIONAL(BUILD_PROTOBUF,test x$protobuf = xyes)



# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL

PKG_CHECK_MODULES(SOFIA,[sofia-sip-ua >= 1.12.11])
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
        WARNINGCXXFLAGS="-Wall -Werror -fno-strict-aliasing"
fi

AC_SUBST(WARNINGCXXFLAGS)



AC_ARG_ENABLE(presence,
	AC_HELP_STRING([--enable-presence],
	    [Build presence server]),
        [presence="${enableval}"],[presence=no]
)


if test x$presence = xyes ; then
	if test "x$XSDCXX" = x; then
		AC_MSG_ERROR([CodeSynthesis XSD required for presence server.])
	fi	
	PKG_CHECK_MODULES(BELLESIP, [belle-sip >= 1.2.4])
	PKG_CHECK_MODULES(XERCESC, [xerces-c >= 3.0.0])
	AC_DEFINE([ENABLE_PRESENCE],1, [enable presence module])
fi

AM_CONDITIONAL([BUILD_PRESENCE], [test x$presence = xyes])




AC_CONFIG_FILES(
[
Makefile
scripts/Makefile
scripts/debian/Makefile
scripts/redhat/Makefile
src/Makefile
src/presence/Makefile
src/presence/xml/Makefile
doc/Makefile
debian/Makefile
flexisip.spec
])
AC_OUTPUT



echo "Flexisip build configuration ended."
echo "Summary of build options:"
printf "* %-30s %s\n" "SNMP"                $build_snmp
printf "* %-30s %s\n" "ODBC"                $odbc
printf "* %-30s %s\n" "ODB"                 $enable_libodb
printf "* %-30s %s\n" "ODB MySQL"           $libodb_mysql
printf "* %-30s %s\n" "Transcoder"          $transcoder
printf "* %-30s %s\n" "Specific features"   $specific_features
printf "* %-30s %s\n" "Push notification"   $pushnotification
printf "* %-30s %s\n" "Redis"               $redis
printf "* %-30s %s\n" "Protobuf"            $protobuf
printf "* %-30s %s\n" "Presence"            $presence

echo "Now type 'make' to compile, and then 'make install' (as root if needed) to install it."
