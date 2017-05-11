dnl     Flexisip, a flexible SIP proxy server with media capabilities.
dnl    Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.
dnl
dnl    This program is free software: you can redistribute it and/or modify
dnl    it under the terms of the GNU Affero General Public License as
dnl    published by the Free Software Foundation, either version 3 of the
dnl    License, or (at your option) any later version.
dnl
dnl    This program is distributed in the hope that it will be useful,
dnl    but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl    GNU Affero General Public License for more details.
dnl
dnl    You should have received a copy of the GNU Affero General Public License
dnl    along with this program.  If not, see <http://www.gnu.org/licenses/>.

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])

AC_INIT([flexisip], [1.0.12], [simon.morlat@linphone.org])

AC_CONFIG_SRCDIR([src/agent.cc])
AC_CONFIG_HEADERS([flexisip-config.h])

AM_INIT_AUTOMAKE([-Wno-portability])
AC_CONFIG_MACRO_DIR([m4])

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],)
m4_include([m4/ax_compare_version.m4])
m4_include([m4/ax_xsdcxx.m4])

# Checks for programs.
# Use ./configure CXX=path to override.
AC_PROG_CC(["xcrun clang" gcc])
AC_PROG_CXX(["xcrun clang++" g++ ])
AC_PROG_LIBTOOL
# use for xml data binding

AC_ARG_ENABLE(snmp,
	AC_HELP_STRING([--enable-snmp], [Build snmp support [no]]),
	[snmp="${enableval}"],
	[snmp=no]
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
AC_DEFINE_UNQUOTED(DEFAULT_LOG_DIR, "$localstatedir/opt/belledonne-communications/log/flexisip", [Directory where log files will be put])


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
	AC_HELP_STRING([--enable-odbc], [Build odbc support [auto]]),
	[odbc="${enableval}"],
	[odbc=auto]
)
# You can specify the odbc_config place to get the correct CFLAGS
AC_ARG_WITH(odbc,
	AC_HELP_STRING([--with-odbc], [Specify the odbc_config binary directory, which is used to find the ODBC libs and includes (eg: /usr/local) [default=/usr]]),
	[odbc_prefix=$withval],
	[odbc_prefix=/usr]
)
if test x$odbc != xno ; then
	# Use the odbc_config tool to get odbc libs and includes
	AC_CHECK_PROG([odbc_config],[odbc_config], [yes], [no], [$odbc_prefix/bin])
	if test $odbc_config = no; then
		dnl debian does include odbc_config program
		AC_MSG_WARN(['odbc_config' not found in $odbc_prefix/bin, maybe use --with-odbc ?])
		if test "$odbc_prefix" != "/usr" ; then
			ODBC_CFLAGS="-I${odbc_prefix}/include"
			ODBC_LIBS="-L${odbc_prefix}/lib"
		fi
		ODBC_LIBS="$ODBC_LIBS -lodbc"
	else
		ODBC_CFLAGS="`$odbc_prefix/bin/odbc_config --cflags`"
		ODBC_LIBS="`$odbc_prefix/bin/odbc_config --libs`"
	fi

	# Checks for libraries.
	CPPFLAGS_save=$CPPFLAGS
	CPPFLAGS="$CPPFLAGS $ODBC_CFLAGS"
	AC_CHECK_HEADERS([sql.h sqlext.h sqltypes.h],[have_unixodbc_headers=yes],[have_unixodbc_headers=no])
	CPPFLAGS=$CPPFLAGS_save

	LIBS_save=$LIBS
	LIBS="$LIBS $ODBC_LIBS"
	AC_CHECK_LIB(odbc, SQLConnect,[foo=bar], [have_sql_linking=yes], [have_sql_linking=no])
	LIBS=$LIBS_save

	AC_SUBST(ODBC_LIBS)
	AC_SUBST(ODBC_CFLAGS)

	if test x$have_unixodbc_headers = xno ; then
		if test x$odbc != xauto ; then
			AC_MSG_ERROR([unixodbc headers not found. This is required for enabling odbc. Use --disable-odbc if you don''t need this feature.])
		fi
		odbc=no
	elif test x$have_sql_linking = xno ; then
		if test x$odbc != xauto ; then
			AC_MSG_ERROR([Linking against odbc failed. This is required for enabling odbc. Use --disable-odbc if you don''t need this feature.])
		fi
		odbc=no
	else
		odbc=yes
	fi
else
	odbc=no
fi
AM_CONDITIONAL(BUILD_ODBC,test x$odbc = xyes)

# Check for mysql
AC_ARG_WITH(mysql,
	AC_HELP_STRING([--with-mysql], [Set prefix where MySQL can be found or "none" to disable (ex:/usr or /usr/local) [[default=/usr]]]),
	[mysql_prefix=$withval],
	[mysql_prefix=/usr]
)
if test "${mysql_prefix}" != "none" ; then
	MYSQL_CFLAGS="-I${mysql_prefix}/include/mariadb"

	dnl check mysql headers
	have_mysql=no
	CPPFLAGS_save=$CPPFLAGS
	CPPFLAGS="$CPPFLAGS $MYSQL_CFLAGS"
	AC_CHECK_HEADER([mysql.h],have_mysql_headers=yes)
	CPPFLAGS=$CPPFLAGS_save
	
	if test "$have_mysql_headers" = "no" ; then
            dnl try with mariadb
            MYSQL_CFLAGS="-I${mysql_prefix}/include/mysql"
            CPPFLAGS_save=$CPPFLAGS
            CPPFLAGS="$CPPFLAGS $MYSQL_CFLAGS"
            AC_CHECK_HEADER([mysql.h],have_mysql_headers=yes)
            CPPFLAGS=$CPPFLAGS_save
	fi

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

## SOCI ORM

AC_ARG_ENABLE(soci,
	AC_HELP_STRING([--enable-soci],[Build with SOCI support [default=auto]]),

	[soci="${enableval}"],
	[soci=auto]
)
AC_ARG_WITH(soci,
	AC_HELP_STRING([--with-soci], [Specify the soci location. We expect this location to contain lib/libsoci.so, lib/libsoci_mysql.so and include/soci/ [default=/usr]]),

	[soci_prefix="${withval}"],
	[soci_prefix=/usr]
)

if test x$soci != "xno"; then

	SOCI_LIBS="-L$soci_prefix/lib -lsoci_core -lsoci_mysql"
	SOCI_CFLAGS="-I$soci_prefix/include/soci"

	LIBS_save=$LIBS
	LIBS="$LIBS $SOCI_LIBS"
	AC_CHECK_LIB(soci_core, soci_create_session,[soci_core_ok=ok], [AC_MSG_WARN([Linking against libsoci_core failed.])])
	AC_CHECK_LIB(soci_mysql, register_factory_mysql,[soci_mysql_ok=ok], [AC_MSG_WARN([Linking against libsoci_mysql failed.])])
	LIBS=$LIBS_save

	CPPFLAGS_save=$CPPFLAGS
	CPPFLAGS="$CPPFLAGS $MYSQL_CFLAGS $SOCI_CFLAGS"
	AC_LANG_PUSH([C++])
	AC_CHECK_HEADERS([soci.h mysql/soci-mysql.h],[soci_headers_ok=ok],[AC_MSG_WARN([soci headers not found])])
	AC_LANG_POP([C++])
	CPPFLAGS=$CPPFLAGS_save

	if test $soci_core_ok$soci_mysql_ok$soci_headers_ok$have_mysql != "okokokyes"; then
		if test x$soci = "xauto"; then
			AC_MSG_WARN([Soci was not detected, disabling])
			soci=no
		else
			AC_MSG_ERROR([Soci was not detected correctly])
		fi
	else
		soci=yes
	fi

	AC_SUBST(SOCI_CFLAGS)
	AC_SUBST(SOCI_LIBS)
fi

AM_CONDITIONAL(ENABLE_SOCI, test x$soci != xno)

# Checks for header files.

AC_CHECK_HEADERS(sys/prctl.h)

AC_ARG_ENABLE(doc,
	AC_HELP_STRING([--enable-doc],
		[Build documentation [yes]]),
		[doc="${enableval}"],[doc=yes]
)


# Check for transcoder
AC_ARG_ENABLE(transcoder,
	AC_HELP_STRING([--enable-transcoder], [Build transcoder support [auto]]),
	[transcoder="${enableval}"],
	[transcoder=auto]
)
have_transcoder=no
if test x$transcoder != xno ; then
	PKG_CHECK_MODULES(MEDIASTREAMER,[mediastreamer >= 2.13.0],[have_transcoder=yes],[have_transcoder=no])
	if test x$have_transcoder = xno ; then
		if test x$transcoder != xauto ; then
			AC_MSG_ERROR([mediastreamer2 not found or too old. This is required for enabling transcoder. Use --disable-transcoder if you don''t need this feature.])
		fi
	fi
fi
AM_CONDITIONAL(BUILD_TRANSCODER,test x$have_transcoder = xyes)
if test "$have_transcoder" = "yes"; then
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


# Monotonic clock was not included in c++11x
AC_LANG_PUSH([C++])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM([
	#include <chrono>
	using namespace std;
	using namespace chrono;
	steady_clock::time_point test;
	],[]
  )],
  [use_monotonic_clock=no],
  [use_monotonic_clock=yes]
)
AC_LANG_POP([C++])
AM_CONDITIONAL(USE_MONOTONIC_CLOCK,test x$use_monotonic_clock = xyes)


if test "$build_upnp" != "false" ; then
	PKG_CHECK_MODULES([LIBUPNP], [libupnp],
		[if  pkg-config --atleast-version=1.6 "libupnp < 1.7"; then
			build_upnp=true
		else
			AC_MSG_ERROR([libupnp >= 1.6 < 1.5 required.])
		fi],
		[if test "$build_upnp" == "true" ; then
			AC_MSG_ERROR([libupnp not found.])
		else
			build_upnp=false
		fi]
	)

fi

AC_ARG_ENABLE(pushnotification,
	AC_HELP_STRING([--enable-pushnotification], [Build pushnotification support [yes]]),
	[pushnotification="${enableval}"],
	[pushnotification=yes]
)

if test x$pushnotification != xno ; then
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
	AC_HELP_STRING([--enable-redis], [Build with redis key/value datastore [auto]]),
	[redis="${enableval}"],
	[redis=auto]
)

AC_ARG_WITH(redis,
	AC_HELP_STRING([--with-redis], [Specify where to find the redis libraries. Will force enable redis build if specified. [default=/usr]]),
	[
		redis_prefix="${withval}"
	],
	[redis_prefix=/usr]
)
have_redis=no
if test x$redis != xno ; then

	PKG_CHECK_MODULES(HIREDIS,[hiredis >= 0.11.0],[have_redis=yes],[have_redis=no])
	if test "$have_redis" = "no" ; then

		if test "$redis_prefix" != "/usr"; then
			HIREDIS_CFLAGS="-I$redis_prefix/include"
			HIREDIS_LIBS="-L$redis_prefix/lib -lhiredis"
		else
			# default value should have a lib anyway
			HIREDIS_LIBS="-lhiredis"
		fi

		CPPFLAGS_save=$CPPFLAGS
		CPPFLAGS="$CPPFLAGS $HIREDIS_CFLAGS"
		LIBS_save=$LIBS
		LIBS="$LIBS $HIREDIS_LIBS"
		AC_CHECK_HEADERS(hiredis/hiredis.h,
			[AC_CHECK_LIB(hiredis,redisAsyncCommand,[have_redis=yes] , [have_redis=no])],
			[have_redis=no])

		CPPFLAGS=$CPPFLAGS_save
		LIBS=$LIBS_save



		# when redis is not detected through pkgconfig, we can't know whether the
		# connect callback uses 1 or 2 args. Better not using it at all.
		redis_no_callback=yes
		if test "$have_redis" = "no" ; then
			HIREDIS_CFLAGS=
			HIREDIS_LIBS=
			if test "$redis" = "yes" ; then
				AC_MSG_ERROR([hiredis library not found.])
			fi
		fi
	fi
	AC_SUBST(HIREDIS_CFLAGS)
	AC_SUBST(HIREDIS_LIBS)
fi

AM_CONDITIONAL(BUILD_REDIS,test x$have_redis = xyes)

AM_CONDITIONAL(WITHOUT_HIREDIS_CONNECT_CALLBACK,test x$redis_no_callback = xyes)
if test x$redis_no_callback = xyes ; then
	AC_MSG_WARN([Using hiredis without connect callback!])
fi

AC_ARG_ENABLE(protobuf,
	AC_HELP_STRING([--enable-protobuf],
		[Build registrar contact serializer using protobuf [auto]]),
		[protobuf="${enableval}"],[protobuf=auto]
)
have_protobuf=no
if test x$protobuf != xno ; then
	PKG_CHECK_MODULES(PROTOBUF,[protobuf >= 2.3.0],[have_protobuf=yes],[have_protobuf=no])
	if test "$protobuf$have_protobuf" = "yesno" ; then
		AC_MSG_ERROR([No protobuf library found])
	fi
fi
AM_CONDITIONAL(BUILD_PROTOBUF,test x$have_protobuf = xyes)



# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL

PKG_CHECK_MODULES(SOFIA,[sofia-sip-ua >= 1.13.12bc])
PKG_CHECK_MODULES(ORTP,[ortp >= 0.26.0])
PKG_CHECK_MODULES(BCTOOLBOX,[bctoolbox >= 0.4.0])

AC_ARG_ENABLE(xsd,
	AC_HELP_STRING([--enable-xsd], [Enable xsd support, used for enhanced file transfers support and presence [default=auto]]),
	[use_xsd="${enableval}"],
	[use_xsd=auto]
)


AC_ARG_ENABLE(presence,
	AC_HELP_STRING([--enable-presence],
		[Build presence server]),
		[presence="${enableval}"],[presence=no]
)

if test x$presence = xyes ; then
	if test "x$use_xsd" = xno; then
		AC_MSG_ERROR([CodeSynthesis XSD required for presence server.])
	fi
	use_xsd=yes
fi

# ##################################
# XSD checks
# ##################################

AC_ARG_WITH([xsd-root],
	[AS_HELP_STRING([--with-xsd-root=@<:@DIR@:>@],
	[Specify where xsd is installed. We expect to find $DIR/bin/xsd (program) and $DIR/libxsd (includes) in there. Default path is /usr])],
	[xsd_root="${withval}"],
	[xsd_root="/usr"]
)



xsd_err_msg="A correct version can be found at http://www.codesynthesis.com/products/xsd/download.xhtml . Use --with-xsd=(path to xsd) to reconfigure with XSD support."

# this function tries to find XSD from the xsd_root
AC_DEFUN([FIND_XSDCXX],
[
	# check if XSD is detected by the system
	AC_CHECK_PROG([XSDCXX], [xsd], [$xsd_root/bin/xsd], [], [$xsd_root/bin])

	if test x$XSDCXX = x; then
		# sometimes, xsc is called xsdcxx
		AC_CHECK_PROG([XSDCXX], [xsdcxx], [$xsd_root/bin/xsdcxx], [], [$xsd_root/bin])
	fi

])

if test x$use_xsd != xno ; then

	if test x$XSDCXX = x; then
		FIND_XSDCXX
	fi
	found_xsd=yes
	# hard check on xsd
	if  test x$XSDCXX = x ; then
		AC_MSG_NOTICE([xsd executable not found. $xsd_err_msg])
		found_xsd=no
	elif test -z "`$XSDCXX version 2>&1 | grep CodeSynthesis`" ; then
		# check that we don't match a bad xsd executable
		AC_MSG_NOTICE([xsd executable is not the good XSD (this can happen on Mac OS). Disabling XML features since use_xsd is auto.])
		found_xsd=no
	fi

	if test "$use_xsd$found_xsd" = "yesno" ; then
		AC_MSG_ERROR([xsd required but not found, read messages above.])
	fi

	if test "$found_xsd" = "yes" ; then

		# check xsd headers
		CPPFLAGS_save=$CPPFLAGS
		CPPFLAGS="-I$xsd_root/libxsd $CPPFLAGS"
		AC_CHECK_HEADERS("xsd/cxx/config.hxx",
			[AC_SUBST([XSDCXX_CPPFLAGS], "-I$xsd_root/libxsd/")],
			[foo=bar])
		CPPFLAGS=$CPPFLAGS_save
		if test x$XSDCXX_CPPFLAGS = x; then
			AC_MSG_ERROR([xsd headers not found at path $xsd_root/libxsd/xsd/cxx/config.hxx. Are you sure that xsd is correctly installed?
				$xsd_err_msg])
		fi

		# if XSD is enabled, we need Xerces as a dependency
		PKG_CHECK_MODULES(XERCESC, [xerces-c >= 3.0.0])
		use_xsd=yes
		AC_DEFINE([ENABLE_XSD], 1, [Enable XSD])
	fi
fi
AM_CONDITIONAL(BUILD_XSD, [test x$use_xsd = xyes] )


if test "$libdir" = /usr/lib ; then
	use_rpath=no
else
	use_rpath=yes
fi
AM_CONDITIONAL(USE_RPATH, [test x$use_rpath = xyes])
# ##################################
# END OF XSD CHECKS
# ##################################

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

if test x$have_protobuf = xyes ; then
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
if test x$strictness = xyes ; then
		CFLAGS="$CFLAGS -Wall -Werror -fno-strict-aliasing"
		WARNINGCXXFLAGS="-Wall -Werror -fno-strict-aliasing -Wno-error=deprecated-declarations -Wno-error=unknown-pragmas"
fi

AC_SUBST(WARNINGCXXFLAGS)


if test x$presence = xyes ; then
	if test "x$use_xsd" = xno; then
		AC_MSG_ERROR([CodeSynthesis XSD required for presence server.])
	fi
	PKG_CHECK_MODULES(BELLESIP, [belle-sip >= 1.2.4])
	AC_DEFINE([ENABLE_PRESENCE],1, [enable presence module])
fi

AM_CONDITIONAL([BUILD_PRESENCE], [test x$presence = xyes])


AC_CONFIG_FILES(
[
Makefile
scripts/Makefile
scripts/debian/Makefile
scripts/redhat/Makefile
scripts/yocto/Makefile
scripts/flexisip.service
scripts/flexisip@.service
scripts/flexisip-presence.service
scripts/flexisip-presence@.service
src/Makefile
src/presence/Makefile
src/xml/Makefile
src/tclap/Makefile
doc/Makefile
debian/Makefile
flexisip.spec
])
AC_OUTPUT



echo "Flexisip build configuration ended."
echo "Summary of build options:"
printf "* %-30s %s\n" "SNMP"                $snmp
printf "* %-30s %s\n" "ODBC"                $odbc
printf "* %-30s %s\n" "Transcoder"          $have_transcoder
printf "* %-30s %s\n" "Specific features"   $specific_features
printf "* %-30s %s\n" "Push notification"   $pushnotification
printf "* %-30s %s\n" "Redis"               $have_redis
printf "* %-30s %s\n" "Protobuf"            $have_protobuf
printf "* %-30s %s\n" "XSD support"         $use_xsd
printf "* %-30s %s\n" "Presence"            $presence
printf "* %-30s %s\n" "Soci"                $soci

echo "Now type 'make' to compile, and then 'make install' (as root if needed) to install it."
