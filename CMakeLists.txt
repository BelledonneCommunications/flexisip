############################################################################
# CMakeLists.txt
# Copyright (C) 2010-2020  Belledonne Communications, Grenoble France
#
############################################################################
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
############################################################################

# CMake 3.13 required by some sub-projects.
cmake_minimum_required(VERSION 3.13)

# Set project version by using the Git describe
include("./linphone-sdk/bctoolbox/cmake/BcToolboxCMakeUtils.cmake")
bc_compute_full_version(FLEXISIP_FULL_VERSION)
bc_parse_full_version("${FLEXISIP_FULL_VERSION}" major minor patch)
project(flexisip VERSION "${major}.${minor}.${patch}" LANGUAGES C CXX)
unset(major)
unset(minor)
unset(patch)

include(CMakePushCheckState)
include(CMakeDependentOption)
include(CheckSymbolExists)
include(CheckFunctionExists)
include(FeatureSummary)
include(CheckCXXSourceCompiles)
include(GNUInstallDirs)

option(ENABLE_STRICT "Pass strict flags to the compiler" ON)
option(ENABLE_DATEHANDLER "Build DateHandler module" OFF)
option(ENABLE_PDFDOC "Build pdf documentation" OFF)
option(ENABLE_MONOTONIC_CLOCK_REGISTRATIONS "Enable monotonic clock for registrations" OFF)
option(ENABLE_PRESENCE "Build presence support" ON)
option(ENABLE_CONFERENCE "Build conference support" ON)
option(ENABLE_PROTOBUF "Build with protobuf support" ON)
option(ENABLE_REDIS "Build with Redis support" ON)
option(ENABLE_SNMP "Build with SNMP support" ON)
option(ENABLE_SOCI "Build with SOCI support" ON)
option(ENABLE_STATIC "Build static library (default is shared library)." OFF)
option(ENABLE_TRANSCODER "Build transcoder support" ON)
option(ENABLE_MDNS "Build multicast DNS support" OFF)
option(ENABLE_EXTERNAL_AUTH_PLUGIN "Enable ExternalAuth plugin support" ON)
option(ENABLE_JWE_AUTH_PLUGIN "Enable JweAuth plugin support" ON)
option(ENABLE_UNIT_TESTS "Enable flexisip unit tests (low level tests)" OFF)

cmake_dependent_option(ENABLE_SPECIFIC_FEATURES "Enable mediarelay specific features" OFF "ENABLE_TRANSCODER" OFF)


# Require C++14
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


find_package(Threads)

if(NOT CMAKE_INSTALL_RPATH AND CMAKE_INSTALL_PREFIX)
	set(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_FULL_LIBDIR})
	message(STATUS "Setting install rpath to ${CMAKE_INSTALL_RPATH}")
endif()

set(SYSCONF_INSTALL_DIR ${CMAKE_INSTALL_FULL_SYSCONFDIR} CACHE STRING "Config directory, the place where flexisip expects its flexisip.conf file to reside" )


set(CONFIG_DIR ${SYSCONF_INSTALL_DIR}/flexisip)
message(STATUS "Config dir: ${CONFIG_DIR}")
set(INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
if(ENABLE_UNIT_TESTS)
	set(TESTER_DATA_DIR ${CMAKE_INSTALL_PREFIX}/share/flexisip-tester)
endif()

function(FIND_PROGRAM_REQUIRED varname progname)
	find_program(${varname} NAMES "${progname}")
	if(NOT ${varname})
		message(FATAL_ERROR "Program '${progname}' is required but could not be found")
	endif()
endfunction()


list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Add external dependencies
set(ENABLE_UNIT_TESTS OFF)
add_subdirectory("submodules/externals/sofia-sip")
unset(ENABLE_UNIT_TESTS)

if(ENABLE_SOCI OR ENABLE_CONFERENCE_SERVER)
	set(SOCI_SHARED ON)
	set(SOCI_STATIC OFF)
	if (APPLE)
		set(SOCI_FRAMEWORK ON)
	endif()
	set(SOCI_TESTS OFF)
	set(SOCI_ASAN OFF)
	set(SOCI_EMPTY OFF)

	# Soci backends
	set(WITH_DB2 OFF)
	set(WITH_FIREBIRD OFF)
	set(WITH_MYSQL ON)
	set(WITH_ODBC OFF)
	set(WITH_ORACLE OFF)
	set(WITH_POSTGRESQL ON)
	set(WITH_SQLITE3 ON)
	set(WITH_THREAD_STACK_SIZE 0)
	set(WITH_VALGRIND OFF)

	set(SOCI_MYSQL ON)
	set(SOCI_POSTGRESQL ON)
	set(SOCI_SQLITE3 ON)
	add_subdirectory("linphone-sdk/external/soci")
endif()

if(ENABLE_JWE_AUTH_PLUGIN)
	add_subdirectory("submodules/externals/jose")
endif()

# Add Linphone SDK dependencies
set(DISABLE_BC_PACKAGE_SEARCH ON)
set(BCUNIT_TARGETNAME "bcunit")
set(BCTOOLBOX_CMAKE_UTILS_DIR "${CMAKE_CURRENT_BINARY_DIR}/linphone-sdk/bctoolbox")

## Global SDK config
set(ENABLE_SHARED ON)
set(ENABLE_STATIC OFF)
set(ENABLE_TOOLS OFF)
set(ENABLE_TEST OFF)
set(ENABLE_TESTS OFF)
set(ENABLE_DOC OFF)
set(ENABLE_PACKAGE_SOURCE OFF)

## BCunit specific config
set(ENABLE_AUTOMATED ON)
set(ENABLE_BASIC ON)
set(ENABLE_CONSOLE ON)
set(ENABLE_CURSES OFF)
set(ENABLE_MEMTRACE OFF)
set(ENABLE_DEPRECATED OFF)
add_subdirectory("linphone-sdk/bcunit")

## BcToolbox specific config
set(ENABLE_POLARSSL OFF)
set(ENABLE_MBEDTLS ON)
set(ENABLE_DECAF OFF)
set(ENABLE_TESTS_COMPONENT ${ENABLE_UNIT_TESTS})
add_subdirectory("linphone-sdk/bctoolbox")

## oRTP specific config
option(ENABLE_NTP_TIMESTAMP OFF)
option(ENABLE_PERF OFF)
option(ENABLE_DEBUG_LOGS OFF)
option(ENABLE_PACKAGE_SOURCE "Create 'package_source' target for source archive making (CMake >= 3.11)" OFF)
add_subdirectory("linphone-sdk/ortp")

## Belr specific config
add_subdirectory("linphone-sdk/belr")

## Mediastreamer specific config
if(ENABLE_TRANSCODER)
	set(ENABLE_DEBUG_LOGS OFF)
	set(ENABLE_FIXED_POINT "Turn on fixed point computations." OFF)
	set(ENABLE_NON_FREE_CODECS OFF)
	set(ENABLE_PCAP OFF)
	set(ENABLE_RELATIVE_PREFIX OFF)

	set(ENABLE_SRTP ON)
	set(ENABLE_ZRTP ON)

	set(ENABLE_SOUND OFF) # Disable all sound card backends.

	set(ENABLE_G726 OFF)
	set(ENABLE_GSM ON)
	set(ENABLE_BV16 OFF)
	set(ENABLE_OPUS ON)
	set(ENABLE_SPEEX_CODEC ON)
	set(ENABLE_SPEEX_DSP ON)
	set(ENABLE_G729 OFF) # Disable for lisence conformity
	set(ENABLE_G729B_CNG OFF) # Disalbe for lisence conformity
	set(ENABLE_RESAMPLE ON)

	set(ENABLE_VIDEO OFF)
	set(ENABLE_MKV OFF)
	set(ENABLE_JPEG OFF)
	add_subdirectory("linphone-sdk/mediastreamer2")
endif()

## Belle-sip specific config
if(ENABLE_PRESENCE OR ENABLE_MDNS OR ENABLE_CONFERENCE OR ENABLE_UNIT_TESTS)
	set(BELLESIP_TARGETNAME "bellesip")
	set(ENABLE_RTP_MAP_ALWAYS_IN_SDP OFF)
	set(ENABLE_TUNNEL OFF)

	# antlr3 settings
	set(ENABLE_64BIT  OFF)
	set(ENABLE_DEBUGGER OFF)

	add_subdirectory("linphone-sdk/belle-sip")
endif()

## Liblinphone specific config
if(ENABLE_CONFERENCE)
	set(DISABLE_SOCI_PACKAGE_SEARCH ON)

	set(ENABLE_ADVANCED_IM ON)
	set(ENABLE_CONSOLE_UI OFF)
	set(ENABLE_CSHARP_WRAPPER OFF)
	set(ENABLE_CXX_WRAPPER YES)
	set(ENABLE_DB_STORAGE YES)
	set(ENABLE_SWIFT_WRAPPER OFF)
	set(ENABLE_SWIFT_WRAPPER_COMPILATION OFF)
	set(ENABLE_JAZZY_DOC OFF)
	set(ENABLE_DAEMON OFF)
	set(ENABLE_DATE OFF)
	set(ENABLE_DEBUG_LOGS OFF)
	set(ENABLE_LIME_X3DH OFF)
	set(ENABLE_JAVA_WRAPPER OFF)
	set(ENABLE_JAVADOC OFF)
	set(ENABLE_LDAP OFF)
	set(ENABLE_LIME OFF)
	set(ENABLE_RELATIVE_PREFIX OFF)
	set(ENABLE_TUNNEL OFF)
	set(ENABLE_TUTORIALS OFF)
	set(ENABLE_UPDATE_CHECK OFF)
	set(ENABLE_VCARD OFF)
	set(ENABLE_VIDEO OFF)
	set(ENABLE_ASSETS OFF)

	set(ENABLE_UNIT_TESTS OFF)
	add_subdirectory("linphone-sdk/liblinphone")
	unset(ENABLE_UNIT_TESTS)
endif()


# Required packages

find_package(LibNgHttp2 REQUIRED)

find_package(XercesC)

check_function_exists(arc4random HAVE_ARC4RANDOM)
find_file(HAVE_SYS_PRCTL_H NAMES sys/prctl.h)

set(CMAKE_REQUIRED_LIBRARIES)

# Options
if(ENABLE_SNMP)
	# todo: Not quite ready
	FIND_PROGRAM_REQUIRED(NET_SNMP_PROG net-snmp-config)
	find_path(NET_SNMP_INCLUDE_DIRS NAMES net-snmp/net-snmp-config.h)
	if(NOT NET_SNMP_INCLUDE_DIRS)
		message(FATAL_ERROR "SNMP header files not found")
	endif()

	execute_process(COMMAND "${NET_SNMP_PROG}" "--agent-libs" OUTPUT_VARIABLE NET_SNMP_LIBRARIES OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()

if(ENABLE_SPECIFIC_FEATURES)
	set(MEDIARELAY_SPECIFIC_FEATURES_ENABLED ON)
endif()

if(ENABLE_MONOTONIC_CLOCK_REGISTRATIONS)
	set(MONOTONIC_CLOCK_REGISTRATIONS ON)
endif()

if(ENABLE_DATEHANDLER)
	set(HAVE_DATEHANDLER ON)
endif()

if(ENABLE_REDIS)
	find_package(Hiredis REQUIRED)
	if(NOT HIREDIS_ASYNC_ENABLED)
		message(FATAL_ERROR "Hiredis needs support for async commands")
	endif()
endif()

if(ENABLE_PROTOBUF)
	find_package(Protobuf REQUIRED)
	# package finder for protobuf does not exit on REQUIRED..
	if(NOT PROTOBUF_FOUND)
		message(FATAL_ERROR "Protobuf not found and is required")
	endif()
	if(NOT PROTOBUF_PROTOC_EXECUTABLE)
		message(FATAL_ERROR "Protobuf 'protoc' executable not found and is required")
	endif()
endif()

if(ENABLE_PDFDOC)
	FIND_PROGRAM_REQUIRED(PDFLATEX_PROG pdflatex)
endif()

find_path(MSGPACK_INCLUDE_DIRS NAMES msgpack.hpp HINTS /usr/local/include)
if(MSGPACK_INCLUDE_DIRS)
	message(STATUS "MSGPACK found")
	add_definitions("-DENABLE_MSGPACK")
	set(ENABLE_MSGPACK 1)
else()
	message(STATUS "MSGPACK not found")
endif()


find_package(OpenSSL 0.9.8 REQUIRED)

feature_summary(WHAT ALL INCLUDE_QUIET_PACKAGES FATAL_ON_MISSING_REQUIRED_PACKAGES)

include_directories(
	include/
	src/
	src/plugin
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_CURRENT_BINARY_DIR}/src/
	${ORTP_INCLUDE_DIRS}
	${SOFIASIPUA_INCLUDE_DIRS}
)

set(BELR_GRAMMARS_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/belr/grammars")

configure_file(${PROJECT_SOURCE_DIR}/cmake/flexisip-config.h.in ${PROJECT_BINARY_DIR}/flexisip-config.h)
set_source_files_properties(${PROJECT_BINARY_DIR}/flexisip-config.h PROPERTIES GENERATED ON)
add_definitions("-DHAVE_CONFIG_H")

# -Werror=varargs seems to do false positives with GCC 4.9.x
bc_init_compilation_flags(CPP_BUILD_FLAGS C_BUILD_FLAGS CXX_BUILD_FLAGS ENABLE_STRICT)
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION MATCHES "^4\\.9\\.[0-9]+$")
	list(APPEND CXX_BUILD_FLAGS "-Wno-error=varargs")
endif()

add_subdirectory(include)
add_subdirectory(src)
add_subdirectory(scripts)
add_subdirectory(share)

if(ENABLE_UNIT_TESTS)
	add_subdirectory(tester)
endif()

# Packaging
add_subdirectory(build)
