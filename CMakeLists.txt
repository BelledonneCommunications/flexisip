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
include("cmake/FlexisipUtils.cmake")

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
add_ccache_option(ON)
cmake_dependent_option(ENABLE_SPECIFIC_FEATURES "Enable mediarelay specific features" OFF "ENABLE_TRANSCODER" OFF)
option(INTERNAL_LIBHIREDIS "Build libhiredis source code present as Flexisip submodule instead of searching it in system libraries" OFF)
option(INTERNAL_LIBSRTP2 "Build SRTP2 source code present as linphone-sdk submodule instead of searching it in system libraries" OFF)
set(CPACK_GENERATOR "" CACHE STRING "Generator to use for making package. Supported values: 'RPM', 'DEB'")
set(SYSCONF_INSTALL_DIR "" CACHE STRING
	"Config directory, the place where flexisip expects its flexisip.conf file to reside. Always equal to '${CMAKE_INSTALL_FULL_SYSCONFDIR}' if empty."
)
set(FLEXISIP_SYSTEMD_INSTALL_DIR "" CACHE STRING
	"Where to install the SystemD units. Always equal to '${CMAKE_INSTALL_FULL_DATAROOTDIR}/systemd/system' if empty."
)

# Handle the default value of installation paths. That ensures that they are
# always relative to the install prefix when the user hasn't set them explicitly.
if(SYSCONF_INSTALL_DIR STREQUAL "")
	set(SYSCONF_INSTALL_DIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}")
endif()
if(FLEXISIP_SYSTEMD_INSTALL_DIR STREQUAL "")
	set(FLEXISIP_SYSTEMD_INSTALL_DIR "${CMAKE_INSTALL_FULL_DATAROOTDIR}/systemd/system")
endif()


# Require C++14
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


find_package(Threads)

if(NOT CMAKE_INSTALL_RPATH AND CMAKE_INSTALL_PREFIX)
	set(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_FULL_LIBDIR})
	message(STATUS "Setting install rpath to ${CMAKE_INSTALL_RPATH}")
endif()

set(CONFIG_DIR "${SYSCONF_INSTALL_DIR}/flexisip")
message(STATUS "Config dir: ${CONFIG_DIR}")

set(INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
if(ENABLE_UNIT_TESTS)
	set(TESTER_DATA_DIR ${CMAKE_INSTALL_PREFIX}/share/flexisip-tester)
	find_program(REDIS_SERVER_EXEC NAMES redis-server REQUIRED)
endif()

function(FIND_PROGRAM_REQUIRED varname progname)
	find_program(${varname} NAMES "${progname}")
	if(NOT ${varname})
		message(FATAL_ERROR "Program '${progname}' is required but could not be found")
	endif()
endfunction()


list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

include("cmake/ExternalDependencies.cmake")
include("cmake/LinphoneSDK.cmake")

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

if(ENABLE_REDIS AND NOT INTERNAL_LIBHIREDIS)
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

# Allow to use SLOGD and LOGD macros.
add_definitions("-DBCTBX_DEBUG_MODE")


find_package(OpenSSL 0.9.8 REQUIRED)

feature_summary(WHAT ALL INCLUDE_QUIET_PACKAGES FATAL_ON_MISSING_REQUIRED_PACKAGES)

include_directories(
	"include"
	"src"
	"src/plugin"
	"src/presence"
	"${CMAKE_CURRENT_BINARY_DIR}"
	"${CMAKE_CURRENT_BINARY_DIR}/include"
	"${CMAKE_CURRENT_BINARY_DIR}/src"
)

set(BELR_GRAMMARS_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/belr/grammars")

configure_file(cmake/flexisip-config.h.in flexisip-config.h)
set_source_files_properties(${PROJECT_BINARY_DIR}/flexisip-config.h PROPERTIES GENERATED ON)
add_compile_definitions("HAVE_CONFIG_H")

# -Werror=varargs seems to do false positives with GCC 4.9.x
bc_init_compilation_flags(CPP_BUILD_FLAGS C_BUILD_FLAGS CXX_BUILD_FLAGS ENABLE_STRICT)
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION MATCHES "^4\\.9\\.[0-9]+$")
	list(APPEND CXX_BUILD_FLAGS "-Wno-error=varargs")
endif()
add_compile_options(${CPP_BUILD_FLAGS} ${CXX_BUILD_FLAGS})

add_subdirectory(include)
add_subdirectory(src)
add_subdirectory(scripts)
add_subdirectory(share)

if(ENABLE_UNIT_TESTS)
	add_subdirectory(tester)
endif()

# Packaging
add_subdirectory(packaging)
