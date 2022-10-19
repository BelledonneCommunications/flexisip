############################################################################
# CMakeLists.txt
# Copyright (C) 2010-2022  Belledonne Communications, Grenoble France
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

# CMake 3.3 is required for the usage of IN_LIST operator in if() command.
cmake_minimum_required(VERSION 3.13)

# CMP0076 is required to use relative path in target_sources
cmake_policy(SET CMP0076 NEW)
# CMP0077 is required to correctly force the value of subprojects' cache variables.
cmake_policy(SET CMP0077 NEW)

# Require C++14
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Ensure compiler optimizations are off when compiling in debug mode
set(CMAKE_C_FLAGS_DEBUG_INIT "-O0")
set(CMAKE_CXX_FLAGS_DEBUG_INIT "-O0")

# Add 'Sanitizer' CMake build type.
# MUST be before project declaration.
set(CMAKE_C_FLAGS_SANITIZER_INIT "-g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer")
set(CMAKE_CXX_FLAGS_SANITIZER_INIT "-g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer")

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
option(ENABLE_STRICT_LINPHONESDK "Pass strict flags to the compiler for all Linphone SDK submodules" ON)
option(ENABLE_DATEHANDLER "Build DateHandler module" OFF)
option(ENABLE_PDFDOC "Build PDF documentation" OFF)
option(ENABLE_MONOTONIC_CLOCK_REGISTRATIONS "Enable monotonic clock for registrations" OFF)
option(ENABLE_PRESENCE "Build presence support" ON)
option(ENABLE_CONFERENCE "Build conference support" ON)
option(ENABLE_PROTOBUF "Build with Protobuf support" ON)
option(ENABLE_REDIS "Build with Redis support" ON)
option(ENABLE_SNMP "Build with SNMP support" ON)
option(ENABLE_SOCI "Build with SOCI support" ON)
option(ENABLE_SOCI_POSTGRESQL_BACKEND "Build with SOCI Postgre sql backend support" ON)
option(ENABLE_TRANSCODER "Build transcoder support" ON)
option(ENABLE_MDNS "Build multicast DNS support" OFF)
option(ENABLE_EXTERNAL_AUTH_PLUGIN "Enable ExternalAuth plugin support" ON)
option(ENABLE_JWE_AUTH_PLUGIN "Enable JweAuth plugin support" ON)
option(ENABLE_B2BUA "Enable Back2back user agent support" ON)
option(ENABLE_UNIT_TESTS "Enable Flexisip unit tests (low level tests)" OFF)
cmake_dependent_option(ENABLE_UNIT_TESTS_PUSH_NOTIFICATION "Enable flexisip push notification unit tests (requires libnghttp2_asio)"  ON "ENABLE_UNIT_TESTS" ON )
option(ENABLE_UNIT_TESTS_MYSQL "Enable flexisip unit tests that use mysql" OFF)
add_ccache_option(ON)
option(ENABLE_COVERAGE "Enable flexisip clang test coverage reports (add instrumentation)" OFF )
cmake_dependent_option(ENABLE_SPECIFIC_FEATURES "Enable media relay specific features" OFF "ENABLE_TRANSCODER" OFF)
option(INTERNAL_LIBHIREDIS "Build libhiredis source code present as Flexisip submodule instead of searching it in system libraries" OFF)
option(INTERNAL_LIBSRTP2 "Build SRTP2 source code present as linphone-sdk submodule instead of searching it in system libraries" ON)
option(INTERNAL_JSONCPP "Build and use vendored Jsoncpp source code instead of searching for it in system libraries" OFF)
set(CPACK_GENERATOR "" CACHE STRING "Generator to use for making package. Supported values: 'RPM', 'DEB'")
set(SYSCONF_INSTALL_DIR "" CACHE STRING
	"Configuration directory, the place where Flexisip expects its flexisip.conf file to reside. Always equal to '${CMAKE_INSTALL_FULL_SYSCONFDIR}' if empty."
)
set(FLEXISIP_SYSTEMD_INSTALL_DIR "" CACHE STRING
	"Where to install the SystemD units. Always equal to '${CMAKE_INSTALL_FULL_DATAROOTDIR}/systemd/system' if empty."
)

# Place the built libraries and executables in top level directories 'lib' and 'bin' in the build tree.
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib" CACHE PATH "Archive output dir.")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib" CACHE PATH "Library output dir.")
set(CMAKE_PDB_OUTPUT_DIRECTORY     "${CMAKE_BINARY_DIR}/bin" CACHE PATH "PDB (MSVC debug symbol)output dir.")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin" CACHE PATH "Executable/dll output dir.")

# Advanced options (i.e. hidden to the user by default)
option(ENABLE_LIBLINPHONE_TESTER "Build liblinphone_tester executable." OFF)
mark_as_advanced(ENABLE_LIBLINPHONE_TESTER)

# Handle the default value of installation paths. That ensures that they are
# always relative to the install prefix when the user hasn't set them explicitly.
if(SYSCONF_INSTALL_DIR STREQUAL "")
	set(SYSCONF_INSTALL_DIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}")
endif()
if(FLEXISIP_SYSTEMD_INSTALL_DIR STREQUAL "")
	set(FLEXISIP_SYSTEMD_INSTALL_DIR "${CMAKE_INSTALL_FULL_DATAROOTDIR}/systemd/system")
endif()

# Build libflexisip and all its dependencies as shared libraries
set(BUILD_SHARED_LIBS ON)

if(NOT CMAKE_INSTALL_RPATH AND CMAKE_INSTALL_PREFIX)
	set(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_FULL_LIBDIR})
	message(STATUS "Setting install rpath to ${CMAKE_INSTALL_RPATH}")
endif()

set(CONFIG_DIR "${SYSCONF_INSTALL_DIR}/flexisip")
message(STATUS "Config dir: ${CONFIG_DIR}")

set(INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

function(FIND_PROGRAM_REQUIRED varname progname)
	find_program(${varname} NAMES "${progname}")
	if(NOT ${varname})
		message(FATAL_ERROR "Program '${progname}' is required but could not be found")
	endif()
endfunction()


list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

set(INTERNAL_MBEDTLS ON)
include("cmake/ExternalDependencies.cmake")
include("cmake/LinphoneSDK.cmake")

# Required packages

find_package(LibNgHttp2 REQUIRED)
find_package(Threads)
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
	find_package(Hiredis 0.14 REQUIRED)
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
