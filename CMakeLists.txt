############################################################################
# CMakeLists.txt
# Copyright (C) 2014  Belledonne Communications, Grenoble France
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

cmake_minimum_required(VERSION 3.2.0 FATAL_ERROR) # 3.2.0 required for target_compile_features support on gcc 4.4+ (centos6)

project(flexisip C CXX)

set(FLEXISIP_MAJOR_VERSION "1")
set(FLEXISIP_MINOR_VERSION "0")
set(FLEXISIP_MICRO_VERSION "13")
set(FLEXISIP_VERSION "${FLEXISIP_MAJOR_VERSION}.${FLEXISIP_MINOR_VERSION}.${FLEXISIP_MICRO_VERSION}")
set(PROJECT_VERSION ${FLEXISIP_VERSION})

include(CMakePushCheckState)
include(CMakeDependentOption)
include(CheckSymbolExists)
include(CheckFunctionExists)
include(FeatureSummary)
include(CheckCXXSourceCompiles)
include(GNUInstallDirs)

option(ENABLE_STRICT "Pass strict flags to the compiler" YES)
option(ENABLE_DATEHANDLER "Build DateHandler module" NO)
option(ENABLE_PDFDOC "Build pdf documentation" NO)
option(ENABLE_MONOTONIC_CLOCK_REGISTRATIONS "Enable monotonic clock for registrations" NO)
option(ENABLE_ODBC "Build ODBC support for database connection" NO)
option(ENABLE_PRESENCE "Build presence support" NO)
option(ENABLE_CONFERENCE "Build conference support" NO)
option(ENABLE_PROTOBUF "Build with protobuf support" NO)
option(ENABLE_REDIS "Build with Redis support" NO)
option(ENABLE_SNMP "Build with SNMP support" NO)
option(ENABLE_SOCI "Build with SOCI support" YES)
option(ENABLE_STATIC "Build static library (default is shared library)." NO)
option(ENABLE_TRANSCODER "Build transcoder support" YES)
option(ENABLE_MDNS "Build multicast DNS support" NO)
option(ENABLE_EXTERNAL_AUTH_PLUGIN "Enable ExternalAuth plugin support" NO)
option(ENABLE_JWE_AUTH_PLUGIN "Enable JweAuth plugin support" NO)

cmake_dependent_option(ENABLE_SPECIFIC_FEATURES "Enable mediarelay specific features" OFF "ENABLE_TRANSCODER" OFF)

find_package(Threads)

if(NOT CMAKE_INSTALL_RPATH AND CMAKE_INSTALL_PREFIX)
	set(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_FULL_LIBDIR})
	message(STATUS "Setting install rpath to ${CMAKE_INSTALL_RPATH}")
endif()

set(SYSCONF_INSTALL_DIR ${CMAKE_INSTALL_FULL_SYSCONFDIR} CACHE STRING "Config directory, the place where flexisip expects its flexisip.conf file to reside" )


set(CONFIG_DIR ${SYSCONF_INSTALL_DIR}/flexisip)
message(STATUS "Config dir: ${CONFIG_DIR}")

function(FIND_PROGRAM_REQUIRED varname progname)
	find_program(${varname} NAMES "${progname}")
	if(NOT ${varname})
		message(FATAL_ERROR "Program '${progname}' is required but could not be found")
	endif()
endfunction()


list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Required packages
find_package(SofiaSipUa 1.13.11 REQUIRED) #find_package only allow numbers
if(LINPHONE_BUILDER_GROUP_EXTERNAL_SOURCE_PATH_BUILDERS)
	include("${EP_ortp_CONFIG_DIR}/ORTPConfig.cmake")
else()
	find_package(ORTP 0.21 REQUIRED)
endif()

find_package(BcToolbox 0.0.3 REQUIRED)
find_package(Belr REQUIRED)

find_package(LibXsd)

check_function_exists(arc4random HAVE_ARC4RANDOM)
find_file(HAVE_SYS_PRCTL_H NAMES sys/prctl.h)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
	if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.7)
		message(STATUS "GCC version < 4.7: use MONOTONIC clock")
		add_definitions(-DUSE_MONOTONIC_CLOCK)
	else()
		message(STATUS "GCC version ${CMAKE_CXX_COMPILER_VERSION} should have steady_clock")
	endif()
endif()

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

if(ENABLE_ODBC)
	FIND_PROGRAM_REQUIRED(ODBC_PROG odbc_config)
	execute_process(COMMAND "${ODBC_PROG}" "--libs" OUTPUT_VARIABLE ODBC_LIBRARIES OUTPUT_STRIP_TRAILING_WHITESPACE)
	execute_process(COMMAND "${ODBC_PROG}" "--cflags" OUTPUT_VARIABLE ODBC_CFLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)
	execute_process(COMMAND "${ODBC_PROG}" "--include-prefix" OUTPUT_VARIABLE ODBC_INCLUDE_DIRS OUTPUT_STRIP_TRAILING_WHITESPACE)
	execute_process(COMMAND "${ODBC_PROG}" "--lib-prefix" OUTPUT_VARIABLE ODBC_LIBRARY_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)
	message(STATUS "ODBC libraries: ${ODBC_LIBRARIES}")
	message(STATUS "ODBC headers: ${ODBC_CFLAGS}")

	# check SQL headers
	find_path(ODBC_SQL_HEADERS NAMES sql.h sqlext.h sqltypes.h mysql/mysql.h PATHS ODBC_INCLUDE_DIRS)
	if(NOT ODBC_SQL_HEADERS)
		message(FATAL_ERROR "ODBC Mysql headers not found.")
	else()
		message(STATUS "ODBC Mysql ${ODBC_SQL_HEADERS}")
	endif()

	# check that odbc_config gives us a correct library path
	find_library(ODBC_LIB_FOUND NAMES odbc PATHS ODBC_LIBRARY_DIR)
	if(NOT ODBC_LIB_FOUND)
		message(FATAL_ERROR "ODBC library not found.")
	endif()
endif()

if(ENABLE_TRANSCODER)
	find_package(Mediastreamer2 2.9.0 REQUIRED)
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

if(ENABLE_PRESENCE OR ENABLE_MDNS)
		# disable Presence on gcc < 4.7 because c++11 is not supported well before
		if (CMAKE_COMPILER_IS_GNUCXX AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.7)
				message(WARNING "Disable Presence because GCC is too old")
				set(ENABLE_PRESENCE OFF)
		endif()

	if(LINPHONE_BUILDER_GROUP_EXTERNAL_SOURCE_PATH_BUILDERS)
		include("${EP_bellesip_CONFIG_DIR}/BelleSIPConfig.cmake")
	else()
		find_package(BelleSIP 1.2.4 REQUIRED)
	endif()
endif()

if(ENABLE_CONFERENCE)
	if(LINPHONE_BUILDER_GROUP_EXTERNAL_SOURCE_PATH_BUILDERS)
		include("${EP_bellesip_CONFIG_DIR}/BelleSIPConfig.cmake")
		include("${EP_linphone_CONFIG_DIR}/LinphoneConfig.cmake")
		include("${EP_linphone_CONFIG_DIR}/wrappers/cpp/LinphoneCxxConfig.cmake")
	else ()
		find_package(BelleSIP 1.2.4 REQUIRED)
		find_package(Linphone REQUIRED)
		find_package(LinphoneCxx REQUIRED)
	endif()
endif()

if(ENABLE_SOCI)
	find_package(Soci REQUIRED COMPONENTS mysql)
	find_path(SOCI_MYSQL_INCLUDES NAMES mysql.h PATH_SUFFIXES mysql HINTS $ENV{MYSQL_DIR}/include /usr/include/mariadb /usr/local/include)
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

bc_init_compilation_flags(CPP_BUILD_FLAGS C_BUILD_FLAGS CXX_BUILD_FLAGS ENABLE_STRICT)

add_subdirectory(include)
add_subdirectory(src)
add_subdirectory(scripts)
add_subdirectory(share)
add_subdirectory(tester)

# Packaging
add_subdirectory(build)
