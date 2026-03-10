############################################################################
# CMakeLists.txt
# Copyright (C) 2010-2026 Belledonne Communications, Grenoble France
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
############################################################################

find_package(Threads REQUIRED)
find_package(XercesC REQUIRED)

find_package(Boost 1.69)
if(Boost_FOUND)
	set(BOOST_TARGET Boost::headers)
else()
	find_package(Boost COMPONENTS system REQUIRED)
	set(BOOST_TARGET Boost::system)
endif()

# TODO Change back to lowercase `jsoncpp` when (if) the SDK decides to use it as well
# https://linphone.atlassian.net/browse/SDK-184
find_package(JsonCPP "1.1.0" REQUIRED)
find_package(LibNgHttp2Asio)

# Some tests need SDK clients able to stream video (mostly those of the B2BUA).
# Mediastreamer2 does not enforce any video codec, resulting in tests crashing at runtime.
# We prefer to detect this at configure time, so we're enforcing VPX
list(APPEND CMAKE_MODULE_PATH ${flexisip_SOURCE_DIR}/linphone-sdk/mediastreamer2/cmake/)
find_package(VPX REQUIRED)

# Generate flexisip-tester-config.h
set(FLEXISIP_ROOT_DIR "${CMAKE_SOURCE_DIR}")
set(FLEXISIP_BIN_DIR "${CMAKE_BINARY_DIR}")
set(FLEXISIP_TESTER_DATA_SRCDIR "${CMAKE_CURRENT_SOURCE_DIR}")

find_program(REDIS_SERVER_EXEC NAMES redis-server REQUIRED)

# Search first for mariadb
find_program(MYSQL_SERVER_EXEC NAMES mariadbd
		PATHS /usr/libexec # CentOS, Rocky
)
# Then search for mysqld if mariadbd was not found
if(NOT MYSQL_SERVER_EXEC)
	find_program(MYSQL_SERVER_EXEC NAMES mysqld
		PATHS /usr/libexec # CentOS, Rocky
		REQUIRED
	)
	# With some versions, mariadb-server only comes with a mysqld executable file, so we need to check "--version"
	execute_process(
			COMMAND ${MYSQL_SERVER_EXEC} --version
			OUTPUT_VARIABLE MYSQL_VERSION_OUTPUT
			ERROR_VARIABLE MYSQL_VERSION_OUTPUT
	)
	if(MYSQL_VERSION_OUTPUT MATCHES "MariaDB")
		set(IS_MARIADB TRUE)
	else()
		set(IS_MARIADB FALSE)
	endif()
else()
	set(IS_MARIADB TRUE)
endif()

if(IS_MARIADB)
	add_compile_definitions(MARIADB_SERVER)

	# Only check for system_tables files with mariadb, this is not used for MySQL.
	get_filename_component(MYSQL_BIN_DIR "${MYSQL_SERVER_EXEC}" DIRECTORY)
	find_file(MYSQL_SYSTEM_TABLES_SETUP
			NAMES "mariadb_system_tables.sql" "mysql_system_tables.sql"
			HINTS "${MYSQL_BIN_DIR}/.."
			PATHS ${CMAKE_SYSTEM_PREFIX_PATH}
			PATH_SUFFIXES "share/mysql" "share/mariadb"
			REQUIRED
			NO_DEFAULT_PATH
	)
endif()

find_program(SQUID_EXEC NAMES squid REQUIRED)
find_program(BASIC_NCSA_AUTH_EXEC NAMES basic_ncsa_auth HINTS "/usr/lib/squid" "/usr/lib64/squid" REQUIRED)

find_program(CAT_EXEC NAMES cat REQUIRED)
configure_file(flexisip-tester-config.hh.in flexisip-tester-config.hh)

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
)

add_subdirectory(utils)
if(NOT BUILD_AS_LIB)
	add_subdirectory(tests)
endif()
