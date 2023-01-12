############################################################################
# ExternalDependencies.cmake
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

############################################################################
# Add some external dependencies as subproject
############################################################################

# Add subdirectory for DECAF, needed for full support of ZRTP
# add_subdirectory("linphone-sdk/external/decaf")

# Configure and add SofiaSip
set(ENABLE_UNIT_TESTS OFF)
add_subdirectory("submodules/externals/sofia-sip")
unset(ENABLE_UNIT_TESTS)

# Add libhiredis
if(ENABLE_REDIS AND INTERNAL_LIBHIREDIS)
	add_subdirectory("submodules/externals/hiredis")
	target_compile_definitions(hiredis INTERFACE "INTERNAL_LIBHIREDIS")
endif()

# Configure and add Soci
if(ENABLE_SOCI OR ENABLE_LIBLINPHONE)
	if(BUILD_SHARED_LIBS)
		set(SOCI_SHARED ON)
		set(SOCI_STATIC OFF)
	else()
		set(SOCI_SHARED OFF)
		set(SOCI_STATIC ON)
	endif()
	set(SOCI_FRAMEWORK OFF)
	set(SOCI_TESTS OFF)
	set(SOCI_ASAN OFF)
	set(SOCI_INSTALL_BACKEND_TARGETS OFF) # Setting this option to ON cause an obscure error while first cmake invokation.
                                          # CMake Error: install(EXPORT "LinphoneTargets" ...) includes target "linphone"
                                          #   which requires target "soci_core" that is not in this export set, but
                                          #   in multiple other export sets: cmake/SOCI.cmake, cmake/SOCI.cmake,
                                          #   cmake/SOCI.cmake, cmake/SOCI.cmake.
	set(SOCI_EMPTY OFF)

	# Soci backends
	set(WITH_DB2 OFF)
	set(WITH_FIREBIRD OFF)
	set(WITH_MYSQL ON)
	set(WITH_ODBC OFF)
	set(WITH_ORACLE OFF)
	set(WITH_POSTGRESQL ${ENABLE_SOCI_POSTGRESQL_BACKEND})
	set(WITH_SQLITE3 ON)
	set(WITH_THREAD_STACK_SIZE 0)
	set(WITH_VALGRIND OFF)

	set(SOCI_MYSQL ON)
	set(SOCI_POSTGRESQL ${WITH_POSTGRESQL})
	set(SOCI_SQLITE3 ON)
	add_subdirectory("linphone-sdk/external/soci")
endif()

# Configure and add Jose
if(ENABLE_JWE_AUTH_PLUGIN)
	add_subdirectory("submodules/externals/jose")
endif()

# Configure and add mbedtls
if(INTERNAL_MBEDTLS)
	if(BUILD_SHARED_LIBS)
		set(USE_SHARED_MBEDTLS_LIBRARY ON)
		set(USE_STATIC_MBEDTLS_LIBRARY OFF)
	else()
		set(USE_SHARED_MBEDTLS_LIBRARY OFF)
		set(USE_STATIC_MBEDTLS_LIBRARY ON)
	endif()
	set(ENABLE_PROGRAMS OFF)
	set(ENABLE_TESTING OFF)
	set(MBEDTLS_FATAL_WARNINGS ${ENABLE_STRICT_LINPHONESDK})
	add_subdirectory("linphone-sdk/external/mbedtls")
endif()

# Configure and add SRTP2
if(INTERNAL_LIBSRTP2)
	set(TEST_APPS OFF CACHE BOOL "Build test applications" FORCE)
	set(ENABLE_MBEDTLS ON CACHE BOOL "Use Mbedtls backend" FORCE)
	add_subdirectory("linphone-sdk/external/srtp")
endif()
