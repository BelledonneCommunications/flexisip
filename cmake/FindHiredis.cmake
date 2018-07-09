############################################################################
# FindHiredis.cmake
# Copyright (C) 2017  Belledonne Communications, Grenoble France
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
#
# - Find the libhiredis library
#
#  HIREDIS_FOUND - system has libhiredis
#  HIREDIS_INCLUDE_DIRS - the libhiredis include directory
#  HIREDIS_LIBRARIES - The libraries needed to use libhiredis
#  HIREDIS_ASYNC_ENABLED - The found libhiredis library supports async commands


find_path(HIREDIS_INCLUDE_DIRS
	NAMES hiredis/hiredis.h
	PATH_SUFFIXES include
)

find_library(HIREDIS_LIBRARIES
	NAMES hiredis
)

if(HIREDIS_INCLUDE_DIRS AND HIREDIS_LIBRARIES)
	# check that the async mode is supported
	cmake_push_check_state(RESET)
	list(APPEND CMAKE_REQUIRED_INCLUDES ${HIREDIS_INCLUDE_DIRS})
	list(APPEND CMAKE_REQUIRED_LIBRARIES ${HIREDIS_LIBRARIES})
	check_symbol_exists("redisAsyncCommand" "hiredis/async.h" HIREDIS_ASYNC_ENABLED)
	cmake_pop_check_state()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Hiredis
	DEFAULT_MSG
	HIREDIS_INCLUDE_DIRS HIREDIS_LIBRARIES
)

mark_as_advanced(HIREDIS_INCLUDE_DIRS HIREDIS_LIBRARIES HIREDIS_ASYNC_ENABLED)
