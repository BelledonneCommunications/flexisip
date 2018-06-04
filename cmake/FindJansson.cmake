############################################################################
# FindJansson.cmake
# Copyright (C) 2018  Belledonne Communications, Grenoble France
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
# - Find Jansson include files and library
#
#  JANSSON_FOUND        - System has jansson
#  JANSSON_INCLUDE_DIRS - The jansson include directories
#  JANSSON_LIBRARIES    - The libraries needed to use jansson

find_package(PkgConfig QUIET)
pkg_check_modules(PC_JANSSON QUIET jansson)

find_path(JANSSON_INCLUDE_DIR
	NAMES jansson.h
	HINTS ${PC_JANSSON_INCLUDE_DIRS}
)
find_library(JANSSON_LIBRARY
	NAMES jansson
	HINTS ${PC_JANSSON_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Jansson REQUIRED_VARS JANSSON_INCLUDE_DIR JANSSON_LIBRARY)

if(JANSSON_FOUND)
	set(JANSSON_LIBRARIES ${JANSSON_LIBRARY})
	set(JANSSON_INCLUDE_DIRS ${JANSSON_INCLUDE_DIR})
endif()

mark_as_advanced(JANSSON_INCLUDE_DIR JANSSON_LIBRARY)
