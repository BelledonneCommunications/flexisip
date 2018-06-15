############################################################################
# FindJose.cmake
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
# - Find Jose include files and library
#
#  JOSE_FOUND        - System has jose
#  JOSE_INCLUDE_DIRS - The jose include directories
#  JOSE_LIBRARIES    - The libraries needed to use jose

find_package(PkgConfig QUIET)
pkg_check_modules(PC_JOSE QUIET jose)

find_path(JOSE_INCLUDE_DIRS
	NAMES jose/jose.h
	HINTS ${PC_JOSE_INCLUDE_DIRS}
)
find_library(JOSE_LIBRARIES
	NAMES jose
	HINTS ${PC_JOSE_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Jose REQUIRED_VARS JOSE_INCLUDE_DIRS JOSE_LIBRARIES)

mark_as_advanced(JOSE_INCLUDE_DIRS JOSE_LIBRARIES)
