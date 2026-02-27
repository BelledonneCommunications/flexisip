############################################################################
# FindLibSystemD.cmake
# Copyright (C) 2010-2026  Belledonne Communications, Grenoble France
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
# Find libsystemd and defined the associated target.
#
# Target name: LibSystemD

include(FindPackageHandleStandardArgs)

find_path(LIBSYSTEMD_INCLUDE_DIR
	NAMES systemd/sd-daemon.h
	)
find_library(LIBSYSTEMD_LIBRARY
	NAMES systemd libsystemd
	)

find_package_handle_standard_args(LibSystemD REQUIRED_VARS LIBSYSTEMD_INCLUDE_DIR LIBSYSTEMD_LIBRARY)

if (LIBSYSTEMD_FOUND)
	add_library(LibSystemD SHARED IMPORTED)
	set_target_properties(LibSystemD PROPERTIES
		INTERFACE_INCLUDE_DIRECTORIES "${LIBSYSTEMD_INCLUDE_DIR}"
		IMPORTED_LOCATION "${LIBSYSTEMD_LIBRARY}"
	)
endif()

unset(LIBSYSTEMD_INCLUDE_DIR)
unset(LIBSYSTEMD_LIBRARY)

