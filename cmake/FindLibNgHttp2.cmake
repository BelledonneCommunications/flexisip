############################################################################
# FindNgHttp2.cmake
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
#
# Find libnghttp2 and defined the associated target.
#
# Target name: LibNgHttp2

include(FindPackageHandleStandardArgs)

find_path(LIBNGHTTP2_INCLUDE_DIR nghttp2.h PATH_SUFFIXES include/nghttp2)
find_library(LIBNGHTTP2_LIBRARY NAMES libnghttp2.so)

find_package_handle_standard_args(LibNgHttp2 REQUIRED_VARS LIBNGHTTP2_INCLUDE_DIR LIBNGHTTP2_LIBRARY)

if (LIBNGHTTP2_FOUND)
	add_library(LibNgHttp2 SHARED IMPORTED)
	set_target_properties(LibNgHttp2 PROPERTIES
		INTERFACE_INCLUDE_DIRECTORIES "${LIBNGHTTP2_INCLUDE_DIR}"
		IMPORTED_LOCATION "${LIBNGHTTP2_LIBRARY}"
	)
endif()

unset(NGHTTP2_INCLUDE_DIR)
unset(NGHTTP2_LIBRARY)

