############################################################################
# FindLibNgHttp2Asio.cmake
# Copyright (C) 2010-2021  Belledonne Communications, Grenoble France
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
# Find libnghttp2_asio and defined the associated target.
#
# Target name: LibNgHttp2Asio

include(FindPackageHandleStandardArgs)

find_path(LIBNGHTTP2ASIO_INCLUDE_DIR nghttp2/asio_http2.h)
find_library(LIBNGHTTP2ASIO_LIBRARY nghttp2_asio)

find_package_handle_standard_args(LibNgHttp2Asio REQUIRED_VARS LIBNGHTTP2ASIO_INCLUDE_DIR LIBNGHTTP2_LIBRARY)

if (LIBNGHTTP2ASIO_FOUND)
	add_library(LibNgHttp2Asio SHARED IMPORTED)
	set_target_properties(LibNgHttp2Asio PROPERTIES
		INTERFACE_INCLUDE_DIRECTORIES "${LIBNGHTTP2ASIO_INCLUDE_DIR}"
		IMPORTED_LOCATION "${LIBNGHTTP2ASIO_LIBRARY}"
	)
	target_link_libraries(LibNgHttp2Asio INTERFACE LibNgHttp2)
endif()

unset(NGHTTP2_ASIO_INCLUDE_DIR)
unset(NGHTTP2_ASIO_LIBRARY)