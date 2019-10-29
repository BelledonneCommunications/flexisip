############################################################################
# MakeArchive.cmake
# Copyright (C) 2010-2019  Belledonne Communications, Grenoble France
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

include("${BCTOOLBOX_CMAKE_UTILS}")
bc_compute_full_version(version)
set(archive_name "${CPACK_PACKAGE_NAME}-${version}")
set(archive_path "${PROJECT_BINARY_DIR}/${archive_name}.tar.gz")

find_program(TAR tar)

set(EXCLUDE_ARGS )
foreach (pattern ${EXCLUDE_PATTERNS})
	list(APPEND EXCLUDE_ARGS "--exclude=${pattern}")
endforeach()

execute_process(COMMAND ${TAR} -C "${PROJECT_SOURCE_DIR}" -cz -f "${archive_path}" "--transform" "s,^\\.,${archive_name}," ${EXCLUDE_ARGS} .)
