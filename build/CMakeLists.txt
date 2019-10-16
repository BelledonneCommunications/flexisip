############################################################################
# CMakeLists.txt
# Copyright (C) 2017-2018  Belledonne Communications, Grenoble France
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

if (NOT CPACK_PACKAGE_NAME)
	set(CPACK_PACKAGE_NAME "flexisip")
endif()

set(CPACK_SOURCE_PACKAGE_FILE_NAME ${CPACK_PACKAGE_NAME}-${PROJECT_VERSION})
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_IGNORE_FILES
	"${CMAKE_BINARY_DIR}"
	"^${PROJECT_SOURCE_DIR}/linphone-sdk"
	"^${PROJECT_SOURCE_DIR}/submodules*"
	"^${PROJECT_SOURCE_DIR}/WORK*"
	"^${PROJECT_SOURCE_DIR}/.git*"
)

# In case we need to decompose the version
if (FLEXISIP_VERSION MATCHES "^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(-[.0-9A-Za-z-]+)?([+][.0-9A-Za-z-]+)?$")
	set( version_major "${CMAKE_MATCH_1}" )
	set( version_minor "${CMAKE_MATCH_2}" )
	set( version_patch "${CMAKE_MATCH_3}" )
	set( identifiers   "${CMAKE_MATCH_4}" )
	set( metadata      "${CMAKE_MATCH_5}" )
endif()

set(RPM_VERSION ${version_major}.${version_minor}.${version_patch})
if (NOT identifiers)
	set(RPM_RELEASE 1)
else()
	string(SUBSTRING "${identifiers}" 1 -1 identifiers)
	set(RPM_RELEASE "0.${identifiers}${metadata}")
endif()

message("-- Package file name is ${CPACK_PACKAGE_FILE_NAME}" )

bc_generate_rpm_specfile("rpm/flexisip.spec.cmake" "${PROJECT_SOURCE_DIR}/flexisip.spec")

include(CPack)

