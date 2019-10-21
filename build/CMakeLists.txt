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

set(CPACK_SOURCE_IGNORE_FILES
	"./linphone-sdk"
	"./submodules*"
	"./WORK*"
	"./OUTPUT*"
	"./.*"
)

bc_generate_rpm_specfile(rpm/flexisip.spec.cmake rpm/flexisip.spec.cmake)

add_custom_target(flexisip-spec
	COMMAND ${CMAKE_COMMAND}
		"-DBCTOOLBOX_CMAKE_UTILS=${BCTOOLBOX_CMAKE_UTILS}"
		"-DPROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}"
		"-DCMAKE_CURRENT_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
		-P "${CMAKE_CURRENT_SOURCE_DIR}/rpm/gen-flexisip-spec.cmake"
	BYPRODUCTS "${PROJECT_SOURCE_DIR}/flexisip.spec"
)

add_custom_target(package_source
	COMMAND ${CMAKE_COMMAND}
		"-DBCTOOLBOX_CMAKE_UTILS=${BCTOOLBOX_CMAKE_UTILS}"
		"-Dflexisip_SOURCE_DIR='${flexisip_SOURCE_DIR}'"
		"-Dflexisip_BINARY_DIR='${flexisip_BINARY_DIR}'"
		"-DCPACK_PACKAGE_NAME='${CPACK_PACKAGE_NAME}'"
		"-DEXCLUDE_PATTERNS='${CPACK_SOURCE_IGNORE_FILES}'"
		-P "${CMAKE_CURRENT_SOURCE_DIR}/MakeArchive.cmake"
	DEPENDS flexisip-spec
)
