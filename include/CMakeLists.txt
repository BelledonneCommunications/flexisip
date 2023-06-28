############################################################################
# CMakeLists.txt
# Copyright (C) 2019 Belledonne Communications, Grenoble France
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

find_package(Git)

set(gitversion_script "${CMAKE_CURRENT_SOURCE_DIR}/gitversion.cmake")
set(workdir "${CMAKE_CURRENT_SOURCE_DIR}")
set(outputdir "${CMAKE_CURRENT_BINARY_DIR}/flexisip")
set(flexisip_version_h "${outputdir}/flexisip-version.h")

add_custom_target(flexisip-git-version ALL
	COMMAND ${CMAKE_COMMAND} -DGIT_EXECUTABLE=${GIT_EXECUTABLE} -DFLEXISIP_VERSION=${FLEXISIP_VERSION}
		-DWORK_DIR=${workdir} -DOUTPUT_DIR=${outputdir} -P "${gitversion_script}"
	BYPRODUCTS "${flexisip_version_h}"
)

install(DIRECTORY flexisip DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES "${flexisip_version_h}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/flexisip")

if(HAS_GCC_BUG_105562)
	set_source_files_properties(flexisip/expressionparser-impl.cc PROPERTIES COMPILE_OPTIONS "-Wno-error=maybe-uninitialized")
endif()