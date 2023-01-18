############################################################################
# CMakeLists.txt
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

project(external-auth-plugin VERSION 1.0.0)

add_library(external-auth SHARED
	external-auth-module.cc
	module-external-authentication.cc
)

# Fix for https://gcc.gnu.org/bugzilla/show_bug.cgi?id=105562
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU"
		AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 12
		AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 13)
	set_source_files_properties(external-auth-module.cc PROPERTIES COMPILE_OPTIONS "-Wno-error=maybe-uninitialized")
endif ()

set_property(TARGET external-auth PROPERTY VERSION ${PROJECT_VERSION})

target_link_libraries(external-auth PRIVATE flexisip sofia-sip-ua)
target_compile_options(external-auth PRIVATE ${CPP_BUILD_FLAGS} ${CXX_BUILD_FLAGS})
add_dependencies(external-auth flexisip-git-version)

install(TARGETS external-auth
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}/flexisip/plugins"
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}/flexisip/plugins"
	ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}/flexisip/plugins"
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)
