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

set_property(TARGET external-auth PROPERTY VERSION ${PROJECT_VERSION})
set_property(TARGET external-auth PROPERTY CXX_STANDARD 11)
set_property(TARGET external-auth PROPERTY CXX_STANDARD_REQUIRED ON)

target_link_libraries(external-auth ${FLEXISIP_LIBS})
target_include_directories(external-auth PUBLIC ${FLEXISIP_INCLUDES})
target_compile_options(external-auth PRIVATE ${CPP_BUILD_FLAGS} ${CXX_BUILD_FLAGS})

install(TARGETS external-auth
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}/flexisip/plugins"
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}/flexisip/plugins"
	ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}/flexisip/plugins"
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)
