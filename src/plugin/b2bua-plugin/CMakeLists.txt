############################################################################
# CMakeLists.txt
# Copyright (C) 2020  Belledonne Communications, Grenoble France
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

project(b2bua-plugin VERSION 1.0.0)

set(B2BUA_SOURCES
	b2bua.cpp
)

set(B2BUA_LIBRARIES
	flexisip
	bctoolbox
)

add_library(b2bua SHARED ${B2BUA_SOURCES})
set_property(TARGET b2bua PROPERTY VERSION ${PROJECT_VERSION})
set_property(TARGET b2bua PROPERTY CXX_STANDARD 14)
set_property(TARGET b2bua PROPERTY CXX_STANDARD_REQUIRED ON)

target_link_libraries(b2bua PRIVATE ${B2BUA_LIBRARIES})
target_include_directories(b2bua PRIVATE ${B2BUA_INCLUDES})
add_dependencies(b2bua flexisip-git-version)

install(TARGETS b2bua
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}/flexisip/plugins"
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}/flexisip/plugins"
	ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}/flexisip/plugins"
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)
