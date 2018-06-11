############################################################################
# CMakeLists.txt
# Copyright (C) 2014-2018  Belledonne Communications, Grenoble France
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

project(jwe-auth-plugin VERSION 1.0.0)

set(JWE_AUTH_SOURCES
	jwe-auth-plugin.cc
)

find_package(Jansson REQUIRED)
find_package(Jose REQUIRED)

set(JWE_AUTH_LIBRARIES
	${FLEXISIP_LIBS}
	${JANSSON_LIBRARIES}
	${JOSE_LIBRARIES}
)

set(JWE_AUTH_INCLUDES
	${FLEXISIP_INCLUDES}
	${JANSSON_INCLUDE_DIR}
	${JOSE_INCLUDE_DIR}
)

add_library(jweauth SHARED ${JWE_AUTH_SOURCES})
set_target_properties(jweauth PROPERTIES VERSION ${PROJECT_VERSION})

target_link_libraries(jweauth ${JWE_AUTH_LIBRARIES})
target_include_directories(jweauth PUBLIC ${JWE_AUTH_INCLUDES})

install(TARGETS jweauth
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}/flexisip/plugins"
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}/flexisip/plugins"
	ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}/flexisip/plugins"
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)
