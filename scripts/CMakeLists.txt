############################################################################
# CMakeLists.txt
# Copyright (C) 2017  Belledonne Communications, Grenoble France
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

#legacy script
set(bindir ${CMAKE_INSTALL_FULL_BINDIR})
message ("-- Startup scripts configured with bindir=${bindir}")
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/redhat/flexisip.in ${CMAKE_CURRENT_BINARY_DIR}/redhat/flexisip)
#install(FILES ${CMAKE_CURRENT_BINARY_DIR}/redhat/flexisip DESTINATION "scripts/redhat")
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/debian/flexisip.in ${CMAKE_CURRENT_BINARY_DIR}/debian/flexisip)
#install(FILES ${CMAKE_CURRENT_BINARY_DIR}/debian/flexisip DESTINATION "scripts/debian")

if (PRESENCE_ENABLE)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/redhat/flexisip-presence.in ${CMAKE_CURRENT_BINARY_DIR}/redhat/flexisip-presence)
#	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/redhat/flexisip-presence DESTINATION "scripts/redhat")
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/debian/flexisip-presence.in ${CMAKE_CURRENT_BINARY_DIR}/debian/flexisip-presence)
#	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/debian/flexisip-presence DESTINATION "scripts/debian")
endif()


#systemd
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/flexisip.service.in ${CMAKE_CURRENT_BINARY_DIR}/flexisip.service)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/flexisip@.service.in ${CMAKE_CURRENT_BINARY_DIR}/flexisip@.service)
#install(FILES 
#	${CMAKE_CURRENT_BINARY_DIR}/flexisip.service
#	${CMAKE_CURRENT_BINARY_DIR}/flexisip@.service 
#	DESTINATION "scripts")

if (PRESENCE_ENABLE)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/flexisip-presence.service.in ${CMAKE_CURRENT_BINARY_DIR}/flexisip-presence.service)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/flexisip-presence@.service.in ${CMAKE_CURRENT_BINARY_DIR}/flexisip-presencei@.service)
#	install(FILES 
#		${CMAKE_CURRENT_BINARY_DIR}/flexisipi-presence.service
#		${CMAKE_CURRENT_BINARY_DIR}/flexisipi-presence@.service 
#		DESTINATION "scripts")
endif()

