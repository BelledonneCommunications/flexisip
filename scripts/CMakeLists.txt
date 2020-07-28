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
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/debian/flexisip.in ${CMAKE_CURRENT_BINARY_DIR}/debian/flexisip)

if (ENABLE_PRESENCE)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/redhat/flexisip-presence.in ${CMAKE_CURRENT_BINARY_DIR}/redhat/flexisip-presence)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/debian/flexisip-presence.in ${CMAKE_CURRENT_BINARY_DIR}/debian/flexisip-presence)
endif()


#systemd
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/flexisip-proxy.service.in ${CMAKE_CURRENT_BINARY_DIR}/flexisip-proxy.service)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/flexisip-proxy@.service.in ${CMAKE_CURRENT_BINARY_DIR}/flexisip-proxy@.service)

if (ENABLE_PRESENCE)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/flexisip-presence.service.in ${CMAKE_CURRENT_BINARY_DIR}/flexisip-presence.service)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/flexisip-presence@.service.in ${CMAKE_CURRENT_BINARY_DIR}/flexisip-presence@.service)
endif()
if (ENABLE_CONFERENCE)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/flexisip-conference.service.in ${CMAKE_CURRENT_BINARY_DIR}/flexisip-conference.service)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/flexisip-conference@.service.in ${CMAKE_CURRENT_BINARY_DIR}/flexisip-conference@.service)
endif()
if (ENABLE_REGEVENT)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/flexisip-regevent.service.in ${CMAKE_CURRENT_BINARY_DIR}/flexisip-regevent.service)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/flexisip-regevent@.service.in ${CMAKE_CURRENT_BINARY_DIR}/flexisip-regevent@.service)
endif()
