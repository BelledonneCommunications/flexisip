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

# logrotate conf
set(logrotate_dir "${SYSCONF_INSTALL_DIR}/logrotate.d")
install(FILES flexisip-logrotate DESTINATION "${logrotate_dir}")
set(FLEXISIP_LOGROTATE_INSTALL_LOCATION "${logrotate_dir}/flexisip-logrotate" PARENT_SCOPE)


# legacy script
set(bindir ${CMAKE_INSTALL_FULL_BINDIR})
message("-- Startup scripts configured with bindir=${bindir}")
configure_file(redhat/flexisip.in redhat/flexisip)
configure_file(debian/flexisip.in debian/flexisip)

if(ENABLE_PRESENCE)
	configure_file(redhat/flexisip-presence.in redhat/flexisip-presence)
	configure_file(debian/flexisip-presence.in debian/flexisip-presence)
endif()


# systemd
set(systemd_services "flexisip-proxy.service" "flexisip-proxy@.service" "flexisip-linphone-daemon.service")
if(ENABLE_PRESENCE)
	list(APPEND systemd_services "flexisip-presence.service" "flexisip-presence@.service")
endif()
if(ENABLE_CONFERENCE)
	list(APPEND systemd_services
		"flexisip-conference.service"
		"flexisip-conference@.service"
		"flexisip-regevent.service"
		"flexisip-regevent@.service"
	)
endif()
if(ENABLE_B2BUA)
	list(APPEND systemd_services
		"flexisip-b2bua.service"
		"flexisip-b2bua@.service"
	)
endif()
set(FLEXISIP_SYSTEMD_SERVICES ${systemd_services} PARENT_SCOPE)

foreach(service ${systemd_services})
	configure_file("${service}.in" "${service}")
	list(APPEND generated_services "${CMAKE_CURRENT_BINARY_DIR}/${service}")
endforeach()

install(FILES ${generated_services} DESTINATION "${FLEXISIP_SYSTEMD_INSTALL_DIR}")


# flexisip_cli.py
install(PROGRAMS flexisip_cli.py DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(PROGRAMS firebase_v1_get_access_token.py DESTINATION ${CMAKE_INSTALL_DATADIR}/flexisip)