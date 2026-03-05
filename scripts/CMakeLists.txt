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

# systemd
set(systemd_services "proxy")
if(ENABLE_PRESENCE)
    list(APPEND systemd_services "presence")
endif()
if(ENABLE_CONFERENCE)
    list(APPEND systemd_services "conference" "regevent")
endif()
if(ENABLE_B2BUA)
    list(APPEND systemd_services "b2bua")
endif()
if(ENABLE_VOICEMAIL)
    list(APPEND systemd_services "voicemail")
endif()

# service configuration files
foreach(service ${systemd_services})
    set(after "")
    if(service MATCHES "proxy")
        set(description "Flexisip proxy server")
        set(after " redis.service mysqld.service mariadb.service")
    elseif(service MATCHES "presence")
        set(description "Flexisip presence server")
        set(after " redis.service mysqld.service mariadb.service")
    elseif(service MATCHES "conference")
        set(description "Flexisip conference server")
        set(after " redis.service mysqld.service mariadb.service")
    elseif(service MATCHES "regevent")
        set(description "Flexisip RegEvent server")
        set(after " redis.service")
    elseif(service MATCHES "b2bua")
        set(description "Flexisip Back-to-back user agent server")
        set(after " redis.service")
    elseif(service MATCHES "voicemail")
        set(description "Flexisip Voicemail server")
    endif()
    set(service_description "${description}")
    set(service_after "${after}")
    set(service_execstart "${bindir}/flexisip --server ${service} --disable-stdout --syslog --pidfile /var/run/flexisip-${service}.pid")
    set(service_filename "flexisip-${service}.service")
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/flexisip.service.in"
        "${CMAKE_CURRENT_BINARY_DIR}/${service_filename}"
    )
    list(APPEND generated_services "${CMAKE_CURRENT_BINARY_DIR}/${service_filename}")

    # template file
    set(service_description  "${description} - %i instance")
    set(service_after "${after}")
    set(service_execstart "/opt/belledonne-communications/bin/flexisip --server ${service} --disable-stdout --syslog --pidfile /var/run/flexisip-${service}/%i.pid -c /etc/flexisip/%i.conf")
    set(service_filename_at "flexisip-${service}@.service")
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/flexisip.service.in"
        "${CMAKE_CURRENT_BINARY_DIR}/${service_filename_at}"
    )
    list(APPEND generated_services "${CMAKE_CURRENT_BINARY_DIR}/${service_filename_at}")
endforeach()

# linphone daemon
set(linphone_service_file "flexisip-linphone-daemon.service")
configure_file("${linphone_service_file}.in" "${linphone_service_file}")
list(APPEND generated_services "${CMAKE_CURRENT_BINARY_DIR}/${linphone_service_file}")


install(FILES ${generated_services} DESTINATION "${FLEXISIP_SYSTEMD_INSTALL_DIR}")

# flexisip_cli.py
install(PROGRAMS flexisip_cli.py DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(PROGRAMS firebase_v1_get_access_token.py DESTINATION ${CMAKE_INSTALL_DATADIR}/flexisip)