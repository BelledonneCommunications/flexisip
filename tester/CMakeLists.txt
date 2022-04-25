############################################################################
# CMakeLists.txt
# Copyright (C) 2010-2022 Belledonne Communications, Grenoble France
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

find_package(Threads REQUIRED)
find_package(LibNgHttp2Asio)
find_package(Boost COMPONENTS system REQUIRED)

# Generate flexisip-tester-config.h
set(TESTER_DATA_DIR "${CMAKE_INSTALL_PREFIX}/share/flexisip-tester")
find_program(REDIS_SERVER_EXEC NAMES redis-server REQUIRED)
configure_file(flexisip-tester-config.hh.in flexisip-tester-config.hh)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_executable(flexisip_tester
        agent-tester.cc
        boolean-expressions.cc
        extended-contact-tester.cc
        fork-call-tester.cc
        fork-context-tester.cc
        fork-context-mysql-tester.cc
        module-pushnotification-tester.cc
        module-info-tester.cc
        register-tester.cc
        registrardb-tester.cc
        router-tester.cc
        tester.cc
        tls-connection-tester.cc
        utils/bellesip-utils.cc
        utils/listening-socket.cc
        utils/redis-server.cc
        utils/tcp-server.cc
        utils/tls-server.cc
        utils/client-core.cc
        utils/proxy-server.cc
        )

if (ENABLE_CONFERENCE)
    target_sources(flexisip_tester PRIVATE registration-event-tester.cc)
    target_sources(flexisip_tester PRIVATE conference-tester.cc)
endif ()

if (LIBNGHTTP2ASIO_FOUND AND ENABLE_UNIT_TESTS_PUSH_NOTIFICATION)
    target_sources(flexisip_tester PRIVATE push-notification-tester.cc utils/pns-mock.cc)
elseif (ENABLE_UNIT_TESTS_PUSH_NOTIFICATION)
    message(FATAL_ERROR "Module LibNgHttp2Asio is required for push notification tester. Either install it or disable push notification tester using -DENABLE_UNIT_TESTS_PUSH_NOTIFICATION=OFF")
endif ()

if (ENABLE_B2BUA)
    target_sources(flexisip_tester PRIVATE b2bua-tester.cc)
endif ()

target_compile_options(flexisip_tester PRIVATE ${CPP_BUILD_FLAGS} ${CXX_BUILD_FLAGS})
target_link_libraries(flexisip_tester PRIVATE
        Boost::system
        OpenSSL::Crypto
        OpenSSL::SSL
        Threads::Threads
        bctoolbox-tester
        bellesip
        flexisip
        linphone
        linphone++
        mediastreamer
        ortp
)
if (LIBNGHTTP2ASIO_FOUND AND ENABLE_UNIT_TESTS_PUSH_NOTIFICATION)
    target_link_libraries(flexisip_tester PRIVATE LibNgHttp2Asio)
endif ()

install(TARGETS flexisip_tester
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
        )

install(DIRECTORY cert
        DESTINATION ${TESTER_DATA_DIR}
        )

install(DIRECTORY config
        DESTINATION ${TESTER_DATA_DIR}
        )

install(DIRECTORY db
        DESTINATION ${TESTER_DATA_DIR}
        )

install(DIRECTORY sounds
        DESTINATION ${TESTER_DATA_DIR}
        )

install(DIRECTORY images
        DESTINATION ${TESTER_DATA_DIR}
        )
