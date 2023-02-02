############################################################################
# CMakeLists.txt
# Copyright (C) 2010-2023 Belledonne Communications, Grenoble France
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
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
find_package(jsoncpp "1.1.0" REQUIRED)

# Generate flexisip-tester-config.h
set(FLEXISIP_TESTER_DATA_SRCDIR "${CMAKE_CURRENT_SOURCE_DIR}")
find_program(REDIS_SERVER_EXEC NAMES redis-server REQUIRED)
configure_file(flexisip-tester-config.hh.in flexisip-tester-config.hh)

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
)

add_executable(flexisip_tester
	agent-tester.cc
	boolean-expressions.cc
	cli-tester.cc
	domain-registration-tester.cc
	extended-contact-tester.cc
	${CMAKE_CURRENT_BINARY_DIR}/flexisip-tester-config.hh flexisip-tester-config.hh.in
	fork-call-tester.cc
	fork-context-tester.cc
	mediarelay-tester.cc
	module-dos-tester.cc
	module-info-tester.cc
	module-pushnotification-tester.cc
	module-registrar-tester.cc
	module-router-tester.cc
	module-toolbox-tester.cc
    msg-sip-tester.cc
	register-tester.cc
	registrardb-tester.cc
	registrardb-redis-tester.cc
	sip-uri-tests.cc
	schedule-injector-tester.cc
	sofia-tester.cc
	sofia-driven-signal-handler-tester.cc
	tester.cc
	thread-pool-tester.cc
	tls-connection-tester.cc
	utils-tester.cc
	utils/asserts.hh
	utils/bellesip-utils.cc utils/bellesip-utils.hh
	utils/client-core.cc utils/client-core.hh
	utils/listening-socket.cc utils/listening-socket.hh
	utils/proxy-server.cc utils/proxy-server.hh
	utils/proxy-server-process.cc utils/proxy-server-process.hh
	utils/redis-server.cc utils/redis-server.hh
	utils/tcp-server.cc utils/tcp-server.hh
	utils/test-patterns/agent-test.hh
	utils/test-patterns/test.hh
	utils/tls-server.cc utils/tls-server.hh
	utils/utf8-string-tester.cc
)

if (ENABLE_CONFERENCE)
	target_sources(flexisip_tester PRIVATE registration-event-tester.cc)
	target_sources(flexisip_tester PRIVATE conference-tester.cc)
endif ()

if (ENABLE_UNIT_TESTS_MYSQL)
	target_sources(flexisip_tester PRIVATE
		fork-context-mysql-tester.cc
	)
endif(ENABLE_UNIT_TESTS_MYSQL)

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
	jsoncpp_lib
	hiredis
)

if (LIBNGHTTP2ASIO_FOUND AND ENABLE_UNIT_TESTS_PUSH_NOTIFICATION)
	target_link_libraries(flexisip_tester PRIVATE LibNgHttp2Asio)
endif ()

install(TARGETS flexisip_tester
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	RESOURCE DESTINATION ${CMAKE_INSTALL_DATADIR}/flexisip-tester
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

set(FLEXISIP_TESTER_INSTALL_DATADIR "${CMAKE_INSTALL_DATADIR}/flexisip-tester")
install(DIRECTORY cert config db sounds images
	DESTINATION ${FLEXISIP_TESTER_INSTALL_DATADIR}
)
