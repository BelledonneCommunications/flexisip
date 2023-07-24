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
find_package(XercesC REQUIRED)
find_package(Boost COMPONENTS system REQUIRED)
find_package(jsoncpp "1.1.0" REQUIRED)
find_package(LibNgHttp2Asio)

# Some tests need SDK clients able to stream video (mostly those of the B2BUA).
# Mediastreamer2 does not enforce any video codec, resulting in tests crashing at runtime.
# We prefer to detect this at configure time, so we're enforcing VPX
list(APPEND CMAKE_MODULE_PATH ${flexisip_SOURCE_DIR}/linphone-sdk/mediastreamer2/cmake/)
find_package(VPX REQUIRED)

# Generate flexisip-tester-config.h
set(FLEXISIP_TESTER_DATA_SRCDIR "${CMAKE_CURRENT_SOURCE_DIR}")
find_program(REDIS_SERVER_EXEC NAMES redis-server REQUIRED)
find_program(MYSQL_SERVER_EXEC NAMES mysqld
	PATHS /usr/libexec # CentOS, Rocky
	REQUIRED
)

get_filename_component(MYSQL_BIN_DIR "${MYSQL_SERVER_EXEC}" DIRECTORY)
find_file(MYSQL_SYSTEM_TABLES_SETUP NAMES mysql_system_tables.sql PATHS
	"${MYSQL_BIN_DIR}/../share/mysql"
	"${MYSQL_BIN_DIR}/../share/mariadb"
REQUIRED)

find_program(CAT_EXEC NAMES cat REQUIRED)
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
	tests/callcontext-mediarelay-tester.cc
	tests/eventlogs/events/event-log-stats-tester.cc
	tests/flexiapi/schemas/iso-8601-date-tester.cc
	tests/presence/presence-pidf-tester.cc
	tests/presence/presence-publish-tester.cc
	tests/presence/xsd-utils-tester.cc
	tests/pushnotification/rfc8599-push-params-tester.cc
	tests/pushnotification/service-tester.cc
	tests/sofia-wrapper/home-tester.cc
	thread-pool-tester.cc
	tls-connection-tester.cc
	utils-tester.cc
	utils/asserts.hh
	utils/bellesip-utils.cc utils/bellesip-utils.hh
	utils/call-builder.cc utils/call-builder.hh
	utils/chat-room-builder.cc utils/chat-room-builder.hh
	utils/client-builder.cc utils/client-builder.hh
	utils/client-call.cc utils/client-call.hh
	utils/client-core.cc utils/client-core.hh
	utils/eventlogs/event-logs.cc utils/eventlogs/event-logs.hh
	utils/eventlogs/writers/event-log-writer-visitor-adapter.hh
	utils/listening-socket.cc utils/listening-socket.hh
	utils/mysql-server.cc utils/mysql-server.hh
	utils/posix-process-tester.cc
	utils/proxy-server.cc utils/proxy-server.hh
	utils/proxy-server-process.cc utils/proxy-server-process.hh
	utils/redis-server.cc utils/redis-server.hh
	utils/tcp-server.cc utils/tcp-server.hh
	utils/test-patterns/agent-test.hh
	utils/test-patterns/presence-test.hh
	utils/test-patterns/test.hh
	utils/tls-server.cc utils/tls-server.hh
	utils/tmp-dir.cc utils/tmp-dir.hh
	utils/utf8-string-tester.cc
)

if (ENABLE_CONFERENCE)
	target_sources(flexisip_tester PRIVATE
		registration-event-tester.cc
		tests/conference/conference-server-tester.cc
		utils/test-conference-server.cc utils/test-conference-server.hh
	)
endif ()

if (ENABLE_SOCI)
	target_sources(flexisip_tester PRIVATE
		fork-context-mysql-tester.cc
		tests/eventlogs/writers/database-event-log-writer-tester.cc
	)
endif()

if (LIBNGHTTP2ASIO_FOUND AND ENABLE_UNIT_TESTS_NGHTTP2ASIO)
	target_sources(flexisip_tester PRIVATE
		push-notification-tester.cc
		tests/flexiapi/flexi-stats-tester.cc
		tests/utils/transport/http/rest-client-tester.cc
		utils/http-mock/http-mock.cc utils/http-mock/http-mock.hh
		utils/pns-mock.cc utils/pns-mock.hh
	)
	if(HAS_GCC_BUG_105562)
		set_source_files_properties(
			push-notification-tester.cc
			utils/pns-mock.cc
			PROPERTIES COMPILE_OPTIONS "-Wno-error=maybe-uninitialized"
		)
	endif()
elseif (ENABLE_UNIT_TESTS_NGHTTP2ASIO)
	message(FATAL_ERROR "The LibNgHttp2Asio module is required by some tests. You may disable them with -DENABLE_UNIT_TESTS_NGHTTP2ASIO=OFF")
endif ()

if(ENABLE_CONFERENCE AND ENABLE_UNIT_TESTS_NGHTTP2ASIO)
	target_sources(flexisip_tester PRIVATE
		tests/eventlogs/writers/flexi-stats-event-log-writer-tester.cc
	)
	if(HAS_GCC_BUG_105562)
		set_source_files_properties(
			tests/eventlogs/writers/flexi-stats-event-log-writer-tester.cc
			PROPERTIES COMPILE_OPTIONS "-Wno-error=maybe-uninitialized"
		)
	endif ()
endif()


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
	XercesC::XercesC
)

if (LIBNGHTTP2ASIO_FOUND AND ENABLE_UNIT_TESTS_NGHTTP2ASIO)
	target_link_libraries(flexisip_tester PRIVATE LibNgHttp2Asio)
endif ()

target_include_directories(flexisip_tester PRIVATE "${PROJECT_SOURCE_DIR}/libxsd")

install(TARGETS flexisip_tester
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	RESOURCE DESTINATION ${CMAKE_INSTALL_DATADIR}/flexisip-tester
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

set(FLEXISIP_TESTER_INSTALL_DATADIR "${CMAKE_INSTALL_DATADIR}/flexisip-tester")
install(DIRECTORY cert config sounds images
	DESTINATION ${FLEXISIP_TESTER_INSTALL_DATADIR}
)
