############################################################################
# CMakeLists.txt
# Copyright (C) 2010-2025 Belledonne Communications, Grenoble France
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
# TODO Change back to lowercase `jsoncpp` when (if) the SDK decides to use it as well
# https://linphone.atlassian.net/browse/SDK-184
find_package(JsonCPP "1.1.0" REQUIRED)
find_package(LibNgHttp2Asio)

# Some tests need SDK clients able to stream video (mostly those of the B2BUA).
# Mediastreamer2 does not enforce any video codec, resulting in tests crashing at runtime.
# We prefer to detect this at configure time, so we're enforcing VPX
list(APPEND CMAKE_MODULE_PATH ${flexisip_SOURCE_DIR}/linphone-sdk/mediastreamer2/cmake/)
find_package(VPX REQUIRED)

# Generate flexisip-tester-config.h
set(FLEXISIP_ROOT_DIR "${CMAKE_SOURCE_DIR}")
set(FLEXISIP_BIN_DIR "${CMAKE_BINARY_DIR}")
set(FLEXISIP_TESTER_DATA_SRCDIR "${CMAKE_CURRENT_SOURCE_DIR}")
find_program(REDIS_SERVER_EXEC NAMES redis-server REQUIRED)
find_program(MYSQL_SERVER_EXEC NAMES mysqld
	PATHS /usr/libexec # CentOS, Rocky
	REQUIRED
)

get_filename_component(MYSQL_BIN_DIR "${MYSQL_SERVER_EXEC}" DIRECTORY)
find_file(MYSQL_SYSTEM_TABLES_SETUP
	NAMES "mariadb_system_tables.sql" "mysql_system_tables.sql"
	HINTS "${MYSQL_BIN_DIR}/.."
	PATHS ${CMAKE_SYSTEM_PREFIX_PATH}
	PATH_SUFFIXES "share/mysql" "share/mariadb"
	REQUIRED
	NO_DEFAULT_PATH
)

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
	${CMAKE_CURRENT_BINARY_DIR}/flexisip-tester-config.hh flexisip-tester-config.hh.in
	fork-call-tester.cc
	fork-context-tester.cc
	mediarelay-tester.cc
	module-dos-tester.cc
	module-info-tester.cc
	module-router-tester.cc
	module-toolbox-tester.cc
	msg-sip-tester.cc
	sip-uri-tests.cc
	schedule-injector-tester.cc
	sofia-tester.cc
	sofia-driven-signal-handler-tester.cc
	tester.cc
	tests/auth/auth-digest-tester.cc
	tests/auth/auth-domains-tester.cc
	tests/auth/auth-tls-client-tester.cc
	tests/auth/auth-trusted-hosts-tester.cc
	tests/auth/module-authorization-tester.cc
	tests/auth/rsa-keys.hh
	tests/callcontext-mediarelay-tester.cc
	tests/configmanager-tester.cc
	tests/eventlogs/events/auth-log-tester.cc
	tests/eventlogs/events/event-id-tester.cc
	tests/eventlogs/events/event-log-stats-tester.cc
	tests/flexiapi/schemas/iso-8601-date-tester.cc
	tests/integration/domotic-tester.cc
	tests/libhiredis-wrapper/redis-async-session-tester.cc
	tests/libhiredis-wrapper/redis-reply-tester.cc
	tests/libhiredis-wrapper/replication/redis-client-tester.cc
	tests/module-forward-tester.cc
	tests/main-tester.cc
	tests/module-nat-helper-tester.cc
	tests/module-registrar-tester.cc
	tests/nat/contact-correction-strategy-helper-tester.cc
	tests/nat/contact-correction-strategy-tester.cc
	tests/nat/flow-token-strategy-tester.cc
	tests/nat/nat-traversal-feature-tester.cc
	tests/nat/nat-traversal-strategy-helper-tester.cc
	tests/presence/presence-pidf-tester.cc
	tests/presence/presence-publish-tester.cc
	tests/presence/xsd-utils-tester.cc
	tests/pushnotification/access-token-provider-tester.cc
	tests/pushnotification/authentication-manager-tester.cc
	tests/pushnotification/rfc8599-push-params-tester.cc
	tests/pushnotification/module-pushnotification-tester.cc
	tests/pushnotification/notify-pushnotification-tester.cc
	tests/pushnotification/service-tester.cc
	tests/registrar/extended-contact-tester.cc
	tests/registrar/register-tester.cc
	tests/registrar/registrardb-tester.cc
	tests/registrar/registrardb-redis-tester.cc
	tests/sofia-wrapper/home-tester.cc
	tests/sofia-wrapper/sip-header-tester.cc
	tests/transaction/outgoing-transaction-tester.cc
	tests/transaction/transaction-tester.cc
	tests/utils/cast-to-const-tester.cc
	tests/utils/flow-data-tester.cc
	tests/utils/flow-factory-tester.cc
	tests/utils/flow-tester.cc
	tests/utils/flow-factory-helper-tester.cc
	tests/utils/limited-unordered-map-tester.cc
	tests/utils/socket-address-tester.cc
	tests/utils/soft-ptr-tester.cc
	tests/utils/transport/http/http1client-tester.cc
	thread-pool-tester.cc
	tls-connection-tester.cc
	utils-tester.cc
	utils/asserts.hh
	utils/bellesip-utils.cc utils/bellesip-utils.hh
	utils/call-builder.cc utils/call-builder.hh
	utils/call-listeners.cc utils/call-listeners.hh
	utils/chat-room-builder.cc utils/chat-room-builder.hh
	utils/client-builder.cc utils/client-builder.hh
	utils/client-call.cc utils/client-call.hh
	utils/client-core.cc utils/client-core.hh
	utils/contact-inserter.cc utils/contact-inserter.hh
	utils/custom-user-agent-behavior.hh
	utils/eventlogs/event-logs.cc utils/eventlogs/event-logs.hh
	utils/eventlogs/writers/event-log-writer-visitor-adapter.hh
	utils/flow-test-helper.cc utils/flow-test-helper.hh
	utils/http-mock/http1-mock.cc utils/http-mock/http1-mock.hh
	utils/listening-socket.cc utils/listening-socket.hh
	utils/nat-test-helper.cc utils/nat-test-helper.hh
	utils/posix-process-tester.cc
	utils/server/injected-module-info.cc utils/server/injected-module-info.hh
	utils/server/mysql-server.cc utils/server/mysql-server.hh
	utils/server/proxy-server.cc utils/server/proxy-server.hh
	utils/server/redis-server.cc utils/server/redis-server.hh
	utils/server/tcp-server.cc utils/server/tcp-server.hh
	utils/server/tls-server.cc utils/server/tls-server.hh
	utils/test-patterns/agent-test.hh
	utils/test-patterns/presence-test.hh
	utils/test-patterns/test.hh
	utils/tls/private-key.cc utils/tls/private-key.hh
	utils/tls/certificate.cc utils/tls/certificate.hh
	utils/tmp-dir.cc utils/tmp-dir.hh
	utils/utf8-string-tester.cc
)

if(ENABLE_CONFERENCE OR ENABLE_B2BUA)
	target_sources(flexisip_tester PRIVATE
		tests/utils/configuration/media.cc
		tests/utils/configuration/transport.cc
	)
endif()

if(ENABLE_CONFERENCE)
	target_sources(flexisip_tester PRIVATE
		registration-event-tester.cc
		tests/conference/conference-server-tester.cc
		utils/server/regevent-server.cc utils/server/regevent-server.hh
		utils/server/test-conference-server.cc utils/server/test-conference-server.hh
	)
endif()

if(ENABLE_SOCI)
	target_sources(flexisip_tester PRIVATE
		fork-context-mysql-tester.cc
		tests/auth/db/authdb-soci-tester.cc
		tests/eventlogs/writers/database-event-log-writer-tester.cc
		tests/presence/list-subscription/external-list-subscription-tester.cc
		tests/utils/soci-helper-tester.cc
	)
endif()

if(LIBNGHTTP2ASIO_FOUND AND ENABLE_UNIT_TESTS_NGHTTP2ASIO)
	target_sources(flexisip_tester PRIVATE
		tests/auth/module-authorization-FAM-tester.cc
		tests/pushnotification/global-push-tester.cc
		tests/pushnotification/push-notification-tester.cc tests/pushnotification/push-notification-tester.hh
		tests/utils/transport/http/rest-client-tester.cc
		tests/utils/transport/http/http2client-tester.cc
		utils/http-mock/http-mock.cc utils/http-mock/http-mock.hh
		utils/pns-mock.cc utils/pns-mock.hh
	)
	if(ENABLE_FLEXIAPI)
		target_sources(flexisip_tester PRIVATE
			tests/flexiapi/flexi-stats-tester.cc
			tests/pushnotification/push-notification-flexiapi-tester.cc
		)
	endif()

	if(HAS_GCC_BUG_105562)
		set_source_files_properties(
			tests/pushnotification/push-notification-tester.cc
			utils/pns-mock.cc
			PROPERTIES COMPILE_OPTIONS "-Wno-error=maybe-uninitialized"
		)
	endif()
elseif(ENABLE_UNIT_TESTS_NGHTTP2ASIO)
	message(FATAL_ERROR "The LibNgHttp2Asio module is required by some tests. You may disable them with -DENABLE_UNIT_TESTS_NGHTTP2ASIO=OFF")
endif()

if(ENABLE_FLEXIAPI AND ENABLE_CONFERENCE AND ENABLE_UNIT_TESTS_NGHTTP2ASIO)
	target_sources(flexisip_tester PRIVATE
		tests/eventlogs/writers/flexi-stats-event-log-writer-tester.cc
	)
	if(HAS_GCC_BUG_105562)
		set_source_files_properties(
			tests/eventlogs/writers/flexi-stats-event-log-writer-tester.cc
			PROPERTIES COMPILE_OPTIONS "-Wno-error=maybe-uninitialized"
		)
	endif()
endif()

if(ENABLE_B2BUA)
	target_sources(flexisip_tester PRIVATE
		utils/server/b2bua-and-proxy-server.cc utils/server/b2bua-and-proxy-server.hh
		tests/b2bua/b2bua-tester.cc
		tests/b2bua/sip-bridge/accounts/account-pool-tester.cc
		tests/b2bua/sip-bridge/accounts/account-pool-performance-tester.cc
		tests/b2bua/sip-bridge/accounts/loaders/static-loader-tester.cc
		tests/b2bua/sip-bridge/accounts/loaders/sql-loader-tester.cc
		tests/b2bua/sip-bridge/accounts/selection-strategy/find-in-pool-tester.cc
		tests/b2bua/sip-bridge/configuration/v2-tester.cc
		tests/b2bua/sip-bridge/listeners/mwi-listener.cc
		tests/b2bua/sip-bridge/invite-tweaker-tester.cc
		tests/b2bua/sip-bridge/sip-bridge-tester.cc
		tests/b2bua/sip-bridge/string-format-fields-tester.cc
		tests/b2bua/trenscrypter/trenscrypter-tester.cc
	)
	if(ENABLE_G729)
		target_sources(flexisip_tester PRIVATE
			tests/b2bua/b2bua-tester-with-g729.cc
		)
	endif()
endif()

if(ENABLE_OPENID_CONNECT)
	target_sources(flexisip_tester PRIVATE
		tests/auth/auth-openid-connect-tester.cc
		tests/auth/bearer-scheme-tester.cc
	)
endif()

if(ENABLE_TRANSCODER)
	target_sources(flexisip_tester PRIVATE
		tests/module-transcode-tester.cc
	)
endif()

target_compile_options(flexisip_tester PRIVATE ${CPP_BUILD_FLAGS} ${CXX_BUILD_FLAGS})
target_link_libraries(flexisip_tester PRIVATE
	Boost::system
	OpenSSL::Crypto
	OpenSSL::SSL
	Threads::Threads
	bctoolbox-tester
	belle-sip
	flexisip
	liblinphone
	liblinphone++
	mediastreamer2
	ortp
	jsoncpp_lib
	hiredis::hiredis
	XercesC::XercesC
)

if(LIBNGHTTP2ASIO_FOUND AND ENABLE_UNIT_TESTS_NGHTTP2ASIO)
	target_link_libraries(flexisip_tester PRIVATE LibNgHttp2Asio)
endif()

target_include_directories(flexisip_tester PRIVATE "${PROJECT_SOURCE_DIR}/libxsd")
