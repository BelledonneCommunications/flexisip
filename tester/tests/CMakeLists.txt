############################################################################
# CMakeLists.txt
# Copyright (C) 2010-2026 Belledonne Communications, Grenoble France
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

add_executable(flexisip_tester
	agent-tester.cc
	boolean-expressions.cc
	cli-tester.cc
	domain-registration-tester.cc
	msg-sip-tester.cc
	sip-uri-tester.cc
	schedule-injector-tester.cc
	accounts-store/accounts-store-tester.cc
	auth/auth-digest-tester.cc
	auth/auth-domains-tester.cc
	auth/auth-tls-client-tester.cc
	auth/auth-trusted-hosts-tester.cc
	auth/module-authorization-tester.cc
	auth/rsa-keys.hh
	callcontext-mediarelay-tester.cc
	configmanager-tester.cc
	eventlogs/events/auth-log-tester.cc
	eventlogs/events/event-id-tester.cc
	eventlogs/events/event-log-stats-tester.cc
	flexiapi/schemas/iso-8601-date-tester.cc
	integration/call-tester.cc
	integration/domotic-tester.cc
	main-tester.cc
	modules/contact-route-inserter/contact-masquerader-tester.cc
	modules/contact-route-inserter/module-contact-route-inserter-tester.cc
	modules/mediarelay-tester.cc
	modules/module-dos-tester.cc
	modules/module-forward-tester.cc
	modules/module-info-tester.cc
	modules/module-nat-helper-tester.cc
	modules/module-registrar-tester.cc
	modules/module-sanitychecker-tester.cc
	modules/module-toolbox-tester.cc
	modules/router/fork/fork-call-tester.cc
	modules/router/fork/fork-context-tester.cc
	modules/router/module-router-diverted-calls-tester.cc
	modules/router/module-router-message-shared-tests.cc modules/router/module-router-message-shared-tests.hh
	modules/router/module-router-tester.cc
	nat/contact-correction-strategy-helper-tester.cc
	nat/contact-correction-strategy-tester.cc
	nat/flow-token-strategy-tester.cc
	nat/nat-traversal-feature-tester.cc
	nat/nat-traversal-strategy-helper-tester.cc
	posix-process-tester.cc
	pushnotification/access-token-provider-tester.cc
	pushnotification/authentication-manager-tester.cc
	pushnotification/rfc8599-push-params-tester.cc
	pushnotification/module-pushnotification-tester.cc
	pushnotification/notify-pushnotification-tester.cc
	pushnotification/service-tester.cc
	registrar/extended-contact-tester.cc
	registrar/register-tester.cc
	registrar/registrardb-tester.cc
	registrar/registrardb-redis-tester.cc
	recordserializer-json-tester.cc
	response-sip-event-tester.cc
	sofia-api/cve-fix-tester.cc
	sofia-api/nta-input.cc
	sofia-api/nta-reply.cc
	sofia-api/nth.cc
	sofia-api/sofia-driven-signal-handler-tester.cc
	sofia-wrapper/home-tester.cc
	sofia-wrapper/su/home-tester.cc
	sofia-wrapper/sip-header-tester.cc
	sofia-wrapper/su-root-tester.cc
	transaction/outgoing-transaction-tester.cc
	transports-tester.cc
	transaction/transaction-tester.cc
	utf8-string-tester.cc
	utils-tester.cc
	utils/cast-to-const-tester.cc
	utils/flow-data-tester.cc
	utils/flow-factory-tester.cc
	utils/flow-tester.cc
	utils/flow-factory-helper-tester.cc
	utils/limited-unordered-map-tester.cc
	utils/socket-address-tester.cc
	utils/soft-ptr-tester.cc
	utils/transport/http/http1client-tester.cc
	thread-pool-tester.cc
	tls-connection-tester.cc
)

if(ENABLE_REGEVENT OR ENABLE_B2BUA OR ENABLE_VOICEMAIL)
	target_sources(flexisip_tester PRIVATE
		utils/configuration/media.cc
		utils/configuration/transport.cc
	)
endif()

if(ENABLE_REGEVENT)
	target_sources(flexisip_tester PRIVATE
		registration-event-tester.cc
	)
endif()

if(ENABLE_PRESENCE)
	target_sources(flexisip_tester PRIVATE
		presence/presence-pidf-tester.cc
		presence/presence-publish-tester.cc
		presence/xsd-utils-tester.cc
	)
endif()

if(ENABLE_SOCI)
	target_sources(flexisip_tester PRIVATE
		auth/db/authdb-soci-tester.cc
		eventlogs/writers/database-event-log-writer-tester.cc
		modules/router/fork/fork-context-mysql-tester.cc
		modules/router/fork/fork-message-context-soci-repository-tester.cc
		modules/router/module-router-sql-tester.cc
		utils/soci-helper-tester.cc
		utils/soci-type-conversion-utils-tester.cc
	)
	if(ENABLE_PRESENCE)
		target_sources(flexisip_tester PRIVATE
			presence/list-subscription/external-list-subscription-tester.cc
		)
	endif()
endif()

if(LIBNGHTTP2ASIO_FOUND AND ENABLE_UNIT_TESTS_NGHTTP2ASIO)
	target_sources(flexisip_tester PRIVATE
		auth/module-authorization-FAM-tester.cc
		pushnotification/global-push-tester.cc
		pushnotification/push-notification-tester.cc pushnotification/push-notification-tester.hh
		utils/transport/http/rest-client-tester.cc
		utils/transport/http/http2client-tester.cc
	)
	if(ENABLE_FLEXIAPI)
		target_sources(flexisip_tester PRIVATE
			flexiapi/flexi-stats-tester.cc
			pushnotification/push-notification-flexiapi-tester.cc
		)
		if(ENABLE_SOCI)
			target_sources(flexisip_tester PRIVATE
				eventlogs/writers/flexi-stats-event-log-writer-tester.cc
			)
		endif()
	endif()
	if(HAS_GCC_BUG_105562)
		set_source_files_properties(
			pushnotification/push-notification-tester.cc
			utils/pns-mock.cc
			PROPERTIES COMPILE_OPTIONS "-Wno-error=maybe-uninitialized"
		)
		if(ENABLE_SOCI)
			set_source_files_properties(
				eventlogs/writers/flexi-stats-event-log-writer-tester.cc
				PROPERTIES COMPILE_OPTIONS "-Wno-error=maybe-uninitialized"
			)
		endif()
	endif()
elseif(ENABLE_UNIT_TESTS_NGHTTP2ASIO)
	message(FATAL_ERROR "The LibNgHttp2Asio module is required by some tests. You may disable them with -DENABLE_UNIT_TESTS_NGHTTP2ASIO=OFF")
endif()

if(ENABLE_B2BUA)
	target_sources(flexisip_tester PRIVATE
		b2bua/b2bua-tester.cc
		b2bua/sip-bridge/accounts/account-pool-tester.cc
		b2bua/sip-bridge/accounts/account-pool-performance-tester.cc
		b2bua/sip-bridge/accounts/loaders/static-loader-tester.cc
		b2bua/sip-bridge/accounts/loaders/sql-loader-tester.cc
		b2bua/sip-bridge/accounts/selection-strategy/find-in-pool-tester.cc
		b2bua/sip-bridge/configuration/v2-tester.cc
		b2bua/sip-bridge/listeners/mwi-listener.cc
		b2bua/sip-bridge/call-transfer-tester.cc
		b2bua/sip-bridge/invite-tweaker-tester.cc
		b2bua/sip-bridge/sip-bridge-tester.cc
		b2bua/sip-bridge/string-format-fields-tester.cc
		b2bua/trenscrypter/trenscrypter-tester.cc
	)
	if(ENABLE_G729)
		target_sources(flexisip_tester PRIVATE
			b2bua/b2bua-tester-with-g729.cc
		)
	endif()
endif()

if(ENABLE_OPENID_CONNECT)
	target_sources(flexisip_tester PRIVATE
		auth/auth-openid-connect-tester.cc
		auth/bearer-scheme-tester.cc
	)
endif()

if(ENABLE_TRANSCODER)
	target_sources(flexisip_tester PRIVATE
		modules/module-transcode-tester.cc
	)
endif()

# C++ 20 adds the support for char8_t which adds a lot of backward compatibility problems.
# See: https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2019/p1423r3.html
# So for now disable it until we need it.
list(APPEND CXX_BUILD_FLAGS "-fno-char8_t")

target_compile_options(flexisip_tester PRIVATE ${CPP_BUILD_FLAGS} ${CXX_BUILD_FLAGS})
target_link_libraries(flexisip_tester PRIVATE
	flexisip_tester_utils
	Threads::Threads
	belle-sip
	liblinphone
	liblinphone++
)

if(ENABLE_REDIS)
	target_sources(flexisip_tester PRIVATE
		libhiredis-wrapper/redis-async-session-tester.cc
		libhiredis-wrapper/redis-reply-tester.cc
		libhiredis-wrapper/replication/redis-client-tester.cc
	)
	target_link_libraries(flexisip_tester PRIVATE hiredis::hiredis)

	if(ENABLE_REDIS_TLS)
		target_sources(flexisip_tester PRIVATE
			libhiredis-wrapper/replication/redis-tls-client-tester.cc
		)
		target_link_libraries(flexisip_tester PRIVATE hiredis_ssl)
	endif()
endif()

if(LIBNGHTTP2ASIO_FOUND AND ENABLE_UNIT_TESTS_NGHTTP2ASIO)
	target_link_libraries(flexisip_tester PRIVATE LibNgHttp2Asio)
	if(ENABLE_VOICEMAIL)
		target_sources(flexisip_tester PRIVATE
			integration/voicemail/voicemail-server-tester.cc
		)
	endif()
endif()

target_sources(flexisip_tester PRIVATE tester.cc tester.hh)

target_include_directories(flexisip_tester PRIVATE "${PROJECT_SOURCE_DIR}/libxsd")