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

#######################################################################################################################
# Build the Flexisip library
#######################################################################################################################

add_library(flexisip SHARED
	agent.cc agent-startlogwriter.cc agent.hh
	auth/auth-scheme.hh
	auth/db/authdb-file.cc
	auth/db/authdb.cc auth/db/authdb.hh
	auth/flexisip-auth-module-base.cc
	auth/flexisip-auth-module.cc auth/flexisip-auth-module.hh
	auth/nonce-store.cc
	auth/preferred-identity.hh
	auth/realm-extractor.hh
	callcontext-mediarelay.cc callcontext-mediarelay.hh
	callstore.cc callstore.hh
	cli.cc cli.hh
	cJSON.c
	common.cc
	sip-boolean-expressions.cc
	configdumper.cc configdumper.hh
	configmanager.cc
	contact-masquerader.cc contact-masquerader.hh
	domain-registrations.cc domain-registrations.hh
	dos/dos-executor/ban-executor.hh
	dos/dos-executor/iptables-executor.cc dos/dos-executor/iptables-executor.hh
	dos/module-dos.cc
	entryfilter.cc entryfilter.hh
	etchosts.cc etchosts.hh
	event.cc
	eventlogs/events/calls/call-ended-event-log.cc eventlogs/events/calls/call-ended-event-log.hh
	eventlogs/events/calls/call-ringing-event-log.cc eventlogs/events/calls/call-ringing-event-log.hh
	eventlogs/events/calls/call-started-event-log.cc eventlogs/events/calls/call-started-event-log.hh
	eventlogs/events/calls/invite-kind.cc eventlogs/events/calls/invite-kind.hh
	eventlogs/events/event-id.cc eventlogs/events/event-id.hh
	eventlogs/events/event-log-write-dispatcher.hh
	eventlogs/events/eventlogs.cc eventlogs/events/eventlogs.hh
	eventlogs/events/message-or-call-started.cc eventlogs/events/message-or-call-started.hh
	eventlogs/events/messages/with-message-kind.hh
	eventlogs/events/messages/message-response-from-recipient-event-log.cc eventlogs/events/messages/message-response-from-recipient-event-log.hh
	eventlogs/events/messages/message-sent-event-log.cc eventlogs/events/messages/message-sent-event-log.hh
	eventlogs/events/sip-event-log.cc eventlogs/events/sip-event-log.hh
	eventlogs/writers/event-log-writer.cc eventlogs/writers/event-log-writer.hh
	eventlogs/writers/filesystem-event-log-writer.cc eventlogs/writers/filesystem-event-log-writer.hh
	exceptions/bad-configuration.hh
	exceptions/exit.hh
	exceptions/invalid-address.hh
	fork-context/branch-info.hh fork-context/branch-info.cc
	fork-context/branch-info-db.hh
	fork-context/fork-basic-context.cc fork-context/fork-basic-context.hh
	fork-context/fork-call-context.cc fork-context/fork-call-context.hh
	fork-context/fork-context-base.cc fork-context/fork-context-base.hh
	fork-context/fork-context-factory.cc fork-context/fork-context-factory.hh
	fork-context/fork-message-context-db.hh
	fork-context/fork-message-context.cc fork-context/fork-message-context.hh
	fork-context/message-kind.cc fork-context/message-kind.hh
	fork-context/fork-context.cc
	fork-context/fork-status.hh
	h264iframefilter.cc h264iframefilter.hh
	lib/nlohmann-json-3-11-2/json.hpp
	log/logmanager.cc
	lpconfig.cc
	main/flexisip.cc main/flexisip.hh
	mediarelay.cc mediarelay.hh
	module-auth.cc
	module-authentication-base.cc
	module-auth-trusted-hosts.cc module-auth-trusted-hosts.hh
	module-authorization.cc module-authorization.hh
	module-capabilities.cc module-capabilities.hh
	module-contact-route-inserter.cc
	module-forward.cc module-forward.hh
	module-garbage-in.cc
	module-gatewayadapter.cc
	module-loadbalancer.cc
	module-mediarelay.cc
	module-nat-helper.cc module-nat-helper.hh
	module-redirect.cc
	module-presence.cc
	module-pushnotification.cc module-pushnotification.hh
	module-regevent.cc
	module-registrar.cc
	module-router.cc
	module-sanitychecker.cc
	module-statistics-collector.cc
	module-toolbox.cc module-toolbox.hh
	module-transcode.cc module-transcode.hh
	module.cc
	nat/contact-correction-strategy.cc nat/contact-correction-strategy.hh
	nat/flow-token-strategy.cc nat/flow-token-strategy.hh
	nat/nat-traversal-strategy.hh nat/nat-traversal-strategy.cc
	plugin/plugin-loader.cc plugin/plugin-loader.hh
	recordserializer-c.cc
	recordserializer-json.cc
	recordserializer.cc
	registrar/change-set.cc
	registrar/contact-key.cc
	registrar/exceptions.cc
	registrar/extended-contact.cc
	registrar/registrar-listeners.cc
	registrar/record.cc
	registrar/registrar-db.cc
	registrardb-internal.cc registrardb-internal.hh
	sdp-modifier.cc sdp-modifier.hh
	service-server/service-server.cc service-server/service-server.hh
	signal-handling/signal-handling.cc
	stun.cc stun.hh
	stun/stun_udp.c
	stun/stun.c
	telephone-event-filter.cc telephone-event-filter.hh
	transport.cc transport.hh
	uac-register.cc uac-register.hh
	utils/process-monitoring/memory-watcher.cc utils/process-monitoring/memory-watcher.hh
	conditional-routes.cc conditional-routes.hh
	i-supervisor-notifier.hh
)

if(ENABLE_FLEXIAPI)
	message(STATUS "Building with support for FlexiAPI")
	target_sources(flexisip PRIVATE
		eventlogs/writers/flexi-stats-event-log-writer.cc eventlogs/writers/flexi-stats-event-log-writer.hh
	)
	add_subdirectory(flexiapi)
endif()

if(ENABLE_OPENID_CONNECT)
	target_sources(flexisip PRIVATE
		auth/bearer-auth.cc auth/bearer-auth.hh
		module-auth-openid-connect.cc module-auth-openid-connect.hh
	)
endif()

add_subdirectory(pushnotification)
add_subdirectory(router)
add_subdirectory(sofia-wrapper)
add_subdirectory(transaction)
add_subdirectory(utils)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	if(NOT CMAKE_CXX_COMPILER_VERSION VERSION_LESS 6.0.0)
		set_source_files_properties(cJSON.c PROPERTIES COMPILE_OPTIONS "-Wno-error=misleading-indentation")
	endif()

	set(stun_c_compile_options "-Wno-error=sign-compare")
	if(NOT CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8.0.0)
		list(APPEND stun_c_compile_options "-Wno-stringop-truncation")
	endif()
	set_source_files_properties(stun/stun.c PROPERTIES COMPILE_OPTIONS "${stun_c_compile_options}")
	unset(stun_c_compile_options)

	if(HAS_GCC_BUG_105616 OR HAS_GCC_BUG_105562)
		set_source_files_properties(
			configdumper.cc
			domain-registrations.cc
			eventlogs/writers/flexi-stats-event-log-writer.cc
			module-authentication-base.cc
			module-registrar.cc
			pushnotification/apple/apple-request.cc
			pushnotification/rfc8599-push-params.cc
			main.cc
			PROPERTIES COMPILE_OPTIONS "-Wno-error=maybe-uninitialized")
	endif()
	if(HAS_GCC_BUG_105562)
		set_source_files_properties(
			expressionparser-impl.cc
			sip-boolean-expressions.cc
			tools/pusher.cc
			PROPERTIES COMPILE_OPTIONS "-Wno-error=maybe-uninitialized")
	endif()
endif()

#Generates information for test coverage reports.
#If flexisip lib needs to be static, add this rule:
#list(APPEND STATIC_LIBRARY_OPTIONS "-fprofile-instr-generate")
if(ENABLE_COVERAGE)
	if(CMAKE_CXX_COMPILER_ID MATCHES "^(Apple)?Clang$")
		target_compile_options(flexisip PRIVATE "-fprofile-instr-generate")
		target_compile_options(flexisip PRIVATE "-fcoverage-mapping")
		target_link_options(flexisip PRIVATE "-fprofile-instr-generate")
	else()
		message(FATAL "CMAKE_CXX_COMPILER_ID is set to ${CMAKE_CXX_COMPILER_ID}. Coverage works only under Clang. Disable ENABLE_COVERAGE option or use Clang.")
	endif()
endif()
if(APPLE)
	target_link_libraries(flexisip PRIVATE Iconv::Iconv)
endif()


target_compile_features(flexisip PRIVATE cxx_auto_type cxx_variadic_macros)
target_link_libraries(flexisip
	PRIVATE
	bctoolbox
	belr
	LibNgHttp2
	ortp
	OpenSSL::SSL
	Threads::Threads
	PUBLIC
	sofia-sip-ua
)
if(ENABLE_UNIT_TESTS)
	target_link_libraries(flexisip PRIVATE bctoolbox-tester)
endif()

add_dependencies(flexisip flexisip-git-version)

if(ENABLE_MSGPACK)
	message(STATUS "Enabling MSGPACK with includes at ${MSGPACK_INCLUDE_DIRS}")
	target_sources(flexisip PRIVATE recordserializer-msgpack.cc)
	target_include_directories(flexisip PRIVATE ${MSGPACK_INCLUDE_DIRS})
endif()
if(ENABLE_SNMP)
	add_subdirectory(snmp)
	target_include_directories(flexisip PRIVATE "mib" ${NET_SNMP_INCLUDE_DIRS})
	target_link_libraries(flexisip PRIVATE ${NET_SNMP_LIBRARIES})
endif()
if(ENABLE_TRANSCODER)
	target_sources(flexisip PRIVATE callcontext-transcoder.cc callcontext-transcoder.hh)
	target_link_libraries(flexisip PRIVATE mediastreamer2)
endif()
if(ENABLE_DATEHANDLER)
	target_sources(flexisip PRIVATE module-datehandler.cc)
endif()
if(ENABLE_REDIS)
	add_subdirectory(libhiredis-wrapper)
	target_sources(flexisip PRIVATE
		registrardb-redis-async.cc
	)
	target_compile_definitions(flexisip PRIVATE "ENABLE_REDIS")
	target_link_libraries(flexisip PRIVATE hiredis::hiredis)
endif()
if(ENABLE_PRESENCE OR ENABLE_CONFERENCE)
	if(NOT XercesC_FOUND)
		message(FATAL_ERROR "Presence asked but XercesC not enabled! Please enable it first.")
	endif()
	list(APPEND XML_SOURCES
		xml/xml.cc
		xml/xml.hh
	)
endif()
if(ENABLE_PRESENCE)
	list(APPEND XML_SOURCES
		xml/data-model.cc
		xml/data-model.hh
		xml/pidf+xml.cc
		xml/pidf+xml.hh
		xml/pidf-oma-pres.cc
		xml/pidf-oma-pres.hh
		xml/resource-lists.cc
		xml/resource-lists.hh
		xml/rlmi+xml.cc
		xml/rlmi+xml.hh
		xml/rpid.cc
		xml/rpid.hh
	)
	target_link_libraries(flexisip PUBLIC belr)
	add_subdirectory(presence)
endif()
if(ENABLE_CONFERENCE)
	target_sources(flexisip PRIVATE
		conference/conference-server.cc
		conference/conference-server.hh
		conference/registration-subscription.cc
		conference/registration-subscription.hh
		conference/participant-registration-subscription-handler.cc
		conference/participant-registration-subscription-handler.hh
		registration-events/client.cpp
		registration-events/client.hh
		registration-events/server.cpp
		registration-events/server.hh
	)
	target_link_libraries(flexisip
		PRIVATE belle-sip
		PUBLIC liblinphone++
	)
	list(APPEND XML_SOURCES
		xml/reginfo.cc
		xml/reginfo.hh
	)
endif()
if(ENABLE_B2BUA)
	target_sources(flexisip PRIVATE
		module-b2bua.cc
	)

	add_subdirectory(b2bua)
endif()
if(ENABLE_SOCI)
	target_compile_definitions(flexisip PRIVATE "ENABLE_SOCI")
	target_sources(flexisip PRIVATE
		auth/db/authdb-soci.cc
		eventlogs/writers/database-event-log-writer.cc eventlogs/writers/database-event-log-writer.hh
		fork-context/fork-message-context-soci-repository.cc fork-context/fork-message-context-soci-repository.hh
		fork-context/fork-message-context-db-proxy.cc fork-context/fork-message-context-db-proxy.hh
		utils/soci-helper.cc utils/soci-helper.hh
	)
	target_link_libraries(flexisip PUBLIC soci_core soci_mysql soci_sqlite3)
	if(HAS_GCC_BUG_105562)
		set_source_files_properties(
			auth/db/authdb-soci.cc
			PROPERTIES COMPILE_OPTIONS "-Wno-error=maybe-uninitialized")
	endif()
endif()
if(XercesC_FOUND)
	target_include_directories(flexisip PRIVATE "${PROJECT_SOURCE_DIR}/libxsd")
	target_link_libraries(flexisip PRIVATE "XercesC::XercesC")
endif()
if(ENABLE_PRESENCE OR ENABLE_MDNS)
	target_link_libraries(flexisip PUBLIC belle-sip)
	target_compile_definitions(flexisip PRIVATE "BELLE_SIP_USE_STL")
endif()

target_sources(flexisip PRIVATE ${XML_SOURCES})
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	if(NOT CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0.0)
		# Completely disable 'deprecated-copy' warning because these source files are generated by XSD and the warnings
		# cannot be fixed thus.
		set_source_files_properties(${XML_SOURCES} PROPERTIES COMPILE_OPTIONS "-Wno-deprecated-copy")
	endif()
else(CMAKE_CXX_COMPILER_ID MATCHES "^(Apple)?Clang$")
	set_source_files_properties(${XML_SOURCES} PROPERTIES COMPILE_OPTIONS "-Wno-deprecated-copy-with-user-provided-copy")
endif()

#######################################################################################################################
# Build plugins.
#######################################################################################################################
if(ENABLE_EXTERNAL_AUTH_PLUGIN)
	add_subdirectory(plugin/external-auth-plugin)
endif()

#######################################################################################################################
# Build the executables
#######################################################################################################################
add_executable(flexisip_server main.cc)
set_property(TARGET flexisip_server PROPERTY OUTPUT_NAME flexisip)
target_compile_features(flexisip_server PRIVATE cxx_auto_type cxx_variadic_macros)
target_link_libraries(flexisip_server PRIVATE flexisip OpenSSL::Crypto ortp)
install(TARGETS flexisip flexisip_server
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

add_executable(flexisip_pusher tools/pusher.cc)
target_link_libraries(flexisip_pusher flexisip OpenSSL::Crypto LibNgHttp2 bctoolbox)
install(TARGETS flexisip_pusher
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

add_executable(flexisip_serializer tools/serializer.cc)
target_link_libraries(flexisip_serializer flexisip bctoolbox)
install(TARGETS flexisip_serializer
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

#######################################################################################################################
# Generate default configuration file for flexisip
#######################################################################################################################
if(NOT CMAKE_CROSSCOMPILING)
	add_custom_target(flexisip_config
		ALL
		COMMAND $<TARGET_FILE:flexisip_server> --dump-all-default > "${CMAKE_BINARY_DIR}/flexisip.conf"
		BYPRODUCTS "${CMAKE_BINARY_DIR}/flexisip.conf"
		COMMENT "Flexisip default configuration file generation"
	)
	add_dependencies(flexisip_config flexisip_server)
	install(FILES "${CMAKE_BINARY_DIR}/flexisip.conf"
		DESTINATION "${SYSCONF_INSTALL_DIR}/flexisip"
		PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
	)
	set(FLEXISIP_CONFIGURATION_FILE_INSTALL_LOCATION "${SYSCONF_INSTALL_DIR}/flexisip/flexisip.conf" PARENT_SCOPE)
endif()
