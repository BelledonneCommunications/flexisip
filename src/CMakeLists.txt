############################################################################
# CMakeLists.txt
# Copyright (C) 2010-2021  Belledonne Communications, Grenoble France
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

#######################################################################################################################
# Build the Flexisip library
#######################################################################################################################
add_library(flexisip SHARED
	agent.cc
	auth/auth-module.cc
	auth/flexisip-auth-module.cc
	auth/flexisip-auth-module-base.cc
	auth/realm-extractor.hh
	auth/nonce-store.cc
	authdb-file.cc
	authdb.cc
	callcontext-mediarelay.cc
	callstore.cc
	cli.cc
	cJSON.c
	common.cc
	sip-boolean-expressions.cc
	configdumper.cc
	configmanager.cc
	contact-masquerader.cc
	domain-registrations.cc
	entryfilter.cc
	etchosts.cc
	event.cc
	eventlogs/eventlogs.cc
	fork-context/fork-basic-context.cc
	fork-context/fork-call-context.cc
	fork-context/fork-context-base.cc
	fork-context/fork-message-context-db-proxy.cc
	fork-context/fork-message-context-soci-repository.cc
	fork-context/fork-message-context.cc
	fork-context/fork-context.cc
	h264iframefilter.cc
	log/logmanager.cc
	lpconfig.cc
	mediarelay.cc
	module-auth.cc
	module-authentication-base.cc
	module-contact-route-inserter.cc
	module-dos.cc
	module-forward.cc
	module-garbage-in.cc
	module-gatewayadapter.cc
	module-loadbalancer.cc
	module-mediarelay.cc
	module-nat-helper.cc
	module-pushnotification.cc
	module-redirect.cc
	module-presence.cc
	module-regevent.cc
	module-registrar.cc
	module-router.cc
	module-sanitychecker.cc
	module-statistics-collector.cc
	module-transcode.cc
	module.cc
	monitor.cc
	plugin/plugin-loader.cc
	pushnotification/apple/apple-client.cc
	pushnotification/apple/apple-request.cc
	pushnotification/firebase/firebase-client.cc
	pushnotification/firebase/firebase-request.cc
	pushnotification/client.cc
	pushnotification/genericpush.cc
	pushnotification/legacy-client.cc
	pushnotification/microsoftpush.cc
	pushnotification/request.cc
	pushnotification/service.cc
	pushnotification/wp-client.cc
	push-param.cc
	recordserializer-c.cc
	recordserializer-json.cc
	registrardb-internal.cc
	registrardb.cc
	sdp-modifier.cc
	service-server.cc
	sofia-wrapper/su-root.cc
	stun.cc
	stun/stun_udp.c
	stun/stun.c
	telephone-event-filter.cc
	transaction.cc
	transport.cc
	uac-register.cc
	utils/digest.cc utils/digest.hh
	utils/sip-uri.cc
	utils/string-formater.cc
	utils/string-utils.cc
	utils/threadpool.cc
	utils/timer.cc
	utils/transport/http/http2client.cc
	utils/transport/http/http-headers.cc
	utils/transport/http/http-message.cc
	utils/transport/http/http-response.cc
	utils/transport/http/ng-data-provider.cc
	utils/transport/tls-connection.cc
	utils/uri-utils.cc
)
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	if (NOT CMAKE_CXX_COMPILER_VERSION VERSION_LESS 6.0.0)
		set_source_files_properties(cJSON.c PROPERTIES COMPILE_OPTIONS "-Wno-error=misleading-indentation")
	endif()

	set(stun_c_compile_options "-Wno-error=sign-compare")
	if (NOT CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8.0.0)
		list(APPEND stun_c_compile_options "-Wno-stringop-truncation")
	endif()
	set_source_files_properties(stun/stun.c PROPERTIES COMPILE_OPTIONS "${stun_c_compile_options}")
	unset(stun_c_compile_options)
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
if (ENABLE_UNIT_TESTS)
	target_link_libraries(flexisip PRIVATE bctoolbox-tester)
endif ()

add_dependencies(flexisip flexisip-git-version)

if(ENABLE_MSGPACK)
	message(STATUS "Enabling MSGPACK with includes at ${MSGPACK_INCLUDE_DIRS}")
	target_sources(flexisip PRIVATE recordserializer-msgpack.cc)
	target_include_directories(flexisip PRIVATE ${MSGPACK_INCLUDE_DIRS})
endif()
if(ENABLE_SNMP)
	target_sources(flexisip PRIVATE snmp-agent.cc snmp-agent.h)
	target_include_directories(flexisip PRIVATE "mib" ${NET_SNMP_INCLUDE_DIRS})
	target_link_libraries(flexisip PRIVATE ${NET_SNMP_LIBRARIES})
endif()
if(ENABLE_TRANSCODER)
	target_sources(flexisip PRIVATE callcontext-transcoder.cc callcontext-transcoder.hh)
	target_link_libraries(flexisip PRIVATE mediastreamer)
endif()
if(ENABLE_DATEHANDLER)
	target_sources(flexisip PRIVATE module-datehandler.cc)
endif()
if(ENABLE_REDIS)
	target_sources(flexisip PRIVATE registrardb-redis-async.cc)
	target_compile_definitions(flexisip PRIVATE "ENABLE_REDIS")
	if(INTERNAL_LIBHIREDIS)
		target_compile_definitions(flexisip PRIVATE "INTERNAL_LIBHIREDIS")
	endif()
	#target_include_directories(flexisip PRIVATE ${HIREDIS_INCLUDE_DIRS})
	target_link_libraries(flexisip PRIVATE hiredis)
endif()
if(ENABLE_PROTOBUF)
	# TODO: generate the protobuf wrapper
	# protoc --proto_path=$(builddir) --cpp_out=$(builddir) $(pb_files)
	set(PROTOBUF_GENERATED_FILES ${CMAKE_CURRENT_BINARY_DIR}/recordserializer-protobuf.pb.cc ${CMAKE_CURRENT_BINARY_DIR}/recordserializer-protobuf.pb.h)
	set(PROTOBUF_PROTO ${CMAKE_CURRENT_LIST_DIR}/recordserializer-protobuf.proto)
	add_custom_command(OUTPUT ${PROTOBUF_GENERATED_FILES}
		COMMAND "${PROTOBUF_PROTOC_EXECUTABLE}" "--proto_path=${CMAKE_CURRENT_SOURCE_DIR}" "--cpp_out=${CMAKE_CURRENT_BINARY_DIR}" "${PROTOBUF_PROTO}"
		COMMENT "Generate protobuf wrappers")
	set_source_files_properties(${PROTOBUF_GENERATED_FILES} PROPERTIES GENERATED ON)

	target_sources(flexisip PRIVATE recordserializer-protobuf.cc ${PROTOBUF_GENERATED_FILES})
	target_link_libraries(flexisip PRIVATE "protobuf::libprotobuf")
	target_compile_definitions(flexisip PRIVATE "ENABLE_PROTOBUF")
endif()
if(ENABLE_PRESENCE)
	if(NOT XercesC_FOUND)
		message(FATAL_ERROR "Presence asked but XercesC not enabled! Please enable it first.")
	endif()
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
		xml/xml.cc
		xml/xml.hh
	)
	target_sources(flexisip PRIVATE
		presence/bellesip-signaling-exception.cc
		presence/bellesip-signaling-exception.hh
		presence/etag-manager.hh
		presence/file-resource-list-manager.cc
		presence/file-resource-list-manager.hh
		presence/list-subscription/body-list-subscription.cc
		presence/list-subscription/body-list-subscription.hh
		presence/list-subscription/list-subscription.cc
		presence/list-subscription/list-subscription.hh
		presence/presence-longterm.cc
		presence/presence-longterm.hh
		presence/presence-server.cc
		presence/presence-server.hh
		presence/presentity-manager.hh
		presence/presentity-presenceinformation.cc
		presence/presentity-presenceinformation.hh
		presence/subscription.cc
		presence/subscription.hh
	)
	target_link_libraries(flexisip PUBLIC belr)
	if(ENABLE_SOCI)
		target_sources(flexisip PRIVATE
			presence/list-subscription/external-list-subscription.cc
			presence/list-subscription/external-list-subscription.hh
		)
	endif()
endif()
if(ENABLE_CONFERENCE)
	target_sources(flexisip PRIVATE
		conference/conference-address-generator.cc
		conference/conference-address-generator.hh
		conference/conference-server.cc
		conference/conference-server.hh
		conference/registration-subscription.cc
		conference/registration-subscription.hh
		conference/participant-registration-subscription-handler.cc
		conference/participant-registration-subscription-handler.hh
		registration-events/utils.cpp
		registration-events/utils.hh
		registration-events/client.cpp
		registration-events/client.hh
		registration-events/server.cpp
		registration-events/server.hh
		registration-events/registrar/listener.hh
		registration-events/registrar/listener.cpp
	)
	target_link_libraries(flexisip
		PRIVATE bellesip
		PUBLIC linphone++
	)
	list(APPEND XML_SOURCES
		xml/reginfo.cc
		xml/reginfo.hh
	)
endif()
if(ENABLE_SOCI)
	target_compile_definitions(flexisip PRIVATE "ENABLE_SOCI")
	target_sources(flexisip PRIVATE authdb-soci.cc soci-helper.cc soci-helper.hh)
	target_link_libraries(flexisip PUBLIC soci_core soci_mysql)
endif()
if(XercesC_FOUND)
	target_include_directories(flexisip PRIVATE "${PROJECT_SOURCE_DIR}/libxsd")
	target_link_libraries(flexisip PRIVATE "XercesC::XercesC")
endif()
if(ENABLE_PRESENCE OR ENABLE_MDNS)
	target_link_libraries(flexisip PUBLIC bellesip)
	target_compile_definitions(flexisip PRIVATE "BELLE_SIP_USE_STL")
endif()

target_sources(flexisip PRIVATE ${XML_SOURCES})
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	if (NOT CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0.0)
		# Completely disable 'deprecated-copy' warning because these source files are generated by XSD and the warnings
		# cannot be fixed thus.
		set_source_files_properties(${XML_SOURCES} PROPERTIES COMPILE_OPTIONS "-Wno-deprecated-copy")
	endif()
endif()

#######################################################################################################################
# Build plugins.
#######################################################################################################################
if(ENABLE_EXTERNAL_AUTH_PLUGIN)
	add_subdirectory(plugin/external-auth-plugin)
endif()

if(ENABLE_JWE_AUTH_PLUGIN)
	add_subdirectory(plugin/jwe-auth-plugin)
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
