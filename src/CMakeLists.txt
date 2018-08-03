############################################################################
# CMakeLists.txt
# Copyright (C) 2014-2018  Belledonne Communications, Grenoble France
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

set(FLEXISIP_LIBS ${ORTP_LIBRARIES} ${SOFIASIPUA_LIBRARIES} ${LINPHONECXX_LIBRARIES} ${BCTOOLBOX_CORE_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

set(FLEXISIP_INCLUDES )

set(FLEXISIP_DEPENDENCIES)

set(FLEXISIP_SOURCES
	agent.cc
	authdb-file.cc
	authdb.cc
	callcontext-mediarelay.cc
	callstore.cc
	cJSON.c
	common.cc
	configdumper.cc
	configmanager.cc
	contact-masquerader.cc
	domain-registrations.cc
	entryfilter.cc
	etchosts.cc
	event.cc
	eventlogs/eventlogs.cc
	expressionparser.cc
	forkbasiccontext.cc
	forkcallcontext.cc
	forkcontext.cc
	forkmessagecontext.cc
	h264iframefilter.cc
	log/logmanager.cc
	lpconfig.cc
	mediarelay.cc
	module-auth.cc
	module-contact-route-inserter.cc
	module-dos.cc
	module-forward.cc
	module-garbage-in.cc
	module-gatewayadapter.cc
	module-loadbalancer.cc
	module-mediarelay.cc
	module-nat-helper.cc
	module-pushnotification.cc
	module-redirect.cc module-presence.cc
	module-registrar.cc
	module-router.cc
	module-sanitychecker.cc
	module-statistics-collector.cc
	module-transcode.cc
	module.cc
	monitor.cc
	plugin/plugin-loader.cc
	pushnotification/pushnotification.cc
	pushnotification/applepush.cc
	pushnotification/firebasepush.cc
	pushnotification/genericpush.cc
	pushnotification/googlepush.cc
	pushnotification/microsoftpush.cc
	pushnotification/pushnotificationclient_wp.cc
	pushnotification/pushnotificationclient.cc
	pushnotification/pushnotificationservice.cc
	recordserializer-c.cc
	recordserializer-json.cc
	registrardb-internal.cc
	registrardb.cc
	sdp-modifier.cc
	sipattrextractor.cc
	stats.cc
	stun.cc
	stun/stun_udp.c
	stun/stun.c
	telephone-event-filter.cc
	transaction.cc
	uac-register.cc
	utils/httputils.cc
	utils/threadpool.cc
)

find_package(Git)
add_custom_target(flexisip-git-version
	COMMAND ${CMAKE_COMMAND} -DGIT_EXECUTABLE=${GIT_EXECUTABLE} -DFLEXISIP_VERSION=${FLEXISIP_VERSION} -DWORK_DIR=${CMAKE_CURRENT_SOURCE_DIR} -DOUTPUT_DIR=${CMAKE_CURRENT_BINARY_DIR} -P ${CMAKE_CURRENT_SOURCE_DIR}/gitversion.cmake
	BYPRODUCTS "${CMAKE_CURRENT_BINARY_DIR}/flexisip_gitversion.h"
)

list(APPEND FLEXISIP_INCLUDES ${BCTOOLBOX_INCLUDE_DIRS})

if(LIBXSD_FOUND)
	list(APPEND FLEXISIP_LIBS ${LIBXSD_LIBRARIES})
	list(APPEND FLEXISIP_INCLUDES ${LIBXSD_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/xml)
	list(APPEND FLEXISIP_SOURCES xml/fthttp.cc xml/fthttp.hh)
endif()

if(ENABLE_MSGPACK)
	message(STATUS "Enabling MSGPACK with includes at ${MSGPACK_INCLUDE_DIRS}")
	list(APPEND FLEXISIP_INCLUDES ${MSGPACK_INCLUDE_DIRS})
	list(APPEND FLEXISIP_SOURCES recordserializer-msgpack.cc)
endif()


if(ENABLE_SNMP)
	list(APPEND FLEXISIP_SOURCES snmp-agent.cc snmp-agent.h)
	list(APPEND FLEXISIP_LIBS ${NET_SNMP_LIBRARIES})
	list(APPEND FLEXISIP_INCLUDES ${NET_SNMP_INCLUDE_DIRS} ${CMAKE_CURRENT_LIST_DIR}/mib)
endif()

if(ENABLE_ODBC)
	add_definitions(-DENABLE_ODBC)
	list(APPEND FLEXISIP_SOURCES authdb-odbc.cc)
	list(APPEND FLEXISIP_LIBS ${ODBC_LIBRARIES})
	list(APPEND FLEXISIP_INCLUDES ${ODBC_INCLUDE_DIRS})
endif()

if(ENABLE_TRANSCODER)
	list(APPEND FLEXISIP_SOURCES callcontext-transcoder.cc callcontext-transcoder.hh)
	list(APPEND FLEXISIP_LIBS ${MEDIASTREAMER2_LIBRARIES})
	list(APPEND FLEXISIP_INCLUDES ${MEDIASTREAMER2_INCLUDE_DIRS})
endif()

if(ENABLE_DATEHANDLER)
	list(APPEND FLEXISIP_SOURCES module-datehandler.cc)
endif()

if(ENABLE_REDIS)
	list(APPEND FLEXISIP_SOURCES registrardb-redis-async.cc registrardb-redis.hh registrardb-redis-sofia-event.h)
	list(APPEND FLEXISIP_LIBS ${HIREDIS_LIBRARIES})
	list(APPEND FLEXISIP_INCLUDES ${HIREDIS_INCLUDE_DIRS})
	add_definitions(-DENABLE_REDIS)
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

	list(APPEND FLEXISIP_SOURCES recordserializer-protobuf.cc ${PROTOBUF_GENERATED_FILES})
	list(APPEND FLEXISIP_LIBS ${PROTOBUF_LIBRARIES})
	list(APPEND FLEXISIP_INCLUDES ${PROTOBUF_INCLUDE_DIRS})
	add_definitions(-DENABLE_PROTOBUF)
endif()

if(ENABLE_PRESENCE OR ENABLE_MDNS)
	list(APPEND FLEXISIP_LIBS ${BELLESIP_LIBRARIES})
	list(APPEND FLEXISIP_INCLUDES ${BELLESIP_INCLUDE_DIRS})
	add_definitions(-DBELLE_SIP_USE_STL ${BELLE_SIP_CFLAGS})
endif()

if(ENABLE_PRESENCE)
	if(NOT LIBXSD_FOUND)
		message(FATAL_ERROR "Presence asked but XSD not enabled! Please enable it first.")
	endif()
	add_definitions(-DBELLE_SIP_USE_STL ${BELLE_SIP_CFLAGS})
	list(APPEND FLEXISIP_LIBS ${XERCES_LIBS})
	list(APPEND FLEXISIP_INCLUDES presence)
	list(APPEND FLEXISIP_SOURCES
		presence/bellesip-signaling-exception.cc
		presence/bellesip-signaling-exception.hh
		presence/etag-manager.hh
		presence/file-resource-list-manager.cc
		presence/file-resource-list-manager.hh
		presence/list-subscription.cc
		presence/list-subscription.hh
		presence/presence-configmanager.cc
		presence/presence-configmanager.hh
		presence/presence-longterm.cc
		presence/presence-longterm.hh
		presence/presence-server.cc
		presence/presence-server.hh
		presence/presentity-manager.hh
		presence/presentity-presenceinformation.cc
		presence/presentity-presenceinformation.hh
		presence/subscription.cc
		presence/subscription.hh
		xml/data-model.cc
		xml/data-model.hh
		xml/pidf+xml.cc
		xml/pidf+xml.hh
		xml/resource-lists.cc
		xml/resource-lists.hh
		xml/rlmi+xml.cc
		xml/rlmi+xml.hh
		xml/rpid.cc
		xml/rpid.hh
		xml/xml.cc
		xml/xml.hh
	)
endif()

if(ENABLE_CONFERENCE)
	list(APPEND FLEXISIP_LIBS ${BELLESIP_LIBRARIES} ${LINPHONE_LIBRARIES})
	list(APPEND FLEXISIP_INCLUDES ${BELLESIP_INCLUDE_DIRS} ${LINPHONE_INCLUDE_DIRS})
	list(APPEND FLEXISIP_SOURCES
		conference/conference-address-generator.cc
		conference/conference-address-generator.hh
		conference/conference-server.cc
		conference/conference-server.hh
		conference/participant-capabilities-check.cc
		conference/participant-capabilities-check.hh
		conference/participant-devices-search.cc
		conference/participant-devices-search.hh
		conference/participant-registration-subscription.cc
		conference/participant-registration-subscription.hh
		conference/participant-registration-subscription-handler.cc
		conference/participant-registration-subscription-handler.hh
	)
endif()

if(ENABLE_PUSHNOTIFICATION)
	list(APPEND FLEXISIP_SOURCES
		module-pushnotification.cc
		pushnotification/applepush.cc
		pushnotification/applepush.hh
		pushnotification/firebasepush.cc
		pushnotification/firebasepush.hh
		pushnotification/genericpush.cc
		pushnotification/genericpush.hh
		pushnotification/googlepush.cc
		pushnotification/googlepush.hh
		pushnotification/microsoftpush.cc
		pushnotification/microsoftpush.hh
		pushnotification/pushnotificationclient.cc
		pushnotification/pushnotificationclient.hh
		pushnotification/pushnotificationclient_wp.cc
		pushnotification/pushnotificationclient_wp.hh
		pushnotification/pushnotificationservice.cc
		pushnotification/pushnotificationservice.hh
	)
endif()

list(APPEND FLEXISIP_LIBS ${OPENSSL_LIBRARIES})
list(APPEND FLEXISIP_INCLUDES ${OPENSSL_INCLUDE_DIR})

if(ENABLE_SOCI)
	add_definitions(-DENABLE_SOCI)
	list(APPEND FLEXISIP_SOURCES authdb-soci.cc)
	list(APPEND FLEXISIP_LIBS ${SOCI_LIBRARY})
	list(APPEND FLEXISIP_INCLUDES ${SOCI_INCLUDE_DIRS} ${SOCI_MYSQL_INCLUDES})
endif()

message(STATUS "Flexisip LIBS : ${FLEXISIP_LIBS}")
message(STATUS "Flexisip INCLUDES : ${FLEXISIP_INCLUDES}")
message(STATUS "Flexisip DEPENDENCIES : ${FLEXISIP_DEPENDENCIES}")

bc_apply_compile_flags(FLEXISIP_SOURCES CPP_BUILD_FLAGS CXX_BUILD_FLAGS)
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	if (${CMAKE_CXX_COMPILER_VERSION} VERSION_GREATER 6.0.0 OR ${CMAKE_CXX_COMPILER_VERSION} VERSION_EQUAL 6.0.0)
		set_source_files_properties(cJSON.c PROPERTIES COMPILE_FLAGS "-Wno-error=misleading-indentation")
	endif()
	set_source_files_properties(stun/stun.c PROPERTIES COMPILE_FLAGS "-Wno-error=sign-compare")
endif()

add_library(flexisip SHARED ${FLEXISIP_SOURCES})
set_property(TARGET flexisip PROPERTY CXX_STANDARD 11)
set_property(TARGET flexisip PROPERTY CXX_STANDARD_REQUIRED ON)

if(FLEXISIP_DEPENDENCIES)
	add_dependencies(flexisip ${FLEXISIP_DEPENDENCIES})
endif()
add_dependencies(flexisip flexisip-git-version)
target_compile_features(flexisip PRIVATE cxx_auto_type cxx_variadic_macros)
target_link_libraries(flexisip ${FLEXISIP_LIBS})
target_include_directories(flexisip PUBLIC ${FLEXISIP_INCLUDES})

add_executable(flexisip_server main.cc)
set_property(TARGET flexisip_server PROPERTY OUTPUT_NAME flexisip)
set_property(TARGET flexisip_server PROPERTY CXX_STANDARD 11)
set_property(TARGET flexisip_server PROPERTY CXX_STANDARD_REQUIRED ON)
target_compile_features(flexisip_server PRIVATE cxx_auto_type cxx_variadic_macros)
target_link_libraries(flexisip_server flexisip)

install(TARGETS flexisip flexisip_server
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

add_executable(flexisip_pusher tools/pusher.cc)
target_link_libraries(flexisip_pusher flexisip)
set_property(TARGET flexisip_pusher PROPERTY CXX_STANDARD 11)
set_property(TARGET flexisip_pusher PROPERTY CXX_STANDARD_REQUIRED ON)

install(TARGETS flexisip_pusher
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

# Build plugins.
if(ENABLE_JWE_AUTH_PLUGIN)
	add_subdirectory(plugin/jwe-auth-plugin)
endif()

# expression parser tester
if(MEDIASTREAMER2_FOUND)
	add_executable(expr test/expr.cc expressionparser.cc expressionparser.hh sipattrextractor.hh utils/flexisip-exception.hh)
	target_link_libraries(expr ${BCTOOLBOX_CORE_LIBRARIES} ${ORTP_LIBRARIES} ${MEDIASTREAMER2_LIBRARIES})
	set_property(TARGET expr PROPERTY CXX_STANDARD 11)
	set_property(TARGET expr PROPERTY CXX_STANDARD_REQUIRED ON)
	target_compile_options(expr PUBLIC -DTEST_BOOL_EXPR -DNO_SOFIA)
endif()

add_executable(flexisip_serializer tools/serializer.cc)
target_link_libraries(flexisip_serializer flexisip)
set_property(TARGET flexisip_serializer PROPERTY CXX_STANDARD 11)
set_property(TARGET flexisip_serializer PROPERTY CXX_STANDARD_REQUIRED ON)

install(TARGETS flexisip_serializer
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)
