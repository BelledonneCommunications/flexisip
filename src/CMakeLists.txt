############################################################################
# CMakeLists.txt
# Copyright (C) 2014  Belledonne Communications, Grenoble France
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
############################################################################

set(FLEXISIP_LIBS ${ORTP_LIBRARIES} ${SOFIASIPUA_LIBRARIES})

set(FLEXISIP_INCLUDES)

set(FLEXISIP_DEPENDENCIES)

file(GLOB FLEXISIP_UTILS_SRC utils/*.cc utils/*.hh)

set(FLEXISIP_SOURCES
	agent.cc agent.hh
	common.cc common.hh
	sdp-modifier.hh sdp-modifier.cc
	callstore.hh callstore.cc
	forkcontext.hh forkcontext.cc
	callcontext-mediarelay.hh callcontext-mediarelay.cc
	forkcallcontext.hh forkcallcontext.cc
	forkmessagecontext.hh forkmessagecontext.cc
	forkbasiccontext.cc forkbasiccontext.hh
	registrardb-internal.cc registrardb-internal.hh registrardb.cc registrardb.hh
	recordserializer-c.cc recordserializer.hh
	recordserializer-json.cc cJSON.c cJSON.h
	etchosts.cc etchosts.hh
	lpconfig.cc lpconfig.h
	configmanager.cc configmanager.hh
	configdumper.hh configdumper.cc
	event.cc event.hh
	transaction.cc transaction.hh
	module.cc module.hh
	monitor.cc monitor.hh
	entryfilter.cc entryfilter.hh
	stun.cc stun.hh
	stun/stun.c stun/stun_udp.c stun/flexisip_stun.h stun/flexisip_stun_udp.h
	mediarelay.cc mediarelay.hh
	authdb.hh authdb.cc authdb-file.cc
	module-sanitychecker.cc
	module-garbage-in.cc
	module-forward.cc
	module-gatewayadapter.cc
	module-contact-route-inserter.cc
	module-nat-helper.cc
	module-registrar.cc
	module-router.cc lateforkapplier.hh
	module-transcode.cc
	module-statistics-collector.cc
	module-mediarelay.cc
	module-auth.cc
	module-loadbalancer.cc
	module-dos.cc
	expressionparser.cc expressionparser.hh
	sipattrextractor.cc sipattrextractor.hh
	h264iframefilter.cc h264iframefilter.hh
	telephone-event-filter.cc telephone-event-filter.hh
	log/logmanager.cc log/logmanager.hh
	eventlogs/eventlogs.cc eventlogs/eventlogs.hh
	contact-masquerader.cc contact-masquerader.hh
	uac-register.cc uac-register.hh
	module-redirect.cc module-presence.cc
	domain-registrations.cc domain-registrations.hh
	${FLEXISIP_UTILS_SRC}
)

find_package(Git)
add_custom_target(flexisip-git-version
	COMMAND ${CMAKE_COMMAND} -DGIT_EXECUTABLE=${GIT_EXECUTABLE} -DFLEXISIP_VERSION=${FLEXISIP_VERSION} -DWORK_DIR=${CMAKE_CURRENT_SOURCE_DIR} -DOUTPUT_DIR=${CMAKE_CURRENT_BINARY_DIR} -P ${CMAKE_CURRENT_SOURCE_DIR}/gitversion.cmake
	BYPRODUCTS "${CMAKE_CURRENT_BINARY_DIR}/flexisip_gitversion.h"
)


function(ADD_XSD_WRAPPERS file _comment)
	set(destinations ${CMAKE_CURRENT_BINARY_DIR}/xml/${file}.hxx ${CMAKE_CURRENT_BINARY_DIR}/xml/${file}.cxx)
	set(source ${CMAKE_CURRENT_LIST_DIR}/xml/${file}.xsd)
	file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/xml")

	set(regex "%http://.+/(.+)%\\\$$1%")

	add_custom_command(OUTPUT ${destinations}
		COMMAND "${XSDCXX_PROG}" "cxx-tree" "--generate-wildcard"
  			"--generate-serialization" "--generate-ostream"
  			"--generate-detach" "--std" "c++11" "--type-naming" "java"
			"--function-naming" "java"  "--location-regex-trace"
			"--location-regex" "\"${regex}\""
			"--output-dir" "${CMAKE_CURRENT_BINARY_DIR}/xml" "${source}"
		COMMENT "${_comment}")

	add_custom_target(${file} DEPENDS ${destinations})

	set_source_files_properties(${destinations} PROPERTIES GENERATED ON)
	set(FLEXISIP_SOURCES ${FLEXISIP_SOURCES} ${destinations} PARENT_SCOPE)
endfunction()

if(ENABLE_XSD)
	list(APPEND FLEXISIP_LIBS ${XERCES_LIBS})
	list(APPEND FLEXISIP_INCLUDES ${XERCES_INCLUDE_DIRS} ${XSDCXX_ROOT_PATH}/libxsd ${CMAKE_CURRENT_BINARY_DIR}/xml)
	list(APPEND FLEXISIP_DEPENDENCIES fthttp)
	ADD_XSD_WRAPPERS(fthttp "Generating XSD for FTHTTP")
endif()



if(ENABLE_ODB)
	#list(APPEND FLEXISIP_LIBS ${ODB_LIBRARIES})
	#list(APPEND FLEXISIP_INCLUDES ${ODB_INCLUDE_DIRS})
	#list(APPEND FLEXISIP_SOURCES eventlogs/eventlogsdb.cc eventlogs/eventlogsdb.hh)
	# TODO: generate the cxx and hxx with ODB
	#eventlogs/eventlogsdb-odb.hxx eventlogs/eventlogsdb-odb.cxx: eventlogs/eventlogsdb.hh
	#	odb $(SOFIA_CFLAGS) $(ORTP_CFLAGS) --std c++11 -d mysql --output-dir eventlogs --generate-query --generate-schema --schema-format embedded $<
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

if(ENABLE_XSD AND ENABLE_PRESENCE)
	list(APPEND FLEXISIP_SOURCES presence/etag-manager.hh)
	list(APPEND FLEXISIP_SOURCES presence/presence-server.cc)
	list(APPEND FLEXISIP_SOURCES presence/presentity-presenceinformation.hh presence/presentity-presenceinformation.cc)
	list(APPEND FLEXISIP_SOURCES presence/bellesip-signaling-exception.hh presence/bellesip-signaling-exception.cc)
	list(APPEND FLEXISIP_SOURCES presence/subscription.hh presence/subscription.cc)
	list(APPEND FLEXISIP_SOURCES presence/list-subscription.hh presence/list-subscription.cc)
	list(APPEND FLEXISIP_LIBS ${BELLESIP_LIBRARIES} ${XERCES_LIBS})
	list(APPEND FLEXISIP_INCLUDES ${BELLESIP_INCLUDE_DIRS} presence)
	add_definitions(-DBELLE_SIP_USE_STL ${BELLE_SIP_CFLAGS})
	ADD_XSD_WRAPPERS(xml "Presence XSD - xml.xsd")
	list(APPEND FLEXISIP_SOURCES xml/xml.xsd)
	ADD_XSD_WRAPPERS(pidf+xml "Presence XSD - pidf+xml.xsd")
	list(APPEND FLEXISIP_SOURCES xml/pidf+xml.xsd)
	ADD_XSD_WRAPPERS(rlmi+xml "Presence XSD - rlmi+xml.xsd")
	list(APPEND FLEXISIP_SOURCES xml/rlmi+xml.xsd)
	ADD_XSD_WRAPPERS(resource-lists "Presence XSD - resource-lists.xsd")
	list(APPEND FLEXISIP_SOURCES xml/resource-lists.xsd)

	list(APPEND FLEXISIP_DEPENDENCIES xml pidf+xml rlmi+xml resource-lists)
endif()

if(ENABLE_PUSHNOTIFICATION)
	file(GLOB PUSHNOTIFICATION_SRCS pushnotification/*.cc pushnotification/*.hh)
	list(APPEND FLEXISIP_SOURCES module-pushnotification.cc ${PUSHNOTIFICATION_SRCS})
	list(APPEND FLEXISIP_LIBS ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES})
	list(APPEND FLEXISIP_INCLUDES ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIRS})
endif()

if(ENABLE_SOCI)
	list(APPEND FLEXISIP_SOURCES authdb-soci.cc)
	list(APPEND FLEXISIP_LIBS ${SOCI_LIBRARY})
	list(APPEND FLEXISIP_INCLUDES ${SOCI_INCLUDE_DIRS} ${SOCI_MYSQL_INCLUDES})
endif()

message(STATUS "Flexisip LIBS : ${FLEXISIP_LIBS}")
message(STATUS "Flexisip INCLUDES : ${FLEXISIP_INCLUDES}")
message(STATUS "Flexisip DEPENDENCIES : ${FLEXISIP_DEPENDENCIES}")

add_library(flexisip SHARED ${FLEXISIP_SOURCES})
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
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

# expression parser tester
if(MEDIASTREAMER2_FOUND)
	add_executable(expr test/expr.cc expressionparser.cc expressionparser.hh sipattrextractor.hh utils/flexisip-exception.cc utils/flexisip-exception.hh)
	target_link_libraries(expr ${ORTP_LIBRARIES} ${MEDIASTREAMER2_LIBRARIES})
	set_property(TARGET expr PROPERTY CXX_STANDARD 11)
	set_property(TARGET expr PROPERTY CXX_STANDARD_REQUIRED ON)
	target_compile_options(expr PUBLIC -DTEST_BOOL_EXPR -DNO_SOFIA)
endif()

if (ENABLE_PUSHNOTIFICATION)
	add_executable(flexisip_pusher tools/pusher.cc)
	target_link_libraries(flexisip_pusher flexisip)
	set_property(TARGET flexisip_pusher PROPERTY CXX_STANDARD 11)
	set_property(TARGET flexisip_pusher PROPERTY CXX_STANDARD_REQUIRED ON)

	install(TARGETS flexisip_pusher
		RUNTIME DESTINATION bin
		LIBRARY DESTINATION lib
		ARCHIVE DESTINATION lib
		PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	)
endif()
