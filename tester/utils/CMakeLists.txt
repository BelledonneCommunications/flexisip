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
###########################################################################

add_library(flexisip_tester_utils
	asserts.hh
	audio/wave.cc audio/wave.hh
	bc-utils.cc bc-utils.hh
	bellesip-utils.cc bellesip-utils.hh
	call-assert.hh
	call-builder.cc call-builder.hh
	call-listeners.cc call-listeners.hh
	chat-room-builder.cc chat-room-builder.hh
	cli-helper.hh
	client-builder.cc client-builder.hh
	client-call.cc client-call.hh
	client-core.cc client-core.hh
	contact-inserter.cc contact-inserter.hh
	core-assert.hh
	custom-user-agent-behavior.hh
	eventlogs/event-logs.cc eventlogs/event-logs.hh
	eventlogs/writers/event-log-writer-visitor-adapter.hh
	flow-test-helper.cc flow-test-helper.hh
	http-mock/http1-mock.cc http-mock/http1-mock.hh
	listeners.hh
	listening-socket.cc listening-socket.hh
	nat-test-helper.cc nat-test-helper.hh
	random.cc random.hh
	server/injected-module-info.cc server/injected-module-info.hh
	server/proxy-server.cc server/proxy-server.hh
	server/redis-server.cc server/redis-server.hh
	server/tls-tcp-server.cc server/tls-tcp-server.hh
	test-patterns/agent-test.hh
	test-patterns/registrardb-test.hh
	test-patterns/test.hh
	tls/private-key.cc tls/private-key.hh
	tls/certificate.cc tls/certificate.hh
	tmp-dir.cc tmp-dir.hh
)

add_dependencies(flexisip_tester_utils flexisip-git-version)
target_include_directories(flexisip_tester_utils PUBLIC
	${PROJECT_BINARY_DIR}/
	${PROJECT_BINARY_DIR}/include/
	${CMAKE_CURRENT_SOURCE_DIR}/
	${CMAKE_CURRENT_BINARY_DIR}/
)

if(ENABLE_SOCI)
	target_sources(flexisip_tester_utils PRIVATE
		server/mysql/db-server-configurer.hh
		server/mysql/mysql-server.cc server/mysql/mysql-server.hh
		soci/soci-tester-utils.cc soci/soci-tester-utils.hh
	)
	if(IS_MARIADB)
		target_sources(flexisip_tester_utils PRIVATE
			server/mysql/mariadb-configurer.cc
			server/mysql/mariadb-configurer.hh
		)
	else()
		target_sources(flexisip_tester_utils PRIVATE
			server/mysql/mysql-configurer.cc
			server/mysql/mysql-configurer.hh
		)
	endif()
endif()

if(ENABLE_REDIS)
	target_link_libraries(flexisip_tester_utils PRIVATE hiredis::hiredis)
	if(ENABLE_REDIS_TLS)
		target_link_libraries(flexisip_tester_utils PRIVATE hiredis_ssl)
	endif()
endif()

if(LIBNGHTTP2ASIO_FOUND AND ENABLE_UNIT_TESTS_NGHTTP2ASIO)
	target_sources(flexisip_tester_utils PRIVATE
		http-mock/http-mock.cc http-mock/http-mock.hh
		pns-mock.cc pns-mock.hh
	)
elseif(ENABLE_UNIT_TESTS_NGHTTP2ASIO)
	message(FATAL_ERROR "The LibNgHttp2Asio module is required by some tests. You may disable them with -DENABLE_UNIT_TESTS_NGHTTP2ASIO=OFF")
endif()

if(ENABLE_PRESENCE)
	target_sources(flexisip_tester_utils PRIVATE
		test-patterns/presence-test.hh
	)
endif()

if(ENABLE_B2BUA)
	target_sources(flexisip_tester_utils PRIVATE
		server/b2bua-and-proxy-server.cc server/b2bua-and-proxy-server.hh
	)
endif()

if(ENABLE_REGEVENT)
	target_sources(flexisip_tester_utils PRIVATE
		server/regevent-server.cc server/regevent-server.hh
	)
endif()

# C++ 20 adds the support for char8_t which adds a lot of backward compatibility problems.
# See: https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2019/p1423r3.html
# So for now disable it until we need it.
list(APPEND CXX_BUILD_FLAGS "-fno-char8_t")

target_compile_options(flexisip_tester_utils PUBLIC ${CPP_BUILD_FLAGS} ${CXX_BUILD_FLAGS})
target_link_libraries(flexisip_tester_utils PUBLIC
	${BOOST_TARGET}
	OpenSSL::Crypto
	OpenSSL::SSL
	bctoolbox-tester
	flexisip
	mediastreamer2
	ortp
	jsoncpp_lib
	XercesC::XercesC
)

if(LIBNGHTTP2ASIO_FOUND AND ENABLE_UNIT_TESTS_NGHTTP2ASIO)
	target_link_libraries(flexisip_tester_utils PUBLIC LibNgHttp2Asio)
endif()