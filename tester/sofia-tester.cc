/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <future>

#include "sofia-sip/http.h"
#include "sofia-sip/nth.h"
#include "sofia-sip/tport_tag.h"

#include "flexisip/sofia-wrapper/su-root.hh"

#include "utils/transport/tls-connection.hh"

#include "utils/core-assert.hh"
#include "utils/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tls-server.hh"

using namespace std;
using namespace sofiasip;

namespace flexisip::tester::sofia_tester_suite {

/*
 * Test sofia-SIP nth_engine, with TLS SNI enabled/disabled.
 */
template <bool tlsSniEnabled>
void nthEngineWithSni() {
	SuRoot root{};
	TlsServer server{};
	auto requestReceived = false;
	auto requestMatch = async(launch::async, [&server, &requestReceived]() {
		server.accept(tlsSniEnabled ? "127.0.0.1" : ""); // SNI checks are done in TlsServer::accept.
		server.read();
		server.send("Status: 200");
		return requestReceived = true;
	});

	const auto url = "https://127.0.0.1:" + to_string(server.getPort());
	auto* engine = nth_engine_create(root.getCPtr(), TPTAG_TLS_SNI(tlsSniEnabled), TAG_END());

	auto* request =
	    nth_client_tcreate(engine, nullptr, nullptr, http_method_get, "GET", URL_STRING_MAKE(url.c_str()), TAG_END());

	if (request == nullptr) {
		BC_FAIL("No request sent.");
	}

	while (!requestReceived) {
		root.step(10ms);
	}

	BC_ASSERT_TRUE(requestMatch.get());
	nth_client_destroy(request);
	nth_engine_destroy(engine);
}

/*
 * Test that Sofia-SIP closes connections that were inactive for more than 'idle-timeout' seconds.
 * This should be the case even if no data has ever passed through this connection.
 */
void connectionToServerIsRemovedAfterIdleTimeoutTriggers() {
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0"},
	    {"global/idle-timeout", "1"},
	}};
	proxy.start();

	// Create TCP connection to server.
	auto connection = TlsConnection{"127.0.0.1", proxy.getFirstPort(), "", ""};
	connection.connect();
	BC_ASSERT(connection.isConnected());

	// Verify it is now disconnected, closed from the server because of inactivity.
	vector<char> data{};
	BC_ASSERT(CoreAssert{proxy}.iterateUpTo(
	    0x20,
	    [&]() {
		    std::ignore = connection.read(data, 32);
		    FAIL_IF(connection.isConnected());
		    return ASSERTION_PASSED();
	    },
	    2s));
}

namespace {
TestSuite _("Sofia-SIP",
            {
                CLASSY_TEST(nthEngineWithSni<true>),
                CLASSY_TEST(nthEngineWithSni<false>),
                CLASSY_TEST(connectionToServerIsRemovedAfterIdleTimeoutTriggers),
            });
}

} // namespace flexisip::tester::sofia_tester_suite