/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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
#include "tester.hh"
#include "utils/core-assert.hh"
#include "utils/server/tls-tcp-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace sofiasip;

namespace flexisip::tester::sofia_tester_suite {
namespace {

/*
 * Test Sofia-SIP nth_engine, with TLS SNI enabled/disabled.
 */
template <bool tlsSniEnabled>
void nthEngineWithSni() {
	SuRoot root{};
	TlsServer server{0, tlsSniEnabled ? "127.0.0.1" : ""}; // SNI checks are done in TlsServer::accept.
	auto requestReceived = false;
	auto requestMatch = async(launch::async, [&server, &requestReceived]() {
		server.accept();
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

	CoreAssert<kNoSleep>(root)
	    .waitUntil(100ms, [&requestReceived] { return LOOP_ASSERTION(requestReceived); })
	    .assert_passed();

	BC_ASSERT_TRUE(requestMatch.get());
	nth_client_destroy(request);
	nth_engine_destroy(engine);
}

/*
 * A crash could happen when the following error was returned by tport_resolve: "Name or service not known" (the primary
 * transport was destroyed in 'nth_client_destroy').
 * The crash appears on the second attempt to send an HTTP request. This is because it tries to make use of the primary
 * transport (which is nullptr because of the first attempt) in the tport_by_name function.
 */
void nthClientNameOrServiceNotKnown() {
	SuRoot root{};
	const auto* url = "https://sip.example.org:1234";
	const auto deleter = [](nth_engine_t* engine) { nth_engine_destroy(engine); };
	unique_ptr<nth_engine_t, decltype(deleter)> engine{
	    nth_engine_create(root.getCPtr(), TPTAG_TLS_SNI(true), TAG_END()),
	    deleter,
	};

	struct Helper {
		int status = 0;
	};
	Helper h;

	const auto cb = [](nth_client_magic_t* magic, nth_client_t* request, const http_t*) {
		reinterpret_cast<Helper*>(magic)->status = nth_client_status(request);
		nth_client_destroy(request);
		return 0;
	};

	for (int id = 0; id < 2; ++id) {
		auto* request = nth_client_tcreate(engine.get(), cb, reinterpret_cast<nth_client_magic_t*>(&h), http_method_get,
		                                   "GET", URL_STRING_MAKE(url), TAG_END());
		if (request == nullptr) BC_FAIL("No request sent.");
		h.status = 0;
		CoreAssert<kNoSleep>(root).waitUntil(100ms, [&h] { return LOOP_ASSERTION(h.status == 503); }).assert_passed();
	}
}

TestSuite _{
    "sofia::nth",
    {
        CLASSY_TEST(nthEngineWithSni<true>),
        CLASSY_TEST(nthEngineWithSni<false>),
        CLASSY_TEST(nthClientNameOrServiceNotKnown),
    },
};

} // namespace
} // namespace flexisip::tester::sofia_tester_suite
