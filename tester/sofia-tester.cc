/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include "utils/server/tls-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip {
namespace tester {
namespace sofia_tester_suite {

class NthEngineTest : public Test {
public:
	void operator()() override {
		sofiasip::SuRoot root{};
		TlsServer server{};
		bool requestReceived = false;
		auto requestMatch = async(launch::async, [&server, &requestReceived, sni = mShouldSniBePresent]() {
			server.accept(sni ? "127.0.0.1" : ""); // SNI checks are done in TlsServer::accept.
			server.read();
			server.send("Status: 200");
			return requestReceived = true;
		});

		auto url = "https://127.0.0.1:" + to_string(server.getPort());
		const auto engine = nth_engine_create(root.getCPtr(), TPTAG_TLS_SNI(mShouldSniBePresent), TAG_END());

		nth_client_t* request = nth_client_tcreate(
		    engine,
		    []([[maybe_unused]] nth_client_magic_t* magic, [[maybe_unused]] nth_client_t* request,
		       [[maybe_unused]] const http_t* http) { return 0; },
		    nullptr, http_method_get, "GET", URL_STRING_MAKE(url.c_str()), TAG_END());

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

protected:
	NthEngineTest(bool shouldSniBePresent) : mShouldSniBePresent(shouldSniBePresent){};

private:
	bool mShouldSniBePresent;
};

class NthEngineWithSniTest : public NthEngineTest {
public:
	NthEngineWithSniTest() : NthEngineTest(true){};
};

class NthEngineWithoutSniTest : public NthEngineTest {
public:
	NthEngineWithoutSniTest() : NthEngineTest(false){};
};

namespace {
TestSuite _("Sofia suite",
            {
                TEST_NO_TAG("Test sofia nth_engine, with TLS SNI enabled.", run<NthEngineWithSniTest>),
                TEST_NO_TAG("Test sofia nth_engine, with TLS SNI support disabled.", run<NthEngineWithoutSniTest>),
            });
}
} // namespace sofia_tester_suite
} // namespace tester
} // namespace flexisip
