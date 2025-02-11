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

#include <chrono>
#include <string>

#include "module-authorization.hh"

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "sofia-wrapper/nta-agent.hh"
#include "sofia-wrapper/nta-outgoing-transaction.hh"
#include "utils/core-assert.hh"
#include "utils/http-mock/http-mock.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::string_literals;
using namespace sofiasip;
using namespace flexisip;
using namespace flexisip::tester;

namespace {
constexpr auto domain = "a.example.org";
constexpr auto sleepInterval = std::chrono::nanoseconds(std::chrono::milliseconds(30));

InjectedHooks forceTrustedHost{
    .onRequest =
        [](unique_ptr<RequestSipEvent>&& ev) {
	        ev->setTrustedHost();
	        return std::move(ev);
        },
};

auto sendRequest(sofiasip::NtaAgent& UAC, const std::string& dstPort, int CSeq) {
	const auto sipUri = "sip:user@"s + domain;
	// clang-format off
	const auto request = std::string(std::string("REGISTER ") + sipUri + " SIP/2.0\r\n"
	                                 "Max-Forwards: 5\r\n"
	                                 "To: <" + sipUri + ">\r\n"
	                                 "From: <" + sipUri + ">;tag=465687829\r\n"
	                                 "Call-ID: 1053183492\r\n"
	                                 "CSeq: " + to_string(CSeq) + " REGISTER\r\n"
	                                 "Contact: <" + sipUri + ";>;+sip.instance=fcm1Reg\r\n"
	                                 "Expires: 3600\r\n"
	                                 "Content-Length: 0\r\n");
	// clang-format on
	return UAC.createOutgoingTransaction(request, "sip:127.0.0.1:"s + dstPort);
}

void dynamicDomainLoading() {
	constexpr auto apiPath = "/api/spaces";
	http_mock::HttpMock server{apiPath};
	nlohmann::json spaces = {
	    {
	        {"domain", "example.org"},
	        {"super", true},
	    },
	    {
	        {"domain", domain},
	        {"super", false},
	    },
	};

	BC_HARD_ASSERT_TRUE(server.addResponseToGET(apiPath, spaces.dump()));
	const auto port = server.serveAsync();

	Server proxy(
	    {
	        {"module::Registrar/reg-domains", "*.example.org"},
	        {"module::Authorization/enabled", "true"},
	        {"module::Authorization/account-manager-host", "127.0.0.1"},
	        {"module::Authorization/account-manager-port", to_string(port)},
	    },
	    &forceTrustedHost);

	proxy.start();
	auto root = proxy.getRoot();

	NtaAgent UAClient(root, "sip:127.0.0.1:0");
	int CSeq = 1;
	auto transaction = sendRequest(UAClient, proxy.getFirstPort(), CSeq);

	CoreAssert<sleepInterval> asserter{root};
	asserter
	    .iterateUpTo(
	        64,
	        [&] {
		        if (transaction->getStatus() == 403) {
			        transaction = sendRequest(UAClient, proxy.getFirstPort(), ++CSeq);
		        }
		        FAIL_IF(transaction->getStatus() != 200);
		        return ASSERTION_PASSED();
	        },
	        1s)
	    .assert_passed();

	server.forceCloseServer();
	root->step(10ms); // needed to acknowledge mock server closing
}

const TestSuite kSuite{"AuthorizationWithFAM",
                       {
                           CLASSY_TEST(dynamicDomainLoading),
                       }};
} // namespace