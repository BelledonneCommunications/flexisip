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

#include <bctoolbox/tester.h>

#include "flexisip/dos/module-dos.hh"

#include "dos/dos-executor/ban-executor.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "utils/bellesip-utils.hh"
#include "utils/core-assert.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/agent-test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono;
using namespace sofiasip;

namespace flexisip::tester {
namespace {

class TestBanExecutor : public BanExecutor {
public:
	void checkConfig() override {};
	void onLoad(const flexisip::GenericStruct*) override {};
	void onUnload() override {};
	void banIP(const std::string&, const std::string&, const std::string&) override {
		banIPCalls++;
	};
	void unbanIP(const std::string&, const std::string&, const std::string&) override {};

	int banIPCalls = 0;
};

/**
 * TODO: we can't test unban for now because configuration is in minutes.
 */
template <const string& transportProtocol>
void ban() {
	const auto timePeriod = 100ms;
	const auto packetRateLimit = 20;
	Server server{{
	    {"module::DoSProtection/enabled", "true"},
	    {"module::DoSProtection/packet-rate-limit", to_string(packetRateLimit)},
	    {"module::DoSProtection/time-period", to_string(timePeriod.count())},
	}};
	server.start();
	const auto serverUri = "sip:127.0.0.1:"s + server.getFirstPort() + ";transport=" + transportProtocol;

	const auto& testExecutor = make_shared<TestBanExecutor>();
	const auto& moduleDos =
	    dynamic_pointer_cast<ModuleDoSProtection>(server.getAgent()->findModuleByRole("DoSProtection"));
	moduleDos->clearWhiteList();
	moduleDos->setBanExecutor(testExecutor);

	NtaAgent client{server.getRoot(), "sip:provencal_le_gaulois@127.0.0.1:0"};
	const auto* clientPort = client.getFirstPort();

	// Prepare requests.
	vector<string> requests{};
	const auto maxNbRequests = 100;
	for (auto requestId = 0; requestId < maxNbRequests; requestId++) {
		stringstream request{};
		request << "MESSAGE sip:provencal_le_gaulois@sip.test.org SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.1:" << clientPort << ";branch=z9hG4bK.PAWTmCZv1\r\n"
		        << "From: <sip:kijou@sip.linphone.org;gr=8aabdb1c>;tag=l3qXxwsO~\r\n"
		        << "To: <sip:provencal_le_gaulois@sip.test.org>\r\n"
		        << "CSeq: 20 MESSAGE\r\n"
		        << "Call-ID: stub-call-id-" << requestId << "\r\n"
		        << "Max-Forwards: 70\r\n"
		        << "Route: <" << serverUri << ">\r\n"
		        << "Supported: replaces, outbound, gruu\r\n"
		        << "Date: Fri, 01 Apr 2022 11:18:26 GMT\r\n"
		        << "Content-Type: text/plain\r\n"
		        << "Content-Length: 0\r\n\r\n";
		requests.push_back(request.str());
	}

	auto nbRequests = 0;
	CoreAssert{server}
	    .iterateUpTo(
	        2 * maxNbRequests,
	        [&client, requests, &nbRequests, &serverUri, &testExecutor]() {
		        if (nbRequests >= maxNbRequests)
			        throw runtime_error("no more requests available, this should not happen");

		        std::ignore = client.createOutgoingTransaction(requests[nbRequests++], serverUri);
		        if (testExecutor->banIPCalls >= 1) return ASSERTION_PASSED();

		        return ASSERTION_FAILED("failed to ban IP address in given amount of time");
	        },
	        2 * timePeriod)
	    .assert_passed();

	BC_ASSERT_GREATER_STRICT(testExecutor->banIPCalls, 0, int, "%i");
}

const string UDP = "udp";
const string TCP = "tcp";

TestSuite _("DoSProtectionModule",
            {
                CLASSY_TEST(ban<UDP>),
                CLASSY_TEST(ban<TCP>),
            });

} // namespace
} // namespace flexisip::tester