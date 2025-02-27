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

#include <chrono>

#include <bctoolbox/tester.h>

#include "flexisip/dos/module-dos.hh"

#include "dos/dos-executor/ban-executor.hh"
#include "utils/bellesip-utils.hh"
#include "utils/core-assert.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/agent-test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono;

namespace flexisip::tester {
namespace {

class TestBanExecutor : public BanExecutor {
public:
	void checkConfig() override{};
	void onLoad(const flexisip::GenericStruct*) override{};
	void onUnload() override{};
	void banIP(const std::string&, const std::string&, const std::string&) override {
		banIPCalls++;
	};
	void unbanIP(const std::string&, const std::string&, const std::string&) override{};

	int banIPCalls = 0;
};

template <const string& transportProtocol>
void ban() {
	const auto timePeriod = 1000ms;
	const auto packetRateLimit = 15;
	Server server{{
	    {"module::DoSProtection/enabled", "true"},
	    {"module::DoSProtection/packet-rate-limit", to_string(packetRateLimit)},
	    {"module::DoSProtection/time-period", to_string(timePeriod.count())},
	}};
	server.start();

	const auto& testExecutor = make_shared<TestBanExecutor>();
	const auto& moduleDos = dynamic_pointer_cast<ModuleDoSProtection>(server.getAgent()->findModule("DoSProtection"));
	moduleDos->clearWhiteList();
	moduleDos->setBanExecutor(testExecutor);

	BellesipUtils belleSipUtils{"0.0.0.0", BELLE_SIP_LISTENING_POINT_RANDOM_PORT, transportProtocol, nullptr};
	const auto port = server.getFirstPort();

	int nbRequests = 0;
	const auto before = system_clock::now();
	CoreAssert<kNoSleep>{server, belleSipUtils}
	    .waitUntil(2 * timePeriod,
	               [&belleSipUtils, &nbRequests, &port, &testExecutor]() {
		               stringstream request{};
		               request << "MESSAGE sip:provencal_le_gaulois@sip.test.org SIP/2.0\r\n"
		                       << "Via: SIP/2.0/TCP 127.0.0.1:12345;branch=z9hG4bK.PAWTmCZv1\r\n"
		                       << "From: <sip:kijou@sip.linphone.org;gr=8aabdb1c>;tag=l3qXxwsO~\r\n"
		                       << "To: <sip:provencal_le_gaulois@sip.test.org>\r\n"
		                       << "CSeq: 20 MESSAGE\r\n"
		                       << "Call-ID: stub-call-id-" << nbRequests++ << "\r\n"
		                       << "Max-Forwards: 70\r\n"
		                       << "Route: <sip:127.0.0.1:" << port << ";transport=" << transportProtocol << ">\r\n"
		                       << "Supported: replaces, outbound, gruu\r\n"
		                       << "Date: Fri, 01 Apr 2022 11:18:26 GMT\r\n"
		                       << "Content-Type: text/plain\r\n"
		                       << "Content-Length: 0\r\n\r\n";
		               belleSipUtils.sendRawRequest(request.str());
		               FAIL_IF(testExecutor->banIPCalls <= 0);
		               return ASSERTION_PASSED();
	               })
	    .assert_passed();

	const auto after = system_clock::now();
	const auto testDuration = duration_cast<milliseconds>(after - before);

	BC_ASSERT_GREATER_STRICT(testDuration.count(), timePeriod.count(), int, "%i");
	const auto maxTestTime = timePeriod + timePeriod * 0.20;
	BC_ASSERT_LOWER_STRICT(testDuration.count(), maxTestTime.count(), int, "%i");

	BC_ASSERT_GREATER(nbRequests, packetRateLimit, int, "%i");
	// BC_ASSERT_LOWER(i, (timePeriod.count() / 1000) * packetRateLimit, int, "%i");
	// --> Impossible because packet-rate is only checked when time-elapsed > time-period, so packet rate can
	// already be higher at this point.

	BC_ASSERT_GREATER_STRICT(testExecutor->banIPCalls, 0, int, "%i");

	// TODO: we can't test unban for now because configuration is in minutes.
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