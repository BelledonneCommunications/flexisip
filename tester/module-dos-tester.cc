/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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
#include "utils/test-patterns/agent-test.hh"

#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono;

namespace flexisip {
namespace tester {

class TestBanExecutor : public BanExecutor {
public:
	void checkConfig() override{};
	void onLoad([[maybe_unused]] const flexisip::GenericStruct* dosModuleConfig) override{};
	void onUnload() override{};
	void banIP([[maybe_unused]] const std::string& ip,
	           [[maybe_unused]] const std::string& port,
	           [[maybe_unused]] const std::string& protocol) override {
		banIPCalls++;
	};

	void unbanIP([[maybe_unused]] const std::string& ip,
	             [[maybe_unused]] const std::string& port,
	             [[maybe_unused]] const std::string& protocol) override{};

	int banIPCalls = 0;
};

template <typename ProtocolConfig>
class BanTest : public AgentTest {
private:
	std::shared_ptr<ProtocolConfig> protocolConfig = make_shared<ProtocolConfig>();

	void onAgentConfiguration(ConfigManager& cfg) override {
		AgentTest::onAgentConfiguration(cfg);
		const auto* globalCfg = cfg.getRoot()->get<GenericStruct>("global");
		globalCfg->get<ConfigStringList>("transports")->set("sip:127.0.0.1:6060");

		cfg.getRoot()->get<GenericStruct>("module::DoSProtection")->get<ConfigBoolean>("enabled")->set("true");
		cfg.getRoot()
		    ->get<GenericStruct>("module::DoSProtection")
		    ->get<ConfigInt>("packet-rate-limit")
		    ->set(to_string(packetRateLimit));
		cfg.getRoot()
		    ->get<GenericStruct>("module::DoSProtection")
		    ->get<ConfigDuration<chrono::milliseconds>>("time-period")
		    ->set(to_string(timePeriod.count()));
	}

	void testExec() override {
		const auto testExecutor = make_shared<TestBanExecutor>();

		const auto moduleDos = dynamic_pointer_cast<ModuleDoSProtection>(mAgent->findModule("DoSProtection"));
		moduleDos->clearWhiteList();
		moduleDos->setBanExecutor(testExecutor);

		BellesipUtils bellesipUtils{"0.0.0.0", -1, protocolConfig->getProtocol(), nullptr};

		int i = 0;
		const auto before = system_clock::now();
		const auto beforePlus2 = before + 2 * timePeriod;
		const auto sleepDuration = 5ms;
		while (!(testExecutor->banIPCalls > 0) && beforePlus2 >= system_clock::now()) {
			// clang-format off
			bellesipUtils.sendRawRequest("MESSAGE sip:provencal_le_gaulois@sip.test.org SIP/2.0\r\n"
			                             "Via: SIP/2.0/TCP 127.0.0.1:6066;branch=z9hG4bK.PAWTmCZv1;rport=49828\r\n"
			                             "From: <sip:kijou@sip.linphone.org;gr=8aabdb1c>;tag=l3qXxwsO~\r\n"
			                             "To: <sip:provencal_le_gaulois@sip.test.org>\r\n"
			                             "CSeq: 20 MESSAGE\r\n"
			                             "Call-ID: Tvw6USHXYv" + std::to_string(i++) + "\r\n"
										 "Max-Forwards: 70\r\n"
			                             "Route: <sip:127.0.0.1:6060;transport=" + protocolConfig->getProtocol() + ";lr>\r\n"
			                             "Supported: replaces, outbound, gruu\r\n"
			                             "Date: Fri, 01 Apr 2022 11:18:26 GMT\r\n"
			                             "Content-Type: text/plain\r\n",
			                             "C'est pas faux \r\n\r\n");
			// clang-format on
			waitFor(sleepDuration);
			bellesipUtils.stackSleep(sleepDuration.count());
		}
		const auto after = system_clock::now();
		const auto testDuration = duration_cast<milliseconds>(after - before);

		BC_ASSERT_GREATER_STRICT(testDuration.count(), timePeriod.count(), int, "%i");
		const auto maxTestTime = timePeriod + timePeriod * 0.1;
		BC_ASSERT_LOWER_STRICT(testDuration.count(), maxTestTime.count(), int, "%i");

		BC_ASSERT_GREATER(i, packetRateLimit, int, "%i");
		// BC_ASSERT_LOWER(i, (timePeriod.count() / 1000) * packetRateLimit, int, "%i");
		// --> impossible because packet-rate is only checked when time-elapsed > time-period, so packet rate can be
		// already higher at this point.

		BC_ASSERT_GREATER_STRICT(testExecutor->banIPCalls, 0, int, "%i");
		/* We can't test unban for now because configuration is in minute */
	}

	chrono::milliseconds timePeriod = 1000ms;
	int packetRateLimit = 20;
};

class TCPConfig {
public:
	static string getProtocol() {
		return "tcp";
	};
};

class UDPConfig {
public:
	static string getProtocol() {
		return "udp";
	};
};

namespace {
TestSuite _("Module DOS unit tests",
            {
                TEST_NO_TAG("Dos protection module UDP ban test", run<BanTest<UDPConfig>>),
                TEST_NO_TAG("Dos protection module TCP ban test", run<BanTest<TCPConfig>>),
            });
}
} // namespace tester
} // namespace flexisip
