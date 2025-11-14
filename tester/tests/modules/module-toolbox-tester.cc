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

#include "modules/module-toolbox.hh"


#include "flexisip/module-router.hh"
#include "tester.hh"
#include "utils/bellesip-utils.hh"
#include "utils/test-patterns/registrardb-test.hh"
#include "utils/test-suite.hh"
#include "utils/tls/certificate.hh"
#include "utils/tls/private-key.hh"
#include "utils/tmp-dir.hh"

using namespace std;
using namespace std::chrono_literals;
using namespace std::chrono;
using namespace flexisip;
using namespace flexisip::tester;

namespace flexisip::tester {
namespace {

////////////////// START OF ModuleToolbox::addRecordRoute TESTS /////////////////////////

class AddRecordRouteTest : public AgentTest {
protected:
	AddRecordRouteTest(const string& mTransport, const string& mRecordRouteExpected)
	    : mTransport(mTransport), mRecordRouteExpected(mRecordRouteExpected), mTmpDir{"AddRecordRouteTest"} {
	}

	string mTransport;
	string mRecordRouteExpected;

private:
	string rawSipInvite = "INVITE sip:participant1@127.0.0.1:5360 SIP/2.0\r\n"
	                      "To: <sip:participant1@127.0.0.1>\r\n"
	                      "From: <sip:anthony@127.0.0.1>;tag=465687829\r\n"
	                      "Call-ID: Y2NlNzg0ODc0ZGIxODU1MWI5MzhkNDVkNDZhOTQ4YWU.\r\n"
	                      "CSeq: 1 INVITE\r\n"
	                      "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, PRACK\r\n"
	                      "Content-Type: application/sdp\r\n"
	                      "\r\n"
	                      // Request body
	                      "v=0\r\n";

	void onAgentConfiguration(ConfigManager& cfg) override {
		AgentTest::onAgentConfiguration(cfg);

		filesystem::path pemPath = mTmpDir.path() / "agent.pem";
		const TlsPrivateKey privateKey{};
		const TlsCertificate certificate{privateKey};
		privateKey.writeToFile(pemPath);
		certificate.appendToFile(pemPath);
		cfg.getRoot()->get<GenericStruct>("global")->get<ConfigString>("tls-certificates-dir")->set(mTmpDir.path());

		const auto* globalCfg = cfg.getRoot()->get<GenericStruct>("global");
		globalCfg->get<ConfigStringList>("transports")->set(mTransport);

		cfg.getRoot()->get<GenericStruct>("module::DoSProtection")->get<ConfigBoolean>("enabled")->set("false");
	}

	void testExec() override {
		const auto msgSip = make_shared<MsgSip>(0, rawSipInvite);
		const auto requestSipEvent = RequestSipEvent::makeRestored(mAgent, msgSip, mAgent->findModuleByRole("Router"));

		SLOGD << "############# REQUEST WITHOUT RECORD-ROUTE #############";
		SLOGD << requestSipEvent->getMsgSip()->msgAsString();
		SLOGD << "########################################################";

		ModuleToolbox::addRecordRoute(mAgent.get(), *requestSipEvent, nullptr);

		SLOGD << "############# REQUEST WITH RECORD-ROUTE #############";
		SLOGD << requestSipEvent->getMsgSip()->msgAsString();
		SLOGD << "########################################################";

		BC_ASSERT_TRUE(requestSipEvent->getMsgSip()->msgAsString().find(mRecordRouteExpected) != std::string::npos);
	}

	TmpDir mTmpDir;
};

class SipAddRecordRouteTest : public AddRecordRouteTest {
public:
	SipAddRecordRouteTest() : AddRecordRouteTest("sip:127.0.0.1:6060", "Record-Route: <sip:127.0.0.1:6060;lr>") {
	}
};

class SipsAddRecordRouteTest : public AddRecordRouteTest {
public:
	SipsAddRecordRouteTest()
	    : AddRecordRouteTest("sips:127.0.0.1:6061", "Record-Route: <sips:127.0.0.1:6061;lr>") {
	}
};

////////////////// END OF ModuleToolbox::addRecordRoute TESTS /////////////////////////

void isPrivateAddress() {
	BC_ASSERT(module_toolbox::isPrivateAddress("10.0.0.1") == true);
	BC_ASSERT(module_toolbox::isPrivateAddress("10.255.255.255") == true);
	BC_ASSERT(module_toolbox::isPrivateAddress("172.16.132.12") == true);
	BC_ASSERT(module_toolbox::isPrivateAddress("172.25.46.55") == true);
	BC_ASSERT(module_toolbox::isPrivateAddress("172.31.224.188") == true);
	BC_ASSERT(module_toolbox::isPrivateAddress("192.168.0.2") == true);
	BC_ASSERT(module_toolbox::isPrivateAddress("192.168.100.42") == true);

	BC_ASSERT(module_toolbox::isPrivateAddress("0.0.0.0") == false);
	BC_ASSERT(module_toolbox::isPrivateAddress("1.2.3.4") == false);
	BC_ASSERT(module_toolbox::isPrivateAddress("127.0.0.1") == false);
	BC_ASSERT(module_toolbox::isPrivateAddress("172.15.0.1") == false);
	BC_ASSERT(module_toolbox::isPrivateAddress("172.32.0.1") == false);
	BC_ASSERT(module_toolbox::isPrivateAddress("255.255.255.255") == false);
}

TestSuite _{
    "module_toolbox",
    {
        CLASSY_TEST(SipAddRecordRouteTest),
        CLASSY_TEST(SipsAddRecordRouteTest),
        CLASSY_TEST(isPrivateAddress),
    },
};
} // namespace
} // namespace flexisip::tester