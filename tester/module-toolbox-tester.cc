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

#include "flexisip/module-router.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

#include "module-toolbox.hh"
#include "utils/bellesip-utils.hh"
#include "utils/test-patterns/registrardb-test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono_literals;
using namespace std::chrono;
using namespace flexisip;
using namespace flexisip::tester;

namespace flexisip {
namespace tester {
namespace module_toolbox_suite {

////////////////// START OF ModuleToolbox::addRecordRoute TESTS /////////////////////////

class AddRecordRouteTest : public AgentTest {
protected:
	AddRecordRouteTest(bool mUseRfc2543RecordRoute, const string& mTransport, const string& mRecordRouteExpected)
	    : mUseRfc2543RecordRoute(mUseRfc2543RecordRoute), mTransport(mTransport),
	      mRecordRouteExpected(mRecordRouteExpected) {
	}

	bool mUseRfc2543RecordRoute;
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
		const auto* globalCfg = cfg.getRoot()->get<GenericStruct>("global");
		globalCfg->get<ConfigStringList>("transports")->set(mTransport);
		globalCfg->get<ConfigBoolean>("use-rfc2543-record-route")->set(mUseRfc2543RecordRoute ? "true" : "false");

		cfg.getRoot()->get<GenericStruct>("module::DoSProtection")->get<ConfigBoolean>("enabled")->set("false");
	}

	void testExec() override {
		const auto msgSip = make_shared<MsgSip>(0, rawSipInvite);
		const auto requestSipEvent = RequestSipEvent::makeRestored(mAgent, msgSip, mAgent->findModule("Router"));

		SLOGD << "############# REQUEST WITHOUT RECORD-ROUTE #############";
		SLOGD << requestSipEvent->getMsgSip()->msgAsString();
		SLOGD << "########################################################";

		ModuleToolbox::addRecordRoute(mAgent.get(), requestSipEvent, nullptr);

		SLOGD << "############# REQUEST WITH RECORD-ROUTE #############";
		SLOGD << requestSipEvent->getMsgSip()->msgAsString();
		SLOGD << "########################################################";

		BC_ASSERT_TRUE(requestSipEvent->getMsgSip()->msgAsString().find(mRecordRouteExpected) != std::string::npos);
	}
};

class SipAddRecordRouteTest : public AddRecordRouteTest {
public:
	SipAddRecordRouteTest() : AddRecordRouteTest(false, "sip:localhost:6060", "Record-Route: <sip:localhost:6060;lr>") {
	}
};

class SipRfc2543AddRecordRouteTest : public AddRecordRouteTest {
public:
	SipRfc2543AddRecordRouteTest()
	    : AddRecordRouteTest(true, "sip:localhost:6060", "Record-Route: <sip:localhost:6060;lr>") {
	}
};

class SipsAddRecordRouteTest : public AddRecordRouteTest {
public:
	SipsAddRecordRouteTest()
	    : AddRecordRouteTest(false, "sips:localhost:6061", "Record-Route: <sips:localhost:6061;lr>") {
	}
};

class SipsRfc2543AddRecordRouteTest : public AddRecordRouteTest {
public:
	SipsRfc2543AddRecordRouteTest()
	    : AddRecordRouteTest(true, "sips:localhost:6061", "Record-Route: <sip:localhost:6061;lr;transport=tls>") {
	}
};

////////////////// END OF ModuleToolbox::addRecordRoute TESTS /////////////////////////

namespace {
TestSuite _("Module toolbox",
            {
                TEST_NO_TAG("ModuleToolbox::addRecordRoute sip", run<SipAddRecordRouteTest>),
                TEST_NO_TAG("ModuleToolbox::addRecordRoute sip with 'use-rfc2543-record-route=true'",
                            run<SipRfc2543AddRecordRouteTest>),
                TEST_NO_TAG("ModuleToolbox::addRecordRoute sips", run<SipsAddRecordRouteTest>),
                TEST_NO_TAG("ModuleToolbox::addRecordRoute sips with 'use-rfc2543-record-route=true'",
                            run<SipsRfc2543AddRecordRouteTest>),
            });
}
} // namespace module_toolbox_suite
} // namespace tester
} // namespace flexisip
