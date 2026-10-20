/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "b2bua/sip-bridge/sip-bridge.hh"

#include <chrono>

#include "linphone++/linphone.hh"

#include "b2bua/b2bua-core.hh"
#include "b2bua/b2bua-server.hh"
#include "helpers.hh"
#include "utils/bc-utils.hh"
#include "utils/client-builder.hh"
#include "utils/core-assert.hh"
#include "utils/server/b2bua-and-proxy-server.hh"
#include "utils/server/proxy-server.hh"
#include "utils/temp-file.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace linphone;

namespace flexisip::tester {
namespace {

using namespace std;
using namespace std::chrono_literals;
using namespace std::string_literals;

void dtmfForwarding() {
	using namespace flexisip::b2bua;
	const auto server = make_shared<B2buaAndProxyServer>("config/flexisip_b2bua.conf");
	auto providers = {
	    V1ProviderDesc{
	        "provider1",
	        "sip:\\+39.*",
	        outboundProxy,
	        false,
	        1,
	        {V1AccountDesc{"sip:bridge@sip.provider1.com", "", ""}},
	    },
	};

	// Instantiate and build clients.
	// Note: added different port ranges to reduce the risk of selecting the same port.
	server->configureExternalProviderBridge(std::move(providers));
	auto builder = ClientBuilder{server->getAgent()};
	const auto intercomUri = "sip:intercom@sip.company1.com"s;
	InternalClient intercom = builder.setAudioPort(port::Range{.min = 40000, .max = 49999}).build(intercomUri);
	const auto phoneUri = "sip:+39064728917@sip.provider1.com;user=phone"s;
	ExternalClient phone = builder.setAudioPort(port::Range{.min = 50000, .max = 59999}).build(phoneUri);

	CoreAssert asserter{intercom.getCore(), phone.getCore(), server};
	const auto legAListener = make_shared<DtmfListener>();
	const auto legBListener = make_shared<DtmfListener>();

	// Add listeners to call legs.
	const auto legA = intercom.call(phone);
	if (!BC_ASSERT_PTR_NOT_NULL(legA)) return;
	legA->addListener(legAListener);
	const auto legB = ClientCall::getLinphoneCall(*phone.getCurrentCall());
	legB->addListener(legBListener);

	legB->sendDtmf('9');
	const auto& legAReceived = legAListener->received;
	asserter.wait([&legAReceived]() { return !legAReceived.empty(); }).assert_passed();
	BC_HARD_ASSERT_CPP_EQUAL(legAReceived.size(), 1);
	BC_ASSERT_EQUAL(legAReceived.front(), '9', char, "%c");

	legA->sendDtmf('6');
	const auto& legBReceived = legBListener->received;
	asserter.wait([&legBReceived]() { return !legBReceived.empty(); }).assert_passed();
	BC_HARD_ASSERT_CPP_EQUAL(legBReceived.size(), 1);
	BC_ASSERT_EQUAL(legBReceived.front(), '6', char, "%c");
}

void overrideSpecialOptions() {
	TempFile providersJson(R"([
        {"mediaEncryption": "none",
         "enableAvpf": false,
         "name": "Test Provider",
         "pattern": "sip:unique-pattern.*",
         "outboundProxy": "<sip:127.0.0.1:3125;transport=scp>",
         "maxCallsPerLine": 173,
         "accounts": [
            {"uri": "sip:bridge@sip.provider1.com"}
         ]
        }
    ])");
	b2bua::bridge::SipBridge sipBridge{make_shared<sofiasip::SuRoot>()};
	Server proxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.example.com"},
	    {"b2bua-server::sip-bridge/providers", providersJson.getFilename().c_str()},
	}};

	proxy.start();

	const ClientBuilder builder{proxy.getAgent()};
	const auto caller = builder.build("sip:caller@sip.example.com");
	// Fake a call close enough to what the SipBridge will be taking as input
	// Only incoming calls have a request address, so we need a stand-in client to receive it
	auto callee = builder.build("sip:unique-pattern@sip.example.com");
	caller.invite(callee);
	BC_HARD_ASSERT_TRUE(callee.hasReceivedCallFrom(caller, CoreAssert{proxy, caller, callee}));
	const auto call = ClientCall::getLinphoneCall(*callee.getCurrentCall());
	BC_HARD_ASSERT_TRUE(call->getRequestAddress()->asStringUriOnly() != "");
	const auto& core = b2bua::B2buaCore::create(
	    *linphone::Factory::get(), *proxy.getConfigManager()->getRoot()->get<GenericStruct>(b2bua::configSection));
	sipBridge.init(core, proxy.getAgent()->getConfigManager());
	auto params = core->createCallParams(call);
	params->setMediaEncryption(linphone::MediaEncryption::ZRTP);
	params->enableAvpf(true);

	const auto calleeAddres = sipBridge.onCallCreate(*call, *params);

	BC_ASSERT_TRUE(holds_alternative<shared_ptr<const linphone::Address>>(calleeAddres));
	// Special call params overriden
	BC_ASSERT_TRUE(params->getMediaEncryption() == linphone::MediaEncryption::None);
	BC_ASSERT_TRUE(params->avpfEnabled() == false);
}

void maxCallDuration() {
	TempFile providersJson{};
	Server proxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "sip-bridge"},
	    // Call will be interrupted after 1s
	    {"b2bua-server/max-call-duration", "1"},
	    {"b2bua-server::sip-bridge/providers", providersJson.getFilename()},
	    // Forward everything to the b2bua
	    {"module::B2bua/enabled", "true"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.provider1.com sip.company1.com"},
	    // Media Relay has problem when everyone is running on localhost
	    {"module::MediaRelay/enabled", "false"},
	    // B2bua use writable-dir instead of var folder
	    {"b2bua-server/data-directory", bcTesterWriteDir()},
	}};
	proxy.start();
	providersJson.writeStream() << R"([
        {"mediaEncryption": "none",
         "enableAvpf": false,
         "name": "Max call duration test provider",
         "pattern": "sip:.*",
         "outboundProxy": "<sip:127.0.0.1:)"
	                            << proxy.getFirstPort() << R"(;transport=tcp>",
         "maxCallsPerLine": 682,
         "accounts": [
            {"uri": "sip:max-call-duration@sip.provider1.com"}
         ]
        }
    ])";
	const auto b2bua = make_shared<flexisip::B2buaServer>(proxy.getRoot(), proxy.getConfigManager());
	b2bua->init();
	proxy.getConfigManager()
	    ->getRoot()
	    ->get<GenericStruct>("module::B2bua")
	    ->get<ConfigString>("b2bua-server")
	    ->set("sip:127.0.0.1:" + to_string(b2bua->getTcpPort()) + ";transport=tcp");
	proxy.getAgent()->findModuleByRole("B2bua")->reload();
	ClientBuilder builder{proxy.getAgent()};
	InternalClient caller = builder.build("sip:caller@sip.company1.com");
	ExternalClient callee = builder.build("sip:callee@sip.provider1.com");
	CoreAssert asserter{caller.getCore(), proxy, callee.getCore()};

	caller.invite(callee);
	ASSERT_PASSED(callee.hasReceivedCallFrom(caller, asserter));
	callee.getCurrentCall()->accept();
	asserter
	    .iterateUpTo(3,
	                 [&callee]() {
		                 const auto calleeCall = callee.getCurrentCall();
		                 FAIL_IF(calleeCall == nullopt);
		                 FAIL_IF(calleeCall->getState() != linphone::Call::State::StreamsRunning);
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();

	// None of the clients terminated the call, but the B2BUA dropped it on its own
	asserter.iterateUpTo(
	            10, [&callee]() { return LOOP_ASSERTION(callee.getCurrentCall() == nullopt); }, 2100ms)
	    .assert_passed();
}

TestSuite _{
    "b2bua::sip-bridge::media",
    {
        CLASSY_TEST(dtmfForwarding),
        CLASSY_TEST(overrideSpecialOptions),
        CLASSY_TEST(maxCallDuration),
    },
};

} // namespace
} // namespace flexisip::tester
