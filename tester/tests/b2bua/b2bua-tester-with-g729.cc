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

#include "b2bua/b2bua-server.hh"

#include <memory>
#include <string>

#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/core-assert.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace flexisip;

namespace flexisip::tester::b2buatester {

namespace {

/** Test that configuring an "audio-codec" in the "b2bua-server" section will force all calls -- incoming *and* outgoing
   -- to use that codec.

    Setup a bridged call between two clients that support multiple codecs, assert that both legs have negotiated the
   configured codec
 */
void forcedAudioCodec() {
	auto proxy = Server{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "example.org"},
	    // Media Relay has problem when everyone is running on localhost
	    {"module::MediaRelay/enabled", "false"},
	    // Forward everything to the b2bua
	    {"module::B2bua/enabled", "true"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "trenscrypter"},
	    {"b2bua-server/audio-codec", "G729/8000"},
	}};
	proxy.start();
	const auto& confMan = proxy.getConfigManager();
	const auto* const configRoot = confMan->getRoot();
	configRoot->get<GenericStruct>("b2bua-server")
	    ->get<ConfigString>("outbound-proxy")
	    ->set("sip:127.0.0.1:"s + proxy.getFirstPort() + ";transport=tcp");
	const auto& b2bua = make_shared<flexisip::B2buaServer>(proxy.getRoot(), confMan);
	b2bua->init();
	configRoot->get<GenericStruct>("module::B2bua")
	    ->get<ConfigString>("b2bua-server")
	    ->set("sip:127.0.0.1:" + to_string(b2bua->getTcpPort()) + ";transport=tcp");
	proxy.getAgent()->findModule("B2bua")->reload();
	auto builder = ClientBuilder(*proxy.getAgent());
	auto caller = builder.build("sip:caller@example.org");
	const auto& callee = builder.build("sip:callee@example.org");
	BC_HARD_ASSERT(1 < caller.getCore()->getAudioPayloadTypes().size());
	BC_HARD_ASSERT(1 < callee.getCore()->getAudioPayloadTypes().size());

	const auto& callerCall = caller.call(callee);
	BC_HARD_ASSERT(callerCall != nullptr);

	const auto& legACodec = callerCall->getCurrentParams()->getUsedAudioPayloadType();
	BC_ASSERT_CPP_EQUAL(legACodec->getMimeType(), "G729");
	BC_ASSERT_CPP_EQUAL(legACodec->getClockRate(), 8000);
	const auto& legBCodec = callee.getCurrentCall()->getAudioPayloadType();
	BC_ASSERT_CPP_EQUAL(legBCodec->getMimeType(), "G729");
	BC_ASSERT_CPP_EQUAL(legBCodec->getClockRate(), 8000);
}

TestSuite _{
    "B2bua::G729",
    {
        CLASSY_TEST(forcedAudioCodec),
    },
};

} // namespace

} // namespace flexisip::tester::b2buatester
