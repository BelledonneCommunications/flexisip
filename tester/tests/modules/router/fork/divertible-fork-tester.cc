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

#include "linphone++/enums.hh"

#include "flexisip/module-router.hh"
#include "utils/asserts.hh"
#include "utils/call-assert.hh"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/uri-utils.hh"

using namespace std;
using namespace linphone;

namespace flexisip::tester {
namespace {
// Ensure a CANCEL after the redirection is well processed.
void cancelCallAfterRedirection() {
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Router/fork-late", "true"},
	    {"module::Router/call-fork-timeout", "2s"},
	    {"module::MediaRelay/enabled", "false"},
	}};
	proxy.start();

	ClientBuilder voicemailBuilder{proxy.getAgent()};
	auto voicemail =
	    make_unique<CoreClient>(voicemailBuilder.setRegistration(OnOff::Off).build("sip:voicemail@127.0.0.2"));
	const auto& config = *proxy.getConfigManager()->getRoot()->get<GenericStruct>("module::Router");
	const auto voicemailAddress = "sip:127.0.0.2:" + to_string(voicemail->getTcpPort()) + ";transport=tcp";
	config.get<ConfigString>("voicemail-server")->set(voicemailAddress);
	const auto router = dynamic_pointer_cast<ModuleRouter>(proxy.getAgent()->findModuleByRole("Router"));
	router->reload();

	ClientBuilder builder{proxy.getAgent()};
	auto caller = make_unique<CoreClient>(builder.build("caller@sip.test.org"));
	constexpr auto* calleeAddress = "sip:callee@sip.test.org";
	auto callee = make_unique<CoreClient>(builder.build(calleeAddress));

	auto asserter = CoreAssert{proxy, *caller, *callee, *voicemail};

	// Initiate a call from 'Caller' to 'Callee'.
	auto callToCallee = ClientCall::tryFrom(caller->invite(calleeAddress));
	BC_HARD_ASSERT(callToCallee.has_value());
	callee->hasReceivedCallFrom(*caller, asserter).hard_assert_passed();
	const auto callFromCallerToCallee = callee->getCurrentCall();
	BC_HARD_ASSERT(callFromCallerToCallee.has_value());
	std::ignore = callFromCallerToCallee->decline(Reason::Declined);

	voicemail->hasReceivedCallFrom(*caller, asserter).hard_assert_passed();
	auto callFromCallerToVoicemail = voicemail->getCurrentCall();
	BC_HARD_ASSERT(callFromCallerToVoicemail.has_value());

	caller->endCurrentCall(*voicemail);
}

TestSuite __{
    "DivertibleFork",
    {
        CLASSY_TEST(cancelCallAfterRedirection),
    },
};
} // namespace
} // namespace flexisip::tester
