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

#include <fstream>
#include <memory>
#include <string_view>

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
#include "utils/tmp-dir.hh"
#include "utils/uri-utils.hh"

using namespace std;
using namespace linphone;

namespace flexisip::tester {
namespace {
std::optional<TmpDir> kSuiteDir;

constexpr string_view kAccounts = R"(
    [
		{
			"type": "account",
			"payload": {
				"id": 1,
				"sip_uri": "sip:initial-callee@sip.example.org",
				"call_forwardings": [
					{
						"type": "always",
						"sip_uri": "sip:final-callee@sip.example.org",
						"forward_to": "sip_uri",
						"enabled": true
					}
				]
			}
		},
		{
			"type": "account",
			"payload": {
				"id": 2,
				"sip_uri": "sip:final-callee@sip.example.org",
				"call_forwardings": [
				]
			}
		}
	]
)";

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

auto hasReceivedCall(shared_ptr<CoreClient>& core) {
	if (!core) return false;
	auto call = core->getCurrentCall();
	return call && call->getState() == linphone::Call::State::IncomingReceived;
}

auto hasNoRunningCall(shared_ptr<CoreClient>& core) {
	if (!core) return false;
	auto call = core->getCurrentCall();
	return !call || call->getState() == linphone::Call::State::Released;
}
struct DivertedCallTester {
	DivertedCallTester(string_view accounts) {
		auto accountsFile = kSuiteDir->path() / __func__;
		std::ofstream(accountsFile) << accounts;

		Server proxy{{
		    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
		    {"global/advanced-account-data", accountsFile},
		    {"module::Registrar/reg-domains", "sip.example.org"},
		    {"module::Router/enable-call-diversions", "true"},
		}};
		proxy.start();

		builder = make_unique<ClientBuilder>(proxy.getAgent());
		caller = builder->make("sip:caller@sip.example.org");
		initialCallee = builder->make("sip:initial-callee@sip.example.org");
		intermediateCallee = builder->make("sip:intermediate-callee@sip.example.org");
		finalCallee = builder->make("sip:final-callee@sip.example.org");

		CoreAssert asserter{proxy, caller, initialCallee, intermediateCallee, finalCallee};

		// Caller invites callee.
		callerCall = ClientCall::tryFrom(caller->invite(*initialCallee));
		BC_HARD_ASSERT(callerCall.has_value());
		BC_HARD_ASSERT(!hasNoRunningCall(caller));

		// Wait until call is received.
		asserter
		    .waitUntil(2s,
		               [&] {
			               FAIL_IF(!(hasReceivedCall(initialCallee) || hasReceivedCall(intermediateCallee) ||
			                         hasReceivedCall(finalCallee) || hasNoRunningCall(caller)));
			               return ASSERTION_PASSED();
		               })
		    .hard_assert_passed();
	}

	~DivertedCallTester() {
		if (callerCall) std::ignore = callerCall->terminate();
	}

	unique_ptr<ClientBuilder> builder;
	shared_ptr<CoreClient> caller;
	shared_ptr<CoreClient> initialCallee;
	shared_ptr<CoreClient> intermediateCallee;
	shared_ptr<CoreClient> finalCallee;
	optional<ClientCall> callerCall;
};

void divertedCall() {
	DivertedCallTester tester{kAccounts};
	BC_ASSERT_TRUE(hasReceivedCall(tester.finalCallee));
}

void maxDivertedCall() {
	constexpr string_view recursiveDiversions = R"(
	[
		{
			"type": "account",
			"payload": {
				"id": 1,
				"sip_uri": "sip:initial-callee@sip.example.org",
				"call_forwardings": [
					{
						"type": "always",
						"sip_uri": "sip:intermediate-callee@sip.example.org",
						"forward_to": "sip_uri",
						"enabled": true
					}
				]
			}
		},
		{
			"type": "account",
			"payload": {
				"id": 2,
				"sip_uri": "sip:intermediate-callee@sip.example.org",
				"call_forwardings": [
					{
						"type": "always",
						"contact_sip_uri": "sip:final-callee@sip.example.org",
						"forward_to": "contact",
						"enabled": true
					}
				]
			}
		},
		{
			"id": 3,
			"type": "account",
			"payload": {
				"sip_uri": "sip:final-callee@sip.example.org",
				"call_forwardings": [
				]
			}
		}
	]
)";

	DivertedCallTester tester{recursiveDiversions};
	BC_ASSERT_FALSE(hasReceivedCall(tester.initialCallee));
	BC_ASSERT_FALSE(hasReceivedCall(tester.intermediateCallee));
	BC_ASSERT_FALSE(hasReceivedCall(tester.finalCallee));
	BC_ASSERT_TRUE(hasNoRunningCall(tester.caller));
}

void redirectToInitialTargetVoicemail() {
	auto accountsFile = kSuiteDir->path() / __func__;
	std::ofstream(accountsFile) << kAccounts;

	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"global/advanced-account-data", accountsFile},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	    {"module::Router/enable-call-diversions", "true"},
	}};
	proxy.start();

	ClientBuilder voicemailBuilder{proxy.getAgent()};
	auto voicemail =
	    make_shared<CoreClient>(voicemailBuilder.setRegistration(OnOff::Off).build("sip:voicemail@127.0.0.2"));
	const auto& config = *proxy.getConfigManager()->getRoot()->get<GenericStruct>("module::Router");
	const auto voicemailAddress = "sip:127.0.0.2:" + to_string(voicemail->getTcpPort()) + ";transport=tcp";
	config.get<ConfigString>("voicemail-server")->set(voicemailAddress);
	const auto router = dynamic_pointer_cast<ModuleRouter>(proxy.getAgent()->findModuleByRole("Router"));
	router->reload();

	ClientBuilder clientBuilder{proxy.getAgent()};
	auto caller = clientBuilder.make("sip:caller@sip.example.org");
	auto initialCallee = clientBuilder.make("sip:initial-callee@sip.example.org");
	auto finalCallee = clientBuilder.make("sip:final-callee@sip.example.org");

	CoreAssert asserter{proxy, caller, initialCallee, finalCallee, *voicemail};
	// Caller invites callee.
	const auto* initialCalleeAor = "sip:initial-callee@sip.example.org";
	auto callToInitialCallee = ClientCall::tryFrom(caller->invite(initialCalleeAor));
	BC_HARD_ASSERT(callToInitialCallee.has_value());

	// Wait until call is received.
	asserter
	    .waitUntil(2s,
	               [&] {
		               FAIL_IF(hasReceivedCall(initialCallee));
		               FAIL_IF(!hasReceivedCall(finalCallee));
		               return ASSERTION_PASSED();
	               })
	    .hard_assert_passed();

	BC_HARD_ASSERT(hasReceivedCall(finalCallee));
	finalCallee->getCurrentCall()->decline(Reason::Declined);

	voicemail->hasReceivedCallFrom(*caller, asserter).hard_assert_passed();

	auto callFromCallerToVoicemail = voicemail->getCurrentCall();
	BC_HARD_ASSERT(callFromCallerToVoicemail.has_value());

	// Verify the content of the request URI.
	const SipUri requestUri{callFromCallerToVoicemail->getRequestAddress()->asStringUriOnly()};
	BC_ASSERT_CPP_EQUAL(uri_utils::unescape(requestUri.getParam("target")), initialCalleeAor);

	if (callFromCallerToVoicemail) callFromCallerToVoicemail->terminate();
}

TestSuite kSuite{
    "DivertibleFork",
    {
        CLASSY_TEST(cancelCallAfterRedirection),
        CLASSY_TEST(divertedCall),
        CLASSY_TEST(maxDivertedCall),
        CLASSY_TEST(redirectToInitialTargetVoicemail),
    },
    Hooks()
        .beforeSuite([] {
	        kSuiteDir.emplace(kSuite.getName());
	        return 0;
        })
        .afterSuite([] {
	        kSuiteDir.reset();
	        return 0;
        }),
};
} // namespace
} // namespace flexisip::tester
