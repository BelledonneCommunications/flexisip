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
#include "http-mock/http-mock.hh"

#include <fstream>
#include <map>
#include <memory>
#include <string_view>

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
void cancelCallAfterDiversion() {
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
	static std::map<string, string> makeConfig(int httpPort, string_view accounts) {
		string accountsParameter = accounts.data();
		if (accountsParameter != "flexiapi")
			accountsParameter = kSuiteDir->path() / "conditional-diverted-call-accounts";

		std::ofstream(accountsParameter) << accounts;
		std::map<string, string> config{{"global/transports", "sip:127.0.0.1:0;transport=tcp"},
		                                {"global::flexiapi/url", "https://127.0.0.1:"s + to_string(httpPort)},
		                                {"global/advanced-account-data", accountsParameter},
		                                {"module::Registrar/reg-domains", "sip.example.org"},
		                                {"module::Router/enable-call-diversions", "true"},
		                                {"module::Router/fork-late", "true"},
		                                {"module::Router/call-fork-timeout", "2s"},
		                                {"module::Router/forwarding-status-codes", "408 486"}};
		return config;
	}

	explicit DivertedCallTester(string_view accounts, bool disableVoicemail = false)
	    : DivertedCallTester(0, accounts, disableVoicemail) {}
	explicit DivertedCallTester(int httpPort, bool disableVoicemail = false)
	    : DivertedCallTester(httpPort, "flexiapi", disableVoicemail) {}

	DivertedCallTester(int httpPort, string_view accounts, bool disableVoicemail)
	    : proxy(makeConfig(httpPort, accounts)) {
		proxy.start();

		builder = make_unique<ClientBuilder>(proxy.getAgent());
		caller = builder->make("sip:caller@sip.example.org");
		initialCallee = builder->make("sip:initial-callee@sip.example.org");
		intermediateCallee = builder->make("sip:intermediate-callee@sip.example.org");
		finalCallee = builder->make("sip:final-callee@sip.example.org");

		voicemail = make_unique<CoreClient>(
		    ClientBuilder(proxy.getAgent()).setRegistration(OnOff::Off).build("sip:voicemail@127.0.0.2"));
		if (!disableVoicemail) {
			const auto& config = *proxy.getConfigManager()->getRoot()->get<GenericStruct>("module::Router");
			const auto voicemailAddress = "sip:127.0.0.2:" + to_string(voicemail->getTcpPort()) + ";transport=tcp";
			config.get<ConfigString>("voicemail-server")->set(voicemailAddress);
			const auto router = dynamic_pointer_cast<ModuleRouter>(proxy.getAgent()->findModuleByRole("Router"));
			router->reload();
		}
		asserter = CoreAssert{proxy, caller, initialCallee, intermediateCallee, finalCallee, voicemail};

		// Caller invites callee.
		callerCall = ClientCall::tryFrom(caller->invite(initialCalleeAor));
		BC_HARD_ASSERT(callerCall.has_value());
		BC_HARD_ASSERT(!hasNoRunningCall(caller));

		// Wait until call is received.
		asserter
		    .waitUntil(2s,
		               [&] {
			               FAIL_IF(!(hasReceivedCall(initialCallee) || hasReceivedCall(intermediateCallee) ||
			                         hasReceivedCall(finalCallee) || hasReceivedCall(voicemail) ||
			                         hasNoRunningCall(caller)));
			               return ASSERTION_PASSED();
		               })
		    .hard_assert_passed();
	}

	~DivertedCallTester() {
		if (callerCall && callerCall->getState() != linphone::Call::State::Released) {
			std::ignore = callerCall->terminate();
		}
	}

	static constexpr auto initialCalleeAor{"sip:initial-callee@sip.example.org"};
	Server proxy;
	unique_ptr<ClientBuilder> builder;
	shared_ptr<CoreClient> caller;
	shared_ptr<CoreClient> initialCallee;
	shared_ptr<CoreClient> intermediateCallee;
	shared_ptr<CoreClient> finalCallee;
	shared_ptr<CoreClient> voicemail;
	optional<ClientCall> callerCall;
	CoreAssert<> asserter;
}; // namespace

void divertedCall() {
	DivertedCallTester tester{kAccounts};
	BC_ASSERT_TRUE(hasReceivedCall(tester.finalCallee));
}

// Test that nobody received the call because the max_call_diversion has been reached.
// The actual behavior is that Flexisip replies with "482 Loop Detected" when voicemail is not configured.
void exceededMaxDivertedCall() {
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

	bool disableVoicemail = true;
	DivertedCallTester tester{recursiveDiversions, disableVoicemail};
	BC_ASSERT_FALSE(hasReceivedCall(tester.initialCallee));
	BC_ASSERT_FALSE(hasReceivedCall(tester.intermediateCallee));
	BC_ASSERT_FALSE(hasReceivedCall(tester.finalCallee));
	BC_ASSERT_TRUE(hasNoRunningCall(tester.caller));
}

void divertToInitialVoicemailAfterPermanentDiversion() {
	DivertedCallTester tester{kAccounts};
	BC_HARD_ASSERT(hasReceivedCall(tester.finalCallee));
	tester.finalCallee->getCurrentCall()->decline(Reason::Busy);
	tester.voicemail->hasReceivedCallFrom(*tester.caller, tester.asserter).hard_assert_passed();

	auto callFromCallerToVoicemail = tester.voicemail->getCurrentCall();
	BC_HARD_ASSERT(callFromCallerToVoicemail.has_value());

	// Verify the content of the request URI.
	const SipUri requestUri{callFromCallerToVoicemail->getRequestAddress()->asStringUriOnly()};
	BC_ASSERT_CPP_EQUAL(uri_utils::unescape(requestUri.getParam("target")), DivertedCallTester::initialCalleeAor);
}

struct ConditionalDivertedCallTester {
	explicit ConditionalDivertedCallTester(const std::string_view& accounts) : divertedCallTester(accounts) {}
	explicit ConditionalDivertedCallTester(int httpPort) : divertedCallTester(httpPort) {}

	// 'initial-callee' rejects the call with the SIP code mapped from `reason`, triggering a conditional diversion.
	void declineInitialCallee(linphone::Reason reason) {
		const auto call = divertedCallTester.initialCallee->getCurrentCall();
		BC_HARD_ASSERT(call.has_value());
		std::ignore = call->decline(reason);
	}

	// Assert the call was diverted and answered by 'final-callee'.
	void assertDivertedToFinalTarget() {
		divertedCallTester.finalCallee->hasReceivedCallFrom(*divertedCallTester.caller, divertedCallTester.asserter)
		    .hard_assert_passed();
		BC_HARD_ASSERT(divertedCallTester.finalCallee->getCurrentCall().has_value());
	}

	// Assert the call was diverted to the voicemail of 'target'.
	void assertDivertedToVoicemail(const string& target) {
		divertedCallTester.voicemail->hasReceivedCallFrom(*divertedCallTester.caller, divertedCallTester.asserter)
		    .hard_assert_passed();
		const auto call = divertedCallTester.voicemail->getCurrentCall();
		BC_HARD_ASSERT(call.has_value());
		BC_ASSERT_CPP_EQUAL(uri_utils::unescape(call->getRequestAddress()->getUriParam("target")), target);
	}

	// Assert that no configured diversions received the call.
	void assertNoDiversion() {
		divertedCallTester.asserter
		    .waitUntil(2s,
		               [&] {
			               FAIL_IF(hasReceivedCall(divertedCallTester.finalCallee) ||
			                       hasReceivedCall(divertedCallTester.voicemail));
			               return ASSERTION_PASSED();
		               })
		    .hard_assert_passed();
	}

	DivertedCallTester divertedCallTester;
};

constexpr string_view kBusyAccounts = R"([
    {
        "type": "account",
        "payload": {
            "id": 1,
            "sip_uri": "sip:initial-callee@sip.example.org",
            "call_forwardings": [
                {
                    "type": "busy",
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
])";

// Diverts to 'final-callee' when 'initial-callee' is busy (486).
void divertCallToTargetWhenBusy() {
	ConditionalDivertedCallTester tester{kBusyAccounts};
	tester.declineInitialCallee(linphone::Reason::Busy);
	tester.assertDivertedToFinalTarget();
}

// Does NOT divert when the received code matches no configured diversion: the account only has a 'busy'
// diversion, but 'callee' declines (603 -> 'no_answer'), so the response is forwarded to 'caller' and 'final-callee'
// is never reached. Also the voicemail is configured here not to divert on 603.
void doNotDivertWhenNoMatchingDiversion() {
	ConditionalDivertedCallTester tester{kBusyAccounts};
	tester.declineInitialCallee(linphone::Reason::Declined);

	tester.divertedCallTester.asserter
	    .waitUntil(2s,
	               [&] {
		               FAIL_IF(!hasNoRunningCall(tester.divertedCallTester.caller));
		               return ASSERTION_PASSED();
	               })
	    .hard_assert_passed();
	BC_ASSERT_FALSE(hasReceivedCall(tester.divertedCallTester.finalCallee));
}

const auto kNoAnswerAccountInitial = R"(
{
	"type": "account",
	"payload": {
		"id": 1,
		"sip_uri": "sip:initial-callee@sip.example.org",
		"call_forwardings": [
			{
				"type": "no_answer",
				"sip_uri": "sip:final-callee@sip.example.org",
				"forward_to": "sip_uri",
				"enabled": true
			}
		]
	}
})";

const auto kNoAnswerAccountFinal = R"(
{
    "type": "account",
    "payload": {
        "id": 2,
        "sip_uri": "sip:final-callee@sip.example.org",
        "call_forwardings": [
        ]
    }
})";

const auto kNoAnswerAccounts = "["s + kNoAnswerAccountInitial + "," + kNoAnswerAccountFinal + "]";

const std::map<std::string, http_mock::HttpMockHandler> basicHandlers = {
    {
        "/api/resolve/initial-callee@sip.example.org",
        [](http_mock::HttpMock&, const http_mock::server::Request&, const http_mock::server::Response& res) {
	        res.writeHead(200);
	        res.send(kNoAnswerAccountInitial);
        },
    },
    {
        "/api/resolve/final-callee@sip.example.org",
        [](http_mock::HttpMock&, const http_mock::server::Request&, const http_mock::server::Response& res) {
	        res.writeHead(200);
	        res.send(kNoAnswerAccountFinal);
        },
    },
};

std::pair<std::unique_ptr<http_mock::HttpMock>, int>
setupFamMock(const std::map<std::string, http_mock::HttpMockHandler>& customHandlers = {}) {
	auto famMock = std::make_unique<http_mock::HttpMock>(customHandlers.empty() ? basicHandlers : customHandlers);
	return {std::move(famMock), famMock->serveAsync()};
}

// Diverts to 'final-callee' when 'initial-callee' does not answer.
void divertCallToTargetWhenNoAnswerAway_File() {
	ConditionalDivertedCallTester tester{kNoAnswerAccounts};
	tester.divertedCallTester.initialCallee->disconnect();
	tester.assertDivertedToFinalTarget();
}

// Diverts to 'final-callee' when 'initial-callee' does not answer.
void divertCallToTargetWhenNoAnswerAway_FAM() {
	const auto [famMock, httpPort] = setupFamMock();
	ConditionalDivertedCallTester tester{httpPort};
	tester.divertedCallTester.initialCallee->disconnect();
	tester.assertDivertedToFinalTarget();
}

// Diverts to 'final-callee' when 'initial-callee' declines (603).
void divertCallToTargetWhenNoAnswerDeclined_File() {
	ConditionalDivertedCallTester tester{kNoAnswerAccounts};
	tester.declineInitialCallee(linphone::Reason::Declined);
	tester.assertDivertedToFinalTarget();
}

// Diverts to 'final-callee' when 'initial-callee' declines (603).
void divertCallToTargetWhenNoAnswerDeclined_FAM() {
	const auto [famMock, httpPort] = setupFamMock();
	ConditionalDivertedCallTester tester{httpPort};
	tester.declineInitialCallee(linphone::Reason::Declined);
	tester.assertDivertedToFinalTarget();
}

void divertCallToInitialVoicemail() {
	constexpr string_view kVoicemailAccounts = R"([
    {
        "type": "account",
        "payload": {
            "id": 1,
            "sip_uri": "sip:initial-callee@sip.example.org",
            "call_forwardings": [
                {
                    "type": "busy",
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
                {
                    "type": "always",
                    "forward_to": "voicemail",
                    "enabled": true
                }
            ]
        }
    }
])";

	{
		ConditionalDivertedCallTester tester{kVoicemailAccounts};
		tester.divertedCallTester.initialCallee->disconnect();
		tester.assertDivertedToVoicemail(DivertedCallTester::initialCalleeAor);
	}
	// We want to be redirected to the initial callee voicemail, even if call has been diverted to another account.
	{
		ConditionalDivertedCallTester tester{kVoicemailAccounts};
		tester.declineInitialCallee(linphone::Reason::Busy);
		tester.assertDivertedToVoicemail(DivertedCallTester::initialCalleeAor);
	}
}

void noDiversionOnLoopedAccounts() {
	constexpr string_view kLoopedAccounts = R"([
    {
        "type": "account",
        "payload": {
            "id": 1,
            "sip_uri": "sip:initial-callee@sip.example.org",
            "call_forwardings": [
                {
                    "type": "no_answer",
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
            "id": 3,
            "sip_uri": "sip:final-callee@sip.example.org",
            "call_forwardings": [
                {
                    "type": "always",
                    "sip_uri": "sip:initial-callee@sip.example.org",
                    "forward_to": "sip_uri",
                    "enabled": true
                }
            ]
        }
    }
])";

	ConditionalDivertedCallTester tester{kLoopedAccounts};
	tester.declineInitialCallee(linphone::Reason::Declined);
	tester.assertNoDiversion();
}

void noDiversionToAlreadyCalledAccount() {
	constexpr string_view kLoopedAccount = R"([
    {
        "type": "account",
        "payload": {
            "id": 1,
            "sip_uri": "sip:initial-callee@sip.example.org",
            "call_forwardings": [
                {
                    "type": "busy",
                    "sip_uri": "sip:initial-callee@sip.example.org",
                    "forward_to": "sip_uri",
                    "enabled": true
                }
            ]
        }
    }
])";

	ConditionalDivertedCallTester tester{kLoopedAccount};
	tester.declineInitialCallee(linphone::Reason::Busy);
	tester.divertedCallTester.asserter
	    .waitUntil(2s,
	               [&] {
		               FAIL_IF(!hasNoRunningCall(tester.divertedCallTester.initialCallee));
		               FAIL_IF(hasNoRunningCall(tester.divertedCallTester.voicemail));
		               return ASSERTION_PASSED();
	               })
	    .hard_assert_passed();
	BC_ASSERT_TRUE(hasReceivedCall(tester.divertedCallTester.voicemail));
}

// CANCEL a call just after a fetch to the FAM and check that no diversion occurs on the FAM response.
// REGISTER an iOS device and disconnect it to avoid Fork destruction on CANCEL.
void noDiversionAfterCancel() {
	const auto [famMock, httpPort] = setupFamMock();
	Server proxy(DivertedCallTester::makeConfig(httpPort, "flexiapi"));
	proxy.start();

	auto builder = make_unique<ClientBuilder>(proxy.getAgent());
	auto caller = builder->make("sip:caller@sip.example.org");
	auto initialCallee = builder->make("sip:initial-callee@sip.example.org");
	auto initialCalleeIdleClient = builder->setApplePushConfig().make("sip:initial-callee@sip.example.org;device=iOS");
	auto finalCallee = builder->make("sip:final-callee@sip.example.org");
	auto voicemail = ClientBuilder(proxy.getAgent()).setRegistration(OnOff::Off).make("sip:voicemail@127.0.0.2");
	const auto& config = *proxy.getConfigManager()->getRoot()->get<GenericStruct>("module::Router");
	const auto voicemailAddress = "sip:127.0.0.2:" + to_string(voicemail->getTcpPort()) + ";transport=tcp";
	config.get<ConfigString>("voicemail-server")->set(voicemailAddress);
	const auto router = dynamic_pointer_cast<ModuleRouter>(proxy.getAgent()->findModuleByRole("Router"));
	router->reload();

	auto asserter = CoreAssert{proxy, caller, initialCallee, initialCalleeIdleClient, finalCallee, voicemail};

	// Wait for client registration.
	asserter
	    .waitUntil(2s,
	               [&initialCallee, &initialCalleeIdleClient] {
		               FAIL_IF(initialCallee->getAccount()->getState() != RegistrationState::Ok);
		               FAIL_IF(initialCalleeIdleClient->getAccount()->getState() != RegistrationState::Ok);
		               return ASSERTION_PASSED();
	               })
	    .hard_assert_passed();
	initialCalleeIdleClient->disconnect();

	// Caller invites initial callee.
	auto callerCall = ClientCall::tryFrom(caller->invite("sip:initial-callee@sip.example.org"));
	BC_HARD_ASSERT(callerCall.has_value());
	asserter
	    .waitUntil(2s,
	               [&] {
		               FAIL_IF(hasNoRunningCall(caller));
		               FAIL_IF(!hasReceivedCall(initialCallee));
		               return ASSERTION_PASSED();
	               })
	    .hard_assert_passed();

	// Decline for NoAnswer diversion.
	auto call = initialCallee->getCurrentCall();
	BC_HARD_ASSERT(call.has_value());
	std::ignore = call->decline(linphone::Reason::Declined);

	// CANCEL call before iterate to ensure proxy will received CANCEL before FAM response.
	callerCall->terminate();

	asserter
	    .waitUntil(2s,
	               [&] {
		               FAIL_IF(!hasNoRunningCall(finalCallee));
		               FAIL_IF(!hasNoRunningCall(voicemail));
		               FAIL_IF(callerCall->getState() != linphone::Call::State::Released);
		               return ASSERTION_PASSED();
	               })
	    .assert_passed();
}

TestSuite kSuite{
    "DivertibleFork",
    {
        CLASSY_TEST(cancelCallAfterDiversion),
        CLASSY_TEST(divertedCall),
        CLASSY_TEST(exceededMaxDivertedCall),
        CLASSY_TEST(divertToInitialVoicemailAfterPermanentDiversion),
        CLASSY_TEST(divertCallToTargetWhenBusy),
        CLASSY_TEST(doNotDivertWhenNoMatchingDiversion),
        CLASSY_TEST(divertCallToTargetWhenNoAnswerAway_File),
        CLASSY_TEST(divertCallToTargetWhenNoAnswerAway_FAM),
        CLASSY_TEST(divertCallToTargetWhenNoAnswerDeclined_File),
        CLASSY_TEST(divertCallToTargetWhenNoAnswerDeclined_FAM),
        CLASSY_TEST(divertCallToInitialVoicemail),
        CLASSY_TEST(noDiversionOnLoopedAccounts),
        CLASSY_TEST(noDiversionToAlreadyCalledAccount),
        CLASSY_TEST(noDiversionAfterCancel),
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