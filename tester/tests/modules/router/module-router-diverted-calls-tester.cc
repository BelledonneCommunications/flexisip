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

#include "utils/call-assert.hh"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

using namespace std;
namespace flexisip::tester {
namespace {
std::optional<TmpDir> kSuiteDir;

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
	DivertedCallTester(const string& maxCallDiversions) {
		auto accounts = R"(
    [
        {
            "type": "account",
            "payload": {
		        "sip_uri": "sip:initial-callee@sip.example.org",
		        "call_diversions": [
			        {
				        "type": "always",
				        "target": "sip:intermediate-callee@sip.example.org",
				        "target_type": "account"
			        }
		        ]
            }
        },
        {
            "type": "account",
            "payload": {
		        "sip_uri": "sip:intermediate-callee@sip.example.org",
		        "call_diversions": [
			        {
				        "type": "always",
				        "target": "sip:final-callee@sip.example.org",
				        "target_type": "account"
			        }
		        ]
            }
        },
        {
            "type": "account",
            "payload": {
		        "sip_uri": "sip:final-callee@sip.example.org",
		        "call_diversions": [
		        ]
            }
        }
    ]
)";

		auto accountsFile = kSuiteDir->path() / __func__;
		std::ofstream(accountsFile) << accounts;

		Server proxy{{
		    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
		    {"global/advanced-account-data", accountsFile},
		    {"module::Registrar/reg-domains", "sip.example.org"},
		    {"module::Router/enable-call-diversions", "true"},
		    {"module::Router/max-call-diversions", maxCallDiversions},
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

	unique_ptr<ClientBuilder> builder;
	shared_ptr<CoreClient> caller;
	shared_ptr<CoreClient> initialCallee;
	shared_ptr<CoreClient> intermediateCallee;
	shared_ptr<CoreClient> finalCallee;
	optional<ClientCall> callerCall;
};

void divertedCall() {
	DivertedCallTester tester{"5"};
	BC_ASSERT_TRUE(hasReceivedCall(tester.finalCallee));
}

void maxDivertedCall() {
	DivertedCallTester tester{"1"};
	BC_ASSERT_FALSE(hasReceivedCall(tester.initialCallee));
	BC_ASSERT_FALSE(hasReceivedCall(tester.intermediateCallee));
	BC_ASSERT_FALSE(hasReceivedCall(tester.finalCallee));
	BC_ASSERT_TRUE(hasNoRunningCall(tester.caller));
}

TestSuite kSuite{
    "RouterModuleDivertedCalls",
    {
        CLASSY_TEST(divertedCall),
        CLASSY_TEST(maxDivertedCall),
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