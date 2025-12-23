
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

#include "accounts-store/accounts-store.hh"

#include <fstream>

#include "utils/core-assert.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

namespace flexisip::tester {
namespace {
std::optional<TmpDir> kSuiteDir;

auto accounts = R"(
    [
        {
            "type": "account",
            "payload": {
		        "sip_uri": "sip:initial-callee@sip.example.org",
		        "call_diversions": [
			        {
				        "type": "busy",
				        "target": "sip:busy-callee@sip.example.org",
				        "target_type": "account"
			        },
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
			        {
				        "type": "busy",
				        "target": "sip:initial-callee@sip.example.org",
				        "target_type": "account"
			        }
		        ]
            }
        }
    ]
)";

void findPermanentCallDiversion() {
	auto accountsFile = kSuiteDir->path() / __func__;
	std::ofstream(accountsFile) << accounts;
	AccountsStore store{accountsFile};
	store.setMaxCallDiversions(2);
	bool callbackCalled{};
	store.checkCallDiversions(SipUri("sip:initial-callee@sip.example.org"), flexiapi::CallDiversion::Type::Always,
	                          [&callbackCalled](const SipUri& uri) {
		                          BC_ASSERT_CPP_EQUAL(uri.str(), "sip:final-callee@sip.example.org");
		                          callbackCalled = true;
	                          });
	BC_ASSERT_TRUE(callbackCalled);
}

void maxCallDiversion() {
	auto accountsFile = kSuiteDir->path() / __func__;
	std::ofstream(accountsFile) << accounts;
	AccountsStore store{accountsFile};
	store.setMaxCallDiversions(1);
	bool callbackCalled{};
	store.checkCallDiversions(SipUri("sip:initial-callee@sip.example.org"), flexiapi::CallDiversion::Type::Always,
	                          [&callbackCalled](const SipUri& uri) {
		                          BC_ASSERT_TRUE(uri.str().empty());
		                          callbackCalled = true;
	                          });
	BC_ASSERT_TRUE(callbackCalled);
}

TestSuite kSuite{
    "AccountsStore",
    {
        CLASSY_TEST(findPermanentCallDiversion),
        CLASSY_TEST(maxCallDiversion),
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