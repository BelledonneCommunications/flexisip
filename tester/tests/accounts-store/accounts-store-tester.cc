
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
#include "flexiapi/config.hh"

#include <fstream>

#include "utils/core-assert.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

using namespace std;
namespace flexisip::tester {
namespace {
std::optional<TmpDir> kSuiteDir;

const auto accountInitial = R"({
            "type": "account",
            "payload": {
				"id": 0,
		        "sip_uri": "sip:initial-callee@sip.example.org",
		        "call_forwardings": [
			        {
				        "type": "busy",
				        "contact_sip_uri": "sip:busy-callee@sip.example.org",
				        "forward_to": "contact",
						"enabled": true
			        },
					{
				        "type": "always",
				        "sip_uri": "sip:fail_if_returned@sip.example.org",
				        "forward_to": "sip_uri",
						"enabled": false
			        },
			        {
				        "type": "always",
				        "contact_sip_uri": "sip:intermediate-callee@sip.example.org",
				        "forward_to": "contact",
						"enabled": true
			        }
		        ]
            }
        })";
const auto accountIntermediate = R"({
            "type": "account",
            "payload": {
				"id": 0,
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
        })";
const auto accountFinal = R"({
            "type": "account",
            "payload": {
				"id": 0,
				"sip_uri": "sip:final-callee@sip.example.org",
		        "call_forwardings": [
			        {
				        "type": "busy",
				        "contact_sip_uri": "sip:initial-callee@sip.example.org",
				        "forward_to": "contact",
						"enabled": true
			        }
		        ]
            }
        })";
const auto accounts = "["s + accountInitial + "," + accountIntermediate + "," + accountFinal + "]";

void findPermanentCallDiversion() {
	auto accountsFile = kSuiteDir->path() / __func__;
	std::ofstream(accountsFile) << accounts;
	AccountsStore store{accountsFile, nullptr, nullptr, nullptr};
	store.setMaxCallDiversions(5);
	bool callbackCalled{};
	store.checkCallDiversions(SipUri("sip:initial-callee@sip.example.org"), flexiapi::CallForwarding::Type::Always,
	                          [&callbackCalled](const SipUri& uri) {
		                          BC_ASSERT_CPP_EQUAL(uri.str(), "sip:final-callee@sip.example.org");
		                          callbackCalled = true;
	                          });
	BC_ASSERT_TRUE(callbackCalled);
}

void findPermanentCallDiversion_noDiversion() {
	auto accountsFile = kSuiteDir->path() / __func__;
	std::ofstream(accountsFile) << accounts;
	AccountsStore store{accountsFile, nullptr, nullptr, nullptr};
	store.setMaxCallDiversions(5);
	bool callbackCalled{};
	store.checkCallDiversions(SipUri("sip:final-callee@sip.example.org"), flexiapi::CallForwarding::Type::Always,
	                          [&callbackCalled](const SipUri& uri) {
		                          BC_ASSERT_CPP_EQUAL(uri.str(), "sip:final-callee@sip.example.org");
		                          callbackCalled = true;
	                          });
	BC_ASSERT_TRUE(callbackCalled);
}

void maxCallDiversion() {
	auto accountsFile = kSuiteDir->path() / __func__;
	std::ofstream(accountsFile) << accounts;
	AccountsStore store{accountsFile, nullptr, nullptr, nullptr};
	store.setMaxCallDiversions(1);
	bool callbackCalled{};
	store.checkCallDiversions(SipUri("sip:initial-callee@sip.example.org"), flexiapi::CallForwarding::Type::Always,
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
        CLASSY_TEST(findPermanentCallDiversion_noDiversion),
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