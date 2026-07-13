
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

#include "spaces-store/accounts/accounts-store.hh"

#include <fstream>

#include "utils/core-assert.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

using namespace std;
namespace flexisip::tester {
namespace {
std::optional<TmpDir> kSuiteDir;

const auto kAccountInitial = R"({
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
const auto kAccountIntermediate = R"({
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
const auto kAccountFinal = R"({
            "type": "account",
            "payload": {
				"id": 0,
				"sip_uri": "sip:final-callee@sip.example.org",
		        "call_forwardings": [
			        {
				        "type": "busy",
				        "contact_sip_uri": "sip:busy-callee@sip.example.org",
				        "forward_to": "contact",
						"enabled": true
			        }
		        ]
            }
        })";
const auto kAccountToVoicemail = R"({
            "type": "account",
            "payload": {
				"id": 0,
				"sip_uri": "sip:to-voicemail-callee@sip.example.org",
		        "call_forwardings": [
			        {
				        "type": "always",
				        "contact_sip_uri": "",
				        "forward_to": "voicemail",
						"enabled": true
			        }
		        ]
            }
        })";
const auto kAccounts =
    "["s + kAccountInitial + "," + kAccountIntermediate + "," + kAccountFinal + "," + kAccountToVoicemail + "]";

class AccountsStoreTest {
public:
	explicit AccountsStoreTest(const std::string_view& accounts) {
		auto accountsFile = kSuiteDir->path() / __func__;
		std::ofstream(accountsFile) << accounts;
		mStore = std::make_unique<AccountsStore>(accountsFile, nullptr, nullptr, nullptr);
	}

	std::optional<AccountsStore::ResolvedCallTarget>
	resolveCallTarget(const SipUri& uri, int maxDepth, int expectedDivertedCnt) {
		std::optional<AccountsStore::ResolvedCallTarget> resolvedTarget{};
		bool callbackCalled{};

		mStore->resolveCallTarget(uri, maxDepth,
		                          [&expectedDivertedCnt, &resolvedTarget, &callbackCalled](
		                              optional<AccountsStore::ResolvedCallTarget>&& result, const int& divertedCnt) {
			                          BC_ASSERT_CPP_EQUAL(divertedCnt, expectedDivertedCnt);
			                          resolvedTarget = std::move(result);
			                          callbackCalled = true;
		                          });

		BC_HARD_ASSERT(callbackCalled);
		return resolvedTarget;
	}

protected:
	std::unique_ptr<AccountsStore> mStore;
};

void permanentDiversionToVoicemail() {
	AccountsStoreTest store{kAccounts};
	const auto maxDepth = 5;
	const auto expectedDivertedCnt = 1;
	const auto result =
	    store.resolveCallTarget(SipUri("sip:to-voicemail-callee@sip.example.org"), maxDepth, expectedDivertedCnt);
	BC_HARD_ASSERT(result.has_value());
	BC_ASSERT_CPP_EQUAL(result->target.type, AccountsStore::TargetType::Voicemail);
}

void noPermanentDiversion() {
	AccountsStoreTest store{kAccounts};
	const auto uri = SipUri("sip:final-callee@sip.example.org");
	const auto maxDepth = 5;
	const auto expectedDivertedCnt = 0;
	const auto result = store.resolveCallTarget(uri, maxDepth, expectedDivertedCnt);
	BC_HARD_ASSERT(result.has_value());
	BC_ASSERT_CPP_EQUAL(result->target.type, AccountsStore::TargetType::Account);
	BC_ASSERT_CPP_EQUAL(result->target.uri.str(), uri.str());
	BC_HARD_ASSERT(result->divertedMap.size() == 1);
	const auto [code, target] = *result->divertedMap.cbegin();
	BC_ASSERT_CPP_EQUAL(code, 486);
	BC_ASSERT_CPP_EQUAL(target.type, AccountsStore::TargetType::Account);
	BC_ASSERT_CPP_EQUAL(target.uri.str(), "sip:busy-callee@sip.example.org");
}

// Check that a target is invalid when maxDepth is reached and the recursion is not finished.
void maximumDepthExceeded() {
	AccountsStoreTest store{kAccounts};
	const auto maxDepth = 1;
	const auto expectedDivertedCnt = 2;
	const auto result =
	    store.resolveCallTarget(SipUri("sip:initial-callee@sip.example.org"), maxDepth, expectedDivertedCnt);
	BC_ASSERT_FALSE(result.has_value());
}

// Check the target and its associated call diversion map.
void permanentAndBusyDiversions() {
	AccountsStoreTest store{kAccounts};
	const auto maxDepth = 5;
	const auto expectedDivertedCnt = 2;
	const auto result =
	    store.resolveCallTarget(SipUri("sip:initial-callee@sip.example.org"), maxDepth, expectedDivertedCnt);
	BC_HARD_ASSERT(result.has_value());
	BC_ASSERT_CPP_EQUAL(result->target.type, AccountsStore::TargetType::Account);
	BC_ASSERT_CPP_EQUAL(result->target.uri.str(), "sip:final-callee@sip.example.org");
	BC_HARD_ASSERT(result->divertedMap.size() == 1);
	const auto& [code, target] = *result->divertedMap.cbegin();
	BC_ASSERT_CPP_EQUAL(code, 486);
	BC_ASSERT_CPP_EQUAL(target.type, AccountsStore::TargetType::Account);
	BC_ASSERT_CPP_EQUAL(target.uri.str(), "sip:busy-callee@sip.example.org");
}

// Check that the target is found but its associated call diversion map is empty.
void divertedMapResetOnMaxDiversion() {
	AccountsStoreTest store{kAccounts};
	const auto maxDepth = 2;
	const auto expectedDivertedCnt = 2;
	const auto result =
	    store.resolveCallTarget(SipUri("sip:initial-callee@sip.example.org"), maxDepth, expectedDivertedCnt);
	BC_HARD_ASSERT(result.has_value());
	BC_ASSERT_CPP_EQUAL(result->target.type, AccountsStore::TargetType::Account);
	BC_ASSERT_CPP_EQUAL(result->target.uri.str(), "sip:final-callee@sip.example.org");
	BC_HARD_ASSERT(result->divertedMap.size() == 0);
}

TestSuite kSuite{
    "AccountsStore",
    {
        CLASSY_TEST(permanentDiversionToVoicemail),
        CLASSY_TEST(noPermanentDiversion),
        CLASSY_TEST(maximumDepthExceeded),
        CLASSY_TEST(permanentAndBusyDiversions),
        CLASSY_TEST(divertedMapResetOnMaxDiversion),
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