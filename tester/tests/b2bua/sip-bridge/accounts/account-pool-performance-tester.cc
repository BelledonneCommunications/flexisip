/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "b2bua/sip-bridge/accounts/account-pool.hh"

#include "b2bua/sip-bridge/accounts/loaders/static-account-loader.hh"
#include "tester.hh"
#include "utils/client-core.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace flexisip::tester {
namespace {
using namespace std;
using namespace b2bua::bridge;

/** Attempt to load the given amount of accounts into a linphone::Core.
 *  Fail if it took more the given amount of milliseconds
 */
template <usize_t accountCount, usize_t maxMs>
void loadManyAccounts() {
	const auto& suRoot = make_shared<sofiasip::SuRoot>();
	const auto& factory = linphone::Factory::get();
	const auto& b2buaCore = tester::minimalCore(*factory);
	const auto& poolConfig = config::v2::AccountPool{
	    .outboundProxy = "<sip:stub.example.org;transport=tls>",
	    .registrationRequired = false,
	    .maxCallsPerLine = 682,
	    .loader = {},
	};
	b2buaCore->start();
	auto accounts = vector<config::v2::Account>(accountCount, config::v2::Account{});
	for (auto& account : accounts) {
		account.uri = "sip:uri-" + randomString(10) + "@stub.example.org";
		account.secretType = config::v2::SecretType::Cleartext;
		account.secret = randomString(10);
		account.alias = "sip:alias-" + randomString(10) + "@stub.example.org";
		account.outboundProxy = "<sip:" + randomString(10) + ".example.org;transport=tls>";
	}

	const auto& before = chrono::steady_clock::now();
	auto pool = AccountPool(suRoot, b2buaCore, "perfTestAccountPool", poolConfig,
	                        make_unique<StaticAccountLoader>(std::move(accounts)));
	BC_ASSERT_LOWER_STRICT(chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - before).count(),
	                       maxMs, usize_t, "%d");
}

const TestSuite _{
    "b2bua::bridge::account::AccountPool-perf",
    {
        // Smoke test
        CLASSY_TEST((loadManyAccounts<3, 1'000>)).tag("benchmark"),
        // Keep benchmarking out of the default (regression tests) runs
        CLASSY_TEST((loadManyAccounts<300, 1'000>)).tag("benchmark").tag("Skip"),
        CLASSY_TEST((loadManyAccounts<3000, 11'000>)).tag("benchmark").tag("Skip"),
    },
};

} // namespace
} // namespace flexisip::tester
