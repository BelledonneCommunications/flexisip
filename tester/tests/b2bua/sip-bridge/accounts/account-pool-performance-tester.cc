/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "b2bua/sip-bridge/accounts/account-pool.hh"

#include <atomic>
#include <future>

#include "b2bua/b2bua-server.hh"
#include "b2bua/sip-bridge/accounts/loaders/static-account-loader.hh"
#include "tester.hh"
#include "utils/assertion-debug-print.hh"
#include "utils/background-thread.hh"
#include "utils/core-assert.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace flexisip::tester {
namespace {

using namespace std;
using namespace b2bua;
using namespace b2bua::bridge;

/** Attempt to load the given amount of accounts into a linphone::Core.
 *  Fail if it took more the given amount of milliseconds
 */
template <usize_t accountCount, usize_t maxMs>
void loadManyAccounts() {
	const auto& suRoot = make_shared<sofiasip::SuRoot>();
	auto b2buaConfMan = ConfigManager();
	b2buaConfMan.load("");
	const auto& b2buaCore =
	    B2buaCore::create(*linphone::Factory::get(), *b2buaConfMan.getRoot()->get<GenericStruct>(b2bua::configSection));
	const auto& poolConfig = config::v2::AccountPool{
	    .outboundProxy = "<sip:stub.example.org;transport=tls>",
	    .registrationRequired = false,
	    .maxCallsPerLine = 682,
	    .loader = {},
	};
	b2buaCore->start();
	auto accounts = vector<config::v2::Account>(accountCount, config::v2::Account{});
	Random random{tester::random::seed()};
	auto stringGenerator = random.string();
	for (auto& account : accounts) {
		account.uri = "sip:uri-" + stringGenerator.generate(10) + "@stub.example.org";
		account.secretType = config::v2::SecretType::Cleartext;
		account.secret = stringGenerator.generate(10);
		account.alias = "sip:alias-" + stringGenerator.generate(10) + "@stub.example.org";
		account.outboundProxy = "<sip:" + stringGenerator.generate(10) + ".example.org;transport=tls>";
	}

	const auto& before = chrono::steady_clock::now();
	auto pool = AccountPool(suRoot, b2buaCore, "perfTestAccountPool", poolConfig,
	                        make_unique<StaticAccountLoader>(std::move(accounts)));
	BC_ASSERT_LOWER_STRICT(chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - before).count(),
	                       maxMs, usize_t, "%d");
}

enum class WithAuth : bool {
	Yes = true,
	No = false,
};

/** Create `accountCount` accounts with `registrationIntervalMs` milliseconds between registrations. Assert they have
 * successfully registered in `timeToRegisterMs`. Force their expiration time to `expirationSeconds`. With a
 * `refresh_window` between 50% and 90%, in the best case scenario, all accounts will have re-registered in half that
 * time (after the last account has successfully registered), so wait until that timepoint then assert all accounts have
 * finished re-registering before `expirationSeconds` elapsed (in total).
 *
 * The Flexisip proxy that plays the role of an external proxy is moved to a different thread so its own performance
 * does not alter that of the B2BUA under test.
 */
template <usize_t accountCount,
          usize_t registrationIntervalMs,
          usize_t expirationSeconds,
          usize_t timeToRegisterMs,
          WithAuth withAuth>
void reRegisterManyAccounts() {
	static constexpr auto authEnabled = withAuth == WithAuth::Yes;
	auto registeredUserNames = unordered_set<string>();
	auto duplicatedUserNames = decltype(registeredUserNames)();
	auto sync = mutex();
	InjectedHooks hooks{
	    .injectAfterModule = "Authentication",
	    .onRequest =
	        [&registeredUserNames, &duplicatedUserNames, &sync](unique_ptr<RequestSipEvent>&& requestEvent) mutable {
		        const auto* sip = requestEvent->getSip();
		        if (sip->sip_request->rq_method != sip_method_register) {
			        return std::move(requestEvent);
		        }

		        const auto _lock = lock_guard(sync);
		        const auto& [username, successfullyInserted] =
		            registeredUserNames.emplace(sip->sip_from->a_url->url_user);
		        if (!successfullyInserted) ignore = duplicatedUserNames.emplace(*username);
		        return std::move(requestEvent);
	        },
	};
	auto externalProxyPromise = promise<const Server&>();
	const auto _proxyThread = BackgroundThread([&hooks, &externalProxyPromise](const atomic_bool& running) {
		const auto& minMaxExpiresConfig = to_string(expirationSeconds);
		// Must be created in the same thread where the root is stepped
		auto externalProxy = Server(
		    {
		        {"module::Registrar/enabled", "true"},
		        {"module::Registrar/min-expires", minMaxExpiresConfig},
		        {"module::Registrar/max-expires", minMaxExpiresConfig},
		        {"module::Authentication/enabled", to_string(authEnabled)},
		        {"module::Authentication/auth-domains", "example.org"},
		        // Trick to avoid creating an authdb file
		        {"module::Authentication/db-implementation", "fixed"},
		    },
		    &hooks);
		externalProxy.start();
		externalProxyPromise.set_value(externalProxy);
		auto& root = *externalProxy.getRoot();
		while (running) {
			root.step(10ms);
		}
	});
	const auto& b2buaSofiaLoop = make_shared<sofiasip::SuRoot>();
	auto expectedUserNames = decltype(registeredUserNames)();
	auto accounts = vector{
	    accountCount,
	    config::v2::Account{
	        .secretType = config::v2::SecretType::Cleartext,
	        .secret = "stub",
	    },
	};
	auto externalProxyFut = externalProxyPromise.get_future();
	const auto& externalProxy = externalProxyFut.get();
	const auto& b2buaCore =
	    B2buaCore::create(*linphone::Factory::get(),
	                      *externalProxy.getConfigManager()->getRoot()->get<GenericStruct>(b2bua::configSection));
	b2buaCore->start();
	auto* externalAuthDb = authEnabled ? &externalProxy.getAgent()->getAuthDb().db() : nullptr;
	Random random{tester::random::seed()};
	auto usernameGenerator = random.string();
	for (auto& account : accounts) {
		auto username = usernameGenerator.generate(10);
		SLOGD << __FUNCTION__ << " - " << username << " is account no. " << expectedUserNames.size();
		account.uri = "sip:" + username + "@example.org";
		if constexpr (authEnabled) {
			externalAuthDb->createAccount(username, "example.org", username, "stub", numeric_limits<int>::max());
		}

		const auto& [_, successfullyInserted] = expectedUserNames.emplace(std::move(username));
		BC_ASSERT(successfullyInserted);
	}
	auto asserter = CoreAssert<kNoSleep>(b2buaSofiaLoop, b2buaCore);
	auto poolConfig = config::v2::AccountPool{
	    .outboundProxy = "<sip:127.0.0.1:" + string(externalProxy.getFirstPort()) + ";transport=udp>",
	    .registrationRequired = true,
	    .maxCallsPerLine = 914,
	    .loader = {},
	    .registrationThrottlingRateMs = registrationIntervalMs,
	    .unregisterOnServerShutdown = false,
	};
	auto pool = AccountPool(b2buaSofiaLoop, b2buaCore, __PRETTY_FUNCTION__, poolConfig,
	                        make_unique<StaticAccountLoader>(std::move(accounts)));
	constexpr auto timeToRegister = chrono::milliseconds(timeToRegisterMs);
	SLOGD << __FUNCTION__ << " - Registration started";
	const auto registrationStart = chrono::system_clock::now();
	asserter
	    .waitUntil(timeToRegister,
	               [&pool]() {
		               FAIL_IF(!pool.allAccountsLoaded());
		               for (const auto& [_, account] : pool) {
			               FAIL_IF(!account->isAvailable());
		               }
		               return ASSERTION_PASSED();
	               })
	    .assert_passed();

	SLOGD << __FUNCTION__ << " - First register was done in : "
	      << chrono::duration_cast<chrono::milliseconds>(chrono::system_clock::now() - registrationStart).count()
	      << "ms.";
	{
		const auto _lock = lock_guard(sync);
		BC_ASSERT_CPP_EQUAL(registeredUserNames.size(), expectedUserNames.size());
		BC_ASSERT_CPP_EQUAL(duplicatedUserNames, decltype(duplicatedUserNames)());
		BC_HARD_ASSERT_CPP_EQUAL(registeredUserNames, expectedUserNames);
		registeredUserNames.clear();
	}

	SLOGD << __FUNCTION__ << " - Idling until half-life of last registered account...";
	constexpr auto halfLife = chrono::seconds(expirationSeconds) / 2.;
	ignore = asserter.waitUntil(halfLife, []() { return false; });

	SLOGD << __FUNCTION__
	      << " - ... Half-life reached. All accounts must have re-registered by the end of the other half.";
	asserter
	    .waitUntil(halfLife,
	               [&registeredUserNames, &sync]() {
		               auto lock = lock_guard(sync);
		               return LOOP_ASSERTION(registeredUserNames.size() == accountCount);
	               })
	    .assert_passed();
	{
		const auto _lock = lock_guard(sync);
		BC_ASSERT_CPP_EQUAL(registeredUserNames.size(), expectedUserNames.size());
		BC_ASSERT_CPP_EQUAL(registeredUserNames, expectedUserNames);
	}
};

const TestSuite _{
    "b2bua::sip-bridge::account::AccountPool-perf",
    {
        // Smoke tests
        CLASSY_TEST((loadManyAccounts<3, 1'000>)).tag("benchmark"),
        CLASSY_TEST((reRegisterManyAccounts<3, 10, 1, 220, WithAuth::No>)).tag("benchmark"),
        CLASSY_TEST((reRegisterManyAccounts<3, 10, 1, 400, WithAuth::Yes>)).tag("benchmark"),
        // Keep benchmarking out of the default (regression tests) runs
        CLASSY_TEST((loadManyAccounts<300, 2'100>)).tag("benchmark").tag("Skip"),
        CLASSY_TEST((loadManyAccounts<3000, 90'000>)).tag("benchmark").tag("Skip"),
        CLASSY_TEST((reRegisterManyAccounts<30, 10, 3, 3 * 1000 / 2, WithAuth::No>)).tag("benchmark").tag("Skip"),
        CLASSY_TEST((reRegisterManyAccounts<30, 10, 4, 4 * 1000 / 2, WithAuth::Yes>)).tag("benchmark").tag("Skip"),
        CLASSY_TEST((reRegisterManyAccounts<300, 10, 20, 20 * 1000 / 2, WithAuth::No>)).tag("benchmark").tag("Skip"),
        CLASSY_TEST((reRegisterManyAccounts<300, 10, 40, 40 * 1000 / 2, WithAuth::Yes>)).tag("benchmark").tag("Skip"),
        CLASSY_TEST((reRegisterManyAccounts<3000, 10, 330, 330 * 1000 / 2, WithAuth::No>)).tag("benchmark").tag("Skip"),
        CLASSY_TEST((reRegisterManyAccounts<3000, 75, 250 * 2, 250 * 1000, WithAuth::Yes>))
            .tag("benchmark")
            .tag("Skip"),
        // Successful runs (All tests must have passed at least once):
        //
        //    Date    |  Compiler  |     Build Type     |          CPU          |       Machine
        // -----------|------------|--------------------|-----------------------|---------------------
        // 2024-07-30 | gcc 13.2.0 | Debug (Sanitizers) | Intel® Core™ i7-9750H | Dell Inc. G3 3590
        // 2024-07-31 | gcc 13.1.0 | Debug (Sanitizers) | Intel® Core™ i7-9750H | MSI GS65 Stealth 9SD
    },
};

} // namespace
} // namespace flexisip::tester