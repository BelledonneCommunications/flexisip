/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <soci/session.h>
#include <soci/sqlite3/soci-sqlite3.h>

#include "b2bua/sip-bridge/accounts/account-pool.hh"
#include "b2bua/sip-bridge/accounts/loaders/sql-account-loader.hh"
#include "b2bua/sip-bridge/accounts/loaders/static-account-loader.hh"
#include "tester.hh"
#include "utils/core-assert.hh"
#include "utils/server/redis-server.hh"
#include "utils/string-formatter.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

namespace flexisip::tester {
using namespace std;
using namespace soci;
using namespace nlohmann;
using namespace flexisip::b2bua::bridge;
using namespace flexisip::b2bua::bridge;
using namespace redis::async;

namespace {
struct SuiteScope {
	const TmpDir tmpDir{"tmpDirForSqlLoader"};
	const std::string tmpDbFileName = tmpDir.path().string() + "/database_filename";
	RedisServer redis{};
	Server proxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/redis-server-domain", "localhost"},
	    {"module::Registrar/redis-server-port", to_string(redis.port())},
	}};
	soci::session sql{sqlite3, tmpDbFileName};
	shared_ptr<linphone::Core> b2buaCore;
	std::shared_ptr<sofiasip::SuRoot> suRoot;

	// clang-format off
	config::v2::AccountPool poolConfig = nlohmann::json::parse(StringFormatter{
	R"({
		"outboundProxy": "<sip:default-outbound-proxy.example.org;transport=tls>",
		"registrationRequired": false,
		"maxCallsPerLine": 55,
		"loader": {
			"dbBackend": "sqlite3",
			"initQuery": "SELECT usernameInDb as username, domain as hostport, userid as user_id, passwordInDb as secret, \"clrtxt\" as secret_type, \"myNiceRealm\" as realm, alias_username, alias_domain as alias_hostport, outboundProxyInDb as outbound_proxy from users",
			"updateQuery": "SELECT usernameInDb as username, domain as hostport, userid as user_id, \"clrtxt\" as secret_type, passwordInDb as secret, \"myNiceRealm\" as realm, alias_username, alias_domain as alias_hostport, outboundProxyInDb as outbound_proxy from users where user_id = :identifier",
			"connection": "@database_filename@"
		}
	})",'@', '@'}
	.format({{"database_filename", tmpDbFileName}}))
	.get<config::v2::AccountPool>();
	// clang-format on
	;
};

std::optional<SuiteScope> SUITE_SCOPE;

void globalSqlTest() {
	///////// ARRANGE
	Session commandsSession{};
	auto& ready = std::get<Session::Ready>(
	    commandsSession.connect(SUITE_SCOPE->suRoot->getCPtr(), "localhost", SUITE_SCOPE->redis.port()));

	CoreAssert asserter{*SUITE_SCOPE->suRoot};

	const auto registrarConf = RedisParameters::fromRegistrarConf(
	    SUITE_SCOPE->proxy.getConfigManager()->getRoot()->get<GenericStruct>("module::Registrar"));

	///////// LOAD
	AccountPool pool{SUITE_SCOPE->suRoot,
	                 SUITE_SCOPE->b2buaCore,
	                 "testAccountPool",
	                 SUITE_SCOPE->poolConfig,
	                 make_unique<SQLAccountLoader>(SUITE_SCOPE->suRoot,
	                                               std::get<config::v2::SQLLoader>(SUITE_SCOPE->poolConfig.loader)),
	                 &registrarConf};

	asserter
	    .wait([&pool] {
		    FAIL_IF(!pool.allAccountsLoaded());
		    FAIL_IF(pool.size() != 2);
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	///////// ASSERT AFTER LOAD
	auto actualAccount1 = pool.getAccountByAlias("sip:expected-from@sip.example.org");
	auto actualAccount2 = pool.getAccountByUri("sip:account2@some.provider.example.com");

	///// Account 1 checks
	BC_HARD_ASSERT_NOT_NULL(actualAccount1);
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount1->getLinphoneAccount()->getParams()->getIdentityAddress()->asString(),
	                         "sip:account1@some.provider.example.com");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount1->getAlias().str(), "sip:expected-from@sip.example.org");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount1->getLinphoneAccount()->getParams()->getServerAddress()->asString(),
	                         "<sip:default-outbound-proxy.example.org;transport=tls>");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount1->getLinphoneAccount()->getParams()->getRoutesAddresses().size(), 1);
	BC_HARD_ASSERT_CPP_EQUAL(
	    actualAccount1->getLinphoneAccount()->getParams()->getRoutesAddresses().begin()->get()->asString(),
	    "<sip:default-outbound-proxy.example.org;transport=tls>");
	auto account1AuthInfo = SUITE_SCOPE->b2buaCore->findAuthInfo("", "account1", "some.provider.example.com");
	BC_HARD_ASSERT_FALSE(account1AuthInfo);
	///// Account 2 checks
	BC_HARD_ASSERT_NOT_NULL(actualAccount2);
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2->getLinphoneAccount()->getParams()->getIdentityAddress()->asString(),
	                         "sip:account2@some.provider.example.com");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2->getAlias().str(), "");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2->getLinphoneAccount()->getParams()->getServerAddress()->asString(),
	                         "<sip:127.0.0.1:5060;transport=tcp>");

	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2->getLinphoneAccount()->getParams()->getRoutesAddresses().size(), 1);
	BC_HARD_ASSERT_CPP_EQUAL(
	    actualAccount2->getLinphoneAccount()->getParams()->getRoutesAddresses().begin()->get()->asString(),
	    "<sip:127.0.0.1:5060;transport=tcp>");
	auto account2AuthInfo = SUITE_SCOPE->b2buaCore->findAuthInfo("", "account2", "some.provider.example.com");
	BC_HARD_ASSERT_TRUE(account2AuthInfo != nullptr);
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getRealm(), "myNiceRealm");
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getUsername(), "account2");
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getDomain(), "some.provider.example.com");
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getPassword(), "p@$sword");

	///////// Update account (modified password and outbound proxy, alias added)
	SUITE_SCOPE->sql << R"sql(DELETE FROM users WHERE usernameInDb = "account2")sql";
	SUITE_SCOPE->sql
	    << R"sql(INSERT INTO users VALUES ("account2", "some.provider.example.com", "userID", "NEWp@$sword", "addedAlias", "new.domain.org", "<sip:new.outbound.org:5060;transport=tcp>"))sql";

	ready.command({"PUBLISH", "flexisip/B2BUA/account",
	               R"({"username": "account2","domain": "some.provider.example.com","identifier":"userID"})"},
	              {});

	asserter
	    .wait([&pool, &actualAccount2] {
		    actualAccount2 = pool.getAccountByUri("sip:account2@some.provider.example.com");
		    FAIL_IF(actualAccount2->getAlias().str() != "sip:addedAlias@new.domain.org");
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	///////// ASSERT AFTER UPDATE
	actualAccount1 = pool.getAccountByAlias("sip:expected-from@sip.example.org");
	actualAccount2 = pool.getAccountByUri("sip:account2@some.provider.example.com");
	auto actualAccount2Alias = pool.getAccountByAlias("sip:addedAlias@new.domain.org");
	///// Account 1 checks
	BC_HARD_ASSERT_NOT_NULL(actualAccount1);
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount1->getLinphoneAccount()->getParams()->getIdentityAddress()->asString(),
	                         "sip:account1@some.provider.example.com");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount1->getAlias().str(), "sip:expected-from@sip.example.org");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount1->getLinphoneAccount()->getParams()->getServerAddress()->asString(),
	                         "<sip:default-outbound-proxy.example.org;transport=tls>");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount1->getLinphoneAccount()->getParams()->getRoutesAddresses().size(), 1);
	BC_HARD_ASSERT_CPP_EQUAL(
	    actualAccount1->getLinphoneAccount()->getParams()->getRoutesAddresses().begin()->get()->asString(),
	    "<sip:default-outbound-proxy.example.org;transport=tls>");
	account1AuthInfo = SUITE_SCOPE->b2buaCore->findAuthInfo("", "account1", "some.provider.example.com");
	BC_HARD_ASSERT_FALSE(account1AuthInfo);
	///// Account 2 checks
	BC_HARD_ASSERT_NOT_NULL(actualAccount2);
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2, actualAccount2Alias);
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2->getLinphoneAccount()->getParams()->getIdentityAddress()->asString(),
	                         "sip:account2@some.provider.example.com");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2->getAlias().str(), "sip:addedAlias@new.domain.org");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2->getLinphoneAccount()->getParams()->getServerAddress()->asString(),
	                         "<sip:new.outbound.org:5060;transport=tcp>");

	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2->getLinphoneAccount()->getParams()->getRoutesAddresses().size(), 1);
	BC_HARD_ASSERT_CPP_EQUAL(
	    actualAccount2->getLinphoneAccount()->getParams()->getRoutesAddresses().begin()->get()->asString(),
	    "<sip:new.outbound.org:5060;transport=tcp>");
	account2AuthInfo = SUITE_SCOPE->b2buaCore->findAuthInfo("", "account2", "some.provider.example.com");
	BC_HARD_ASSERT_TRUE(account2AuthInfo != nullptr);
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getRealm(), "myNiceRealm");
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getUsername(), "account2");
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getDomain(), "some.provider.example.com");
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getPassword(), "NEWp@$sword");

	///////// Delete account2
	SUITE_SCOPE->sql << R"sql(DELETE FROM users WHERE usernameInDb = "account2")sql";

	ready.command({"PUBLISH", "flexisip/B2BUA/account",
	               R"({"username": "account2","domain":"some.provider.example.com","identifier":"userID"})"},
	              {});

	asserter
	    .wait([&pool] {
		    FAIL_IF(pool.getAccountByUri("sip:account2@some.provider.example.com") != nullptr);
		    FAIL_IF(pool.getAccountByAlias("sip:addedAlias@new.domain.org") != nullptr);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();
	///////// ASSERT AFTER UPDATE
	actualAccount1 = pool.getAccountByAlias("sip:expected-from@sip.example.org");
	///// Account 1 checks
	BC_HARD_ASSERT_NOT_NULL(actualAccount1);
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount1->getLinphoneAccount()->getParams()->getIdentityAddress()->asString(),
	                         "sip:account1@some.provider.example.com");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount1->getAlias().str(), "sip:expected-from@sip.example.org");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount1->getLinphoneAccount()->getParams()->getServerAddress()->asString(),
	                         "<sip:default-outbound-proxy.example.org;transport=tls>");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount1->getLinphoneAccount()->getParams()->getRoutesAddresses().size(), 1);
	BC_HARD_ASSERT_CPP_EQUAL(
	    actualAccount1->getLinphoneAccount()->getParams()->getRoutesAddresses().begin()->get()->asString(),
	    "<sip:default-outbound-proxy.example.org;transport=tls>");
	account1AuthInfo = SUITE_SCOPE->b2buaCore->findAuthInfo("", "account1", "some.provider.example.com");
	BC_HARD_ASSERT_FALSE(account1AuthInfo);
}

void emptyNoRedisSqlTest() {
	///////// ARRANGE
	CoreAssert asserter{*SUITE_SCOPE->suRoot};

	SUITE_SCOPE->sql << R"sql(DELETE FROM users)sql";

	///////// LOAD
	AccountPool pool{SUITE_SCOPE->suRoot,
	                 SUITE_SCOPE->b2buaCore,
	                 "testAccountPool",
	                 SUITE_SCOPE->poolConfig,
	                 make_unique<SQLAccountLoader>(SUITE_SCOPE->suRoot,
	                                               std::get<config::v2::SQLLoader>(SUITE_SCOPE->poolConfig.loader)),
	                 nullptr};

	asserter
	    .wait([&pool] {
		    FAIL_IF(!pool.allAccountsLoaded());
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	///////// ASSERT AFTER LOAD, empty and no crashes
	BC_HARD_ASSERT_TRUE(pool.begin() == pool.end());
}

void emptyThenPublishSqlTest() {
	Session commandsSession{};
	auto& ready = std::get<Session::Ready>(
	    commandsSession.connect(SUITE_SCOPE->suRoot->getCPtr(), "localhost", SUITE_SCOPE->redis.port()));

	CoreAssert asserter{*SUITE_SCOPE->suRoot};

	const auto registrarConf = RedisParameters::fromRegistrarConf(
	    SUITE_SCOPE->proxy.getConfigManager()->getRoot()->get<GenericStruct>("module::Registrar"));

	SUITE_SCOPE->sql << R"sql(DELETE FROM users)sql";

	///////// LOAD
	AccountPool pool{SUITE_SCOPE->suRoot,
	                 SUITE_SCOPE->b2buaCore,
	                 "testAccountPool",
	                 SUITE_SCOPE->poolConfig,
	                 make_unique<SQLAccountLoader>(SUITE_SCOPE->suRoot,
	                                               std::get<config::v2::SQLLoader>(SUITE_SCOPE->poolConfig.loader)),
	                 &registrarConf};

	asserter
	    .wait([&pool] {
		    FAIL_IF(!pool.allAccountsLoaded());
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	///////// ASSERT AFTER LOAD, empty and no crashes
	BC_HARD_ASSERT_TRUE(pool.begin() == pool.end());

	///////// Account added
	SUITE_SCOPE->sql
	    << R"sql(INSERT INTO users VALUES ("account2", "some.provider.example.com", "userID", "NEWp@$sword", "addedAlias", "new.domain.org", "<sip:new.outbound.org:5060;transport=tcp>"))sql";

	ready.command({"PUBLISH", "flexisip/B2BUA/account",
	               R"({"username": "account2","domain": "some.provider.example.com","identifier":"userID"})"},
	              {});

	shared_ptr<Account> actualAccount2{};
	asserter
	    .wait([&pool, &actualAccount2] {
		    actualAccount2 = pool.getAccountByUri("sip:account2@some.provider.example.com");
		    FAIL_IF(!actualAccount2 || actualAccount2->getAlias().str() != "sip:addedAlias@new.domain.org");
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	///////// ASSERT AFTER UPDATE
	BC_HARD_ASSERT_TRUE(pool.size() == 1);
	actualAccount2 = pool.getAccountByUri("sip:account2@some.provider.example.com");
	auto actualAccount2Alias = pool.getAccountByAlias("sip:addedAlias@new.domain.org");
	///// Account 2 checks
	BC_HARD_ASSERT_NOT_NULL(actualAccount2);
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2, actualAccount2Alias);
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2->getLinphoneAccount()->getParams()->getIdentityAddress()->asString(),
	                         "sip:account2@some.provider.example.com");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2->getAlias().str(), "sip:addedAlias@new.domain.org");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2->getLinphoneAccount()->getParams()->getServerAddress()->asString(),
	                         "<sip:new.outbound.org:5060;transport=tcp>");

	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2->getLinphoneAccount()->getParams()->getRoutesAddresses().size(), 1);
	BC_HARD_ASSERT_CPP_EQUAL(
	    actualAccount2->getLinphoneAccount()->getParams()->getRoutesAddresses().begin()->get()->asString(),
	    "<sip:new.outbound.org:5060;transport=tcp>");
	auto account2AuthInfo = SUITE_SCOPE->b2buaCore->findAuthInfo("", "account2", "some.provider.example.com");
	BC_HARD_ASSERT_TRUE(account2AuthInfo != nullptr);
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getRealm(), "myNiceRealm");
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getUsername(), "account2");
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getDomain(), "some.provider.example.com");
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getPassword(), "NEWp@$sword");
}

/**
 * Tests the AccountPool throttling mechanism.
 *
 * This test counts the number of registrations received by a flexisip-proxy for different AccountPool registration rate
 * configurations. It attempts to register 10 accounts within a maximum of 500ms, with registration throttling rates of
 * 0ms, and 100ms.
 *
 * It ensures that with 0ms throttling, all accounts are registered synchronously
 *
 * With 100ms throttling, it ensures that not all accounts are registered (5 or 6 due to sofia loop precision and for
 * test stability).
 */
void accountRegistrationThrottling() {
	/////////
	/// Setup
	/////////
	constexpr auto accountCount = 10;
	int numberOfRegister = 0;
	InjectedHooks hooks{
	    .onRequest =
	        [&numberOfRegister](const std::shared_ptr<RequestSipEvent>& requestEvent) mutable {
		        const auto* sip = requestEvent->getSip();
		        if (sip->sip_request->rq_method != sip_method_register) {
			        return;
		        }
		        numberOfRegister++;
	        },
	};
	auto proxy = Server(
	    {
	        // Requesting bind on port 0 to let the kernel find any available port
	        {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	        {"module::Registrar/enabled", "true"},
	        {"module::Registrar/reg-domains", "example.org"},
	    },
	    &hooks);
	proxy.start();
	const auto& suRoot = make_shared<sofiasip::SuRoot>();
	const auto& b2buaCore = minimalCore(*linphone::Factory::get());
	b2buaCore->start();
	auto accounts = vector{accountCount, config::v2::Account{}};
	for (auto& account : accounts) {
		account.uri = "sip:uri-" + randomString(10) + "@example.org";
	}
	auto asserter = CoreAssert(proxy, *suRoot, b2buaCore);

	/////////
	/// Rate to 0ms (synchronous)
	/////////
	auto poolConfig = config::v2::AccountPool{
	    .outboundProxy = "<sip:127.0.0.1:" + std::string(proxy.getFirstPort()) + ";transport=tcp>",
	    .registrationRequired = true,
	    .maxCallsPerLine = 682,
	    .loader = {},
	    .registrationThrottlingRateMs = 0,
	};
	auto pool = make_optional<AccountPool>(suRoot, b2buaCore, "perfTestAccountPool", poolConfig,
	                                       make_unique<StaticAccountLoader>(vector{accounts}));
	BC_HARD_ASSERT(pool->allAccountsLoaded());
	// Let the Proxy receive the REGISTER requests
	asserter
	    .iterateUpTo(
	        3, [&numberOfRegister]() { return LOOP_ASSERTION(numberOfRegister == accountCount); }, 200ms)
	    .assert_passed();
	BC_HARD_ASSERT_CPP_EQUAL(numberOfRegister, accountCount);
	numberOfRegister = 0;

	/////////
	/// Rate to 100ms
	/////////
	poolConfig.registrationThrottlingRateMs = 100;
	pool.emplace(suRoot, b2buaCore, "perfTestAccountPool", poolConfig,
	             make_unique<StaticAccountLoader>(vector{accounts}));
	BC_HARD_ASSERT(!pool->allAccountsLoaded());
	asserter.forceIterateThenAssert(0, 500ms, []() { return ASSERTION_PASSED(); }).assert_passed();

	BC_ASSERT_TRUE(numberOfRegister > 4);
	BC_ASSERT_TRUE(numberOfRegister < 7);
}

const TestSuite _{
    "b2bua::bridge::account::AccountPool",
    {
        CLASSY_TEST(accountRegistrationThrottling),
    },
};

const TestSuite _SQL{
    "b2bua::bridge::account::AccountPool-SQL",
    {
        CLASSY_TEST(globalSqlTest),
        CLASSY_TEST(emptyNoRedisSqlTest),
        CLASSY_TEST(emptyThenPublishSqlTest),
    },
    Hooks()
        .beforeSuite([] {
	        SUITE_SCOPE.emplace();
	        try {
		        SUITE_SCOPE->sql << R"sql(CREATE TABLE users (
						usernameInDb TEXT PRIMARY KEY,
						domain TEXT,
						userid TEXT,
						passwordInDb TEXT,
						alias_username TEXT,
						alias_domain TEXT,
						outboundProxyInDb TEXT))sql";
	        } catch (const soci_error& e) {
		        auto msg = "Error initiating DB : "s + e.what();
		        BC_HARD_FAIL(msg.c_str());
	        }
	        return 0;
        })
        .beforeEach([] {
	        SUITE_SCOPE->b2buaCore = minimalCore(*linphone::Factory::get());
	        SUITE_SCOPE->suRoot = make_shared<sofiasip::SuRoot>();
	        SUITE_SCOPE->sql
	            << R"sql(INSERT INTO users VALUES ("account1", "some.provider.example.com", "", "", "expected-from", "sip.example.org", ""))sql";
	        SUITE_SCOPE->sql
	            << R"sql(INSERT INTO users VALUES ("account2", "some.provider.example.com", "userID", "p@$sword", "", "", "<sip:127.0.0.1:5060;transport=tcp>"))sql";
        })
        .afterEach([] { SUITE_SCOPE->sql << R"sql(DELETE FROM users)sql"; })
        .afterSuite([] {
	        SUITE_SCOPE.reset();
	        return 0;
        }),
};

} // namespace
} // namespace flexisip::tester
