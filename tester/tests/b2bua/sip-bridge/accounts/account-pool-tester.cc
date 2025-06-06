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

#include <fstream>

#include "b2bua/sip-bridge/accounts/account-pool.hh"

#include <soci/session.h>
#include <soci/sqlite3/soci-sqlite3.h>

#include "b2bua/b2bua-server.hh"
#include "b2bua/sip-bridge/accounts/loaders/sql-account-loader.hh"
#include "b2bua/sip-bridge/accounts/loaders/static-account-loader.hh"
#include "tester.hh"
#include "utils/core-assert.hh"
#include "utils/lazy.hh"
#include "utils/server/redis-server.hh"
#include "utils/string-formatter.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

namespace flexisip::tester {

using namespace std;
using namespace soci;
using namespace nlohmann;
using namespace flexisip::b2bua;
using namespace flexisip::b2bua::bridge;
using namespace redis::async;

namespace {

struct ProxyServer {
	vector<sofiasip::Url> registers = {};
	vector<sofiasip::Url> unregisters = {};
	InjectedHooks hooks = {
	    .onRequest =
	        [&](std::unique_ptr<RequestSipEvent>&& requestEvent) mutable {
		        const auto* sip = requestEvent->getSip();
		        if (sip->sip_request->rq_method != sip_method_register) {
			        return std::move(requestEvent);
		        }

		        const auto* contact = sip->sip_contact;
		        BC_HARD_ASSERT(contact != nullptr);
		        const auto* uri = contact->m_url;
		        BC_HARD_ASSERT(uri != nullptr);
		        if ((sip->sip_expires && sip->sip_expires->ex_delta == 0) ||
		            (contact->m_expires && contact->m_expires == "0"sv)) {
			        unregisters.emplace_back(uri);
		        } else {
			        registers.emplace_back(uri);
		        }
		        return std::move(requestEvent);
	        },
	};
	Server proxy{
	    {
	        // Requesting bind on port 0 to let the kernel find any available port
	        {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	        {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	        {"module::Registrar/enabled", "true"},
	        {"module::Registrar/reg-domains", "example.org"},
	    },
	    &hooks,
	};

	explicit ProxyServer(const vector<std::pair<std::string, std::string>>& extraParameters = {}) {
		for (const auto& parameter : extraParameters)
			proxy.setConfigParameter(parameter);
		proxy.start();
	}

	shared_ptr<B2buaCore> makeB2buaCoreFromConfig() const {
		const auto core = B2buaCore::create(
		    *linphone::Factory::get(), *proxy.getConfigManager()->getRoot()->get<GenericStruct>(b2bua::configSection));
		core->start();
		return core;
	}
};

struct PubSubRedisServer {
	RedisServer redis{};
	RedisParameters params = {
	    .domain = "localhost",
	    .auth = redis::auth::None(),
	    .port = redis.port(),
	    .mSlaveCheckTimeout = 999s,
	    .mSubSessionKeepAliveTimeout = 1s,
	};
};
// Does not store any state, so is safe to share between tests
auto sRedisServer = Lazy<PubSubRedisServer>();

struct SqlScope {
	static constexpr auto& poolConfigTemplate = R"({
		"outboundProxy": "<sip:default-outbound-proxy.example.org;transport=tls>",
		"registrationRequired": false,
		"maxCallsPerLine": 55,
		"loader": {
			"dbBackend": "sqlite3",
			"initQuery": "SELECT usernameInDb as username, domain as hostport, userid as user_id, passwordInDb as secret, \"clrtxt\" as secret_type, \"myNiceRealm\" as realm, alias_username, alias_domain as alias_hostport, outboundProxyInDb as outbound_proxy from users",
			"updateQuery": "SELECT usernameInDb as username, domain as hostport, userid as user_id, \"clrtxt\" as secret_type, passwordInDb as secret, \"myNiceRealm\" as realm, alias_username, alias_domain as alias_hostport, outboundProxyInDb as outbound_proxy from users where user_id = :identifier",
			"connection": "@database_filename@"
		}
	})";
	const TmpDir tmpDir{"tmpDirForSqlLoader"};
	const std::string tmpDbFileName = tmpDir.path().string() + "/database_filename";
	soci::session sql{sqlite3, tmpDbFileName};
	config::v2::AccountPool poolConfig = nlohmann::json::parse(StringFormatter{poolConfigTemplate, '@', '@'}.format(
	                                                               {{"database_filename", tmpDbFileName}}))
	                                         .get<config::v2::AccountPool>();
	SqlScope() {
		try {
			sql << R"sql(CREATE TABLE users (
						usernameInDb TEXT PRIMARY KEY,
						domain TEXT,
						userid TEXT,
						passwordInDb TEXT,
						alias_username TEXT,
						alias_domain TEXT,
						outboundProxyInDb TEXT))sql";
		} catch (const soci_error& e) {
			auto msg = "Error initializing DB : "s + e.what();
			BC_HARD_FAIL(msg.c_str());
		}
	}
};
auto sSqlScope = Lazy<SqlScope>();

void globalSqlTest() {
	///////// ARRANGE
	auto proxy = ProxyServer();
	const auto& suRoot = proxy.proxy.getRoot();
	Session commandsSession{};
	auto& ready =
	    std::get<Session::Ready>(commandsSession.connect(suRoot->getCPtr(), "localhost", sRedisServer->redis.port()));
	const auto core = proxy.makeB2buaCoreFromConfig();
	CoreAssert asserter{suRoot};

	///////// LOAD
	AccountPool pool{
	    suRoot,
	    core,
	    "testAccountPool",
	    sSqlScope->poolConfig,
	    make_unique<SQLAccountLoader>(suRoot, std::get<config::v2::SQLLoader>(sSqlScope->poolConfig.loader)),
	    &sRedisServer->params};
	const auto& accountsByUri = pool.getOrCreateView("{uri}").view;
	const auto& accountsByAlias = pool.getOrCreateView("{alias}").view;

	asserter
	    .wait([&pool] {
		    FAIL_IF(!pool.allAccountsLoaded());
		    FAIL_IF(pool.size() != 2);
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	///////// ASSERT AFTER LOAD
	auto actualAccount1 = accountsByAlias.find("sip:expected-from@sip.example.org");
	auto actualAccount2 = accountsByUri.find("sip:account2@some.provider.example.com");

	///// Account 1 checks
	BC_HARD_ASSERT(actualAccount1 != accountsByAlias.end());
	BC_HARD_ASSERT_CPP_EQUAL(
	    actualAccount1->second->getLinphoneAccount()->getParams()->getIdentityAddress()->asString(),
	    "sip:account1@some.provider.example.com");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount1->second->getAlias().str(), "sip:expected-from@sip.example.org");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount1->second->getLinphoneAccount()->getParams()->getServerAddress()->asString(),
	                         "<sip:default-outbound-proxy.example.org;transport=tls>");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount1->second->getLinphoneAccount()->getParams()->getRoutesAddresses().size(), 1);
	BC_HARD_ASSERT_CPP_EQUAL(
	    actualAccount1->second->getLinphoneAccount()->getParams()->getRoutesAddresses().begin()->get()->asString(),
	    "<sip:default-outbound-proxy.example.org;transport=tls>");
	auto account1AuthInfo = core->findAuthInfo("", "account1", "some.provider.example.com");
	BC_HARD_ASSERT_FALSE(account1AuthInfo);
	///// Account 2 checks
	BC_HARD_ASSERT(actualAccount2 != accountsByUri.end());
	BC_HARD_ASSERT_CPP_EQUAL(
	    actualAccount2->second->getLinphoneAccount()->getParams()->getIdentityAddress()->asString(),
	    "sip:account2@some.provider.example.com");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2->second->getAlias().str(), "");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2->second->getLinphoneAccount()->getParams()->getServerAddress()->asString(),
	                         "<sip:127.0.0.1:5060;transport=tcp>");

	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2->second->getLinphoneAccount()->getParams()->getRoutesAddresses().size(), 1);
	BC_HARD_ASSERT_CPP_EQUAL(
	    actualAccount2->second->getLinphoneAccount()->getParams()->getRoutesAddresses().begin()->get()->asString(),
	    "<sip:127.0.0.1:5060;transport=tcp>");
	auto account2AuthInfo = core->findAuthInfo("", "account2", "some.provider.example.com");
	BC_HARD_ASSERT_TRUE(account2AuthInfo != nullptr);
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getRealm(), "myNiceRealm");
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getUsername(), "account2");
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getDomain(), "some.provider.example.com");
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getPassword(), "p@$sword");

	///////// Update account (modified password and outbound proxy, alias added)
	sSqlScope->sql << R"sql(DELETE FROM users WHERE usernameInDb = "account2")sql";
	sSqlScope->sql
	    << R"sql(INSERT INTO users VALUES ("account2", "some.provider.example.com", "userID", "NEWp@$sword", "addedAlias", "new.domain.org", "<sip:new.outbound.org:5060;transport=tcp>"))sql";

	ready.command({"PUBLISH", "flexisip/B2BUA/account",
	               R"({"username": "account2","domain": "some.provider.example.com","identifier":"userID"})"},
	              {});

	asserter
	    .wait([&accountsByUri] {
		    const auto actualAccount = accountsByUri.find("sip:account2@some.provider.example.com");
		    FAIL_IF(actualAccount == accountsByUri.end());
		    FAIL_IF(actualAccount->second->getAlias().str() != "sip:addedAlias@new.domain.org");
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	///////// ASSERT AFTER UPDATE
	actualAccount1 = accountsByAlias.find("sip:expected-from@sip.example.org");
	actualAccount2 = accountsByUri.find("sip:account2@some.provider.example.com");
	auto actualAccount2Alias = accountsByAlias.find("sip:addedAlias@new.domain.org");
	///// Account 1 checks
	BC_HARD_ASSERT(actualAccount1 != accountsByAlias.end());
	BC_HARD_ASSERT_CPP_EQUAL(
	    actualAccount1->second->getLinphoneAccount()->getParams()->getIdentityAddress()->asString(),
	    "sip:account1@some.provider.example.com");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount1->second->getAlias().str(), "sip:expected-from@sip.example.org");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount1->second->getLinphoneAccount()->getParams()->getServerAddress()->asString(),
	                         "<sip:default-outbound-proxy.example.org;transport=tls>");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount1->second->getLinphoneAccount()->getParams()->getRoutesAddresses().size(), 1);
	BC_HARD_ASSERT_CPP_EQUAL(
	    actualAccount1->second->getLinphoneAccount()->getParams()->getRoutesAddresses().begin()->get()->asString(),
	    "<sip:default-outbound-proxy.example.org;transport=tls>");
	account1AuthInfo = core->findAuthInfo("", "account1", "some.provider.example.com");
	BC_HARD_ASSERT_FALSE(account1AuthInfo);
	///// Account 2 checks
	BC_HARD_ASSERT(actualAccount2 != accountsByUri.end());
	BC_HARD_ASSERT(actualAccount2Alias != accountsByUri.end());
	BC_HARD_ASSERT(actualAccount2->second == actualAccount2Alias->second);
	BC_HARD_ASSERT_CPP_EQUAL(
	    actualAccount2->second->getLinphoneAccount()->getParams()->getIdentityAddress()->asString(),
	    "sip:account2@some.provider.example.com");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2->second->getAlias().str(), "sip:addedAlias@new.domain.org");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2->second->getLinphoneAccount()->getParams()->getServerAddress()->asString(),
	                         "<sip:new.outbound.org:5060;transport=tcp>");

	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2->second->getLinphoneAccount()->getParams()->getRoutesAddresses().size(), 1);
	BC_HARD_ASSERT_CPP_EQUAL(
	    actualAccount2->second->getLinphoneAccount()->getParams()->getRoutesAddresses().begin()->get()->asString(),
	    "<sip:new.outbound.org:5060;transport=tcp>");
	account2AuthInfo = core->findAuthInfo("", "account2", "some.provider.example.com");
	BC_HARD_ASSERT_TRUE(account2AuthInfo != nullptr);
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getRealm(), "myNiceRealm");
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getUsername(), "account2");
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getDomain(), "some.provider.example.com");
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getPassword(), "NEWp@$sword");

	///////// Delete account2
	sSqlScope->sql << R"sql(DELETE FROM users WHERE usernameInDb = "account2")sql";

	ready.command({"PUBLISH", "flexisip/B2BUA/account",
	               R"({"username": "account2","domain":"some.provider.example.com","identifier":"userID"})"},
	              {});

	asserter
	    .wait([&accountsByUri, &accountsByAlias] {
		    FAIL_IF(accountsByUri.find("sip:account2@some.provider.example.com") != accountsByUri.end());
		    FAIL_IF(accountsByAlias.find("sip:addedAlias@new.domain.org") != accountsByAlias.end());
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();
	///////// ASSERT AFTER UPDATE
	actualAccount1 = accountsByAlias.find("sip:expected-from@sip.example.org");
	///// Account 1 checks
	BC_HARD_ASSERT(actualAccount1 != accountsByAlias.end());
	BC_HARD_ASSERT_CPP_EQUAL(
	    actualAccount1->second->getLinphoneAccount()->getParams()->getIdentityAddress()->asString(),
	    "sip:account1@some.provider.example.com");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount1->second->getAlias().str(), "sip:expected-from@sip.example.org");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount1->second->getLinphoneAccount()->getParams()->getServerAddress()->asString(),
	                         "<sip:default-outbound-proxy.example.org;transport=tls>");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount1->second->getLinphoneAccount()->getParams()->getRoutesAddresses().size(), 1);
	BC_HARD_ASSERT_CPP_EQUAL(
	    actualAccount1->second->getLinphoneAccount()->getParams()->getRoutesAddresses().begin()->get()->asString(),
	    "<sip:default-outbound-proxy.example.org;transport=tls>");
	account1AuthInfo = core->findAuthInfo("", "account1", "some.provider.example.com");
	BC_HARD_ASSERT_FALSE(account1AuthInfo);
}

void emptyNoRedisSqlTest() {
	///////// ARRANGE
	auto proxy = ProxyServer();
	const auto& suRoot = proxy.proxy.getRoot();
	CoreAssert asserter{suRoot};
	const auto core = proxy.makeB2buaCoreFromConfig();

	sSqlScope->sql << R"sql(DELETE FROM users)sql";

	///////// LOAD
	AccountPool pool{
	    suRoot,
	    core,
	    "testAccountPool",
	    sSqlScope->poolConfig,
	    make_unique<SQLAccountLoader>(suRoot, std::get<config::v2::SQLLoader>(sSqlScope->poolConfig.loader)),
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
	auto proxy = ProxyServer();
	const auto& suRoot = proxy.proxy.getRoot();
	Session commandsSession{};
	auto& ready =
	    std::get<Session::Ready>(commandsSession.connect(suRoot->getCPtr(), "localhost", sRedisServer->redis.port()));
	const auto core = proxy.makeB2buaCoreFromConfig();
	CoreAssert asserter{suRoot};

	sSqlScope->sql << R"sql(DELETE FROM users)sql";

	///////// LOAD
	AccountPool pool{
	    suRoot,
	    core,
	    "testAccountPool",
	    sSqlScope->poolConfig,
	    make_unique<SQLAccountLoader>(suRoot, std::get<config::v2::SQLLoader>(sSqlScope->poolConfig.loader)),
	    &sRedisServer->params};
	const auto& accountsByUri = pool.getOrCreateView("{uri}").view;
	const auto& accountsByAlias = pool.getOrCreateView("{alias}").view;

	asserter
	    .wait([&pool] {
		    FAIL_IF(!pool.allAccountsLoaded());
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	///////// ASSERT AFTER LOAD, empty and no crashes
	BC_HARD_ASSERT_TRUE(pool.begin() == pool.end());

	///////// Account added
	sSqlScope->sql
	    << R"sql(INSERT INTO users VALUES ("account2", "some.provider.example.com", "userID", "NEWp@$sword", "addedAlias", "new.domain.org", "<sip:new.outbound.org:5060;transport=tcp>"))sql";

	ready.command({"PUBLISH", "flexisip/B2BUA/account",
	               R"({"username": "account2","domain": "some.provider.example.com","identifier":"userID"})"},
	              {});

	asserter
	    .wait([&accountsByUri] {
		    const auto actualAccount = accountsByUri.find("sip:account2@some.provider.example.com");
		    FAIL_IF(actualAccount == accountsByUri.end());
		    FAIL_IF(actualAccount->second->getAlias().str() != "sip:addedAlias@new.domain.org");
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	///////// ASSERT AFTER UPDATE
	BC_HARD_ASSERT_TRUE(pool.size() == 1);
	const auto actualAccount2 = accountsByUri.find("sip:account2@some.provider.example.com");
	const auto actualAccount2Alias = accountsByAlias.find("sip:addedAlias@new.domain.org");
	///// Account 2 checks
	BC_HARD_ASSERT(actualAccount2 != accountsByAlias.end());
	BC_HARD_ASSERT(actualAccount2->second == actualAccount2Alias->second);
	BC_HARD_ASSERT_CPP_EQUAL(
	    actualAccount2->second->getLinphoneAccount()->getParams()->getIdentityAddress()->asString(),
	    "sip:account2@some.provider.example.com");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2->second->getAlias().str(), "sip:addedAlias@new.domain.org");
	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2->second->getLinphoneAccount()->getParams()->getServerAddress()->asString(),
	                         "<sip:new.outbound.org:5060;transport=tcp>");

	BC_HARD_ASSERT_CPP_EQUAL(actualAccount2->second->getLinphoneAccount()->getParams()->getRoutesAddresses().size(), 1);
	BC_HARD_ASSERT_CPP_EQUAL(
	    actualAccount2->second->getLinphoneAccount()->getParams()->getRoutesAddresses().begin()->get()->asString(),
	    "<sip:new.outbound.org:5060;transport=tcp>");
	auto account2AuthInfo = core->findAuthInfo("", "account2", "some.provider.example.com");
	BC_HARD_ASSERT_TRUE(account2AuthInfo != nullptr);
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getRealm(), "myNiceRealm");
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getUsername(), "account2");
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getDomain(), "some.provider.example.com");
	BC_HARD_ASSERT_CPP_EQUAL(account2AuthInfo->getPassword(), "NEWp@$sword");
}

template <typename T>
inline std::ostream& operator<<(std::ostream& os, const std::vector<T>& vector) noexcept {
	os << "std::vector[\n";
	for (const auto& elem : vector) {
		os << '\t' << elem << ",\n";
	}
	os << "]";
	return os;
}

/**
 * Verify an invalid uri is discarded
 */
void accountCreation() {
	vector<config::v2::Account> accounts{};
	// empty uri
	accounts.emplace_back();
	// invalid uri
	accounts.emplace_back(config::v2::Account::Parameters{.uri = "invalid-sip-uri"});
	// valid uri
	accounts.emplace_back(config::v2::Account::Parameters{.uri = "sip:valid-uri@example.org"});

	ProxyServer servers{};
	const auto proxy = servers.proxy;
	const auto b2bua = servers.makeB2buaCoreFromConfig();
	auto asserter = CoreAssert(proxy, b2bua);

	auto poolConfig = config::v2::AccountPool{
	    .registrationRequired = true,
	    .maxCallsPerLine = 682,
	    .loader = {},
	    .outboundProxy = "<sip:127.0.0.1:"s + proxy.getFirstPort() + ";transport=tcp>",
	    .registrationThrottlingRateMs = 0,
	};
	auto pool = make_optional<AccountPool>(proxy.getRoot(), b2bua, "createAccountTest", poolConfig,
	                                       make_unique<StaticAccountLoader>(std::move(accounts)));
	BC_HARD_ASSERT(pool->allAccountsLoaded());
	asserter.iterateUpTo(3, [&]() { return LOOP_ASSERTION(servers.registers.size() == 1); }, 200ms).assert_passed();
	BC_ASSERT_CPP_EQUAL(servers.registers.size(), 1);
}

/**
 * Verify that an account with the 'registrar' field set actually registers to the correct registrar.
 */
void accountCreationDifferentRegistrarAddresses() {
	ProxyServer serversOne{};
	const auto proxyOne = serversOne.proxy;
	const auto b2buaOne = serversOne.makeB2buaCoreFromConfig();
	ProxyServer serversTwo{};
	const auto proxyTwo = serversTwo.proxy;

	vector<config::v2::Account> accounts{};
	// First user will register to the first proxy (using the registrar specified in the 'registrar' field).
	accounts.emplace_back(config::v2::Account::Parameters{
	    .uri = "sip:userOne@sip.example.org",
	    .outboundProxy = "unreachable.proxy.org", // Intentionally set to an unreachable address
	    .registrar = "127.0.0.1:"s + proxyOne.getFirstPort(),
	});
	// Second user will register to the second proxy (using the default registrar set in the account pool).
	accounts.emplace_back(config::v2::Account::Parameters{
	    .uri = "sip:userTwo@sip.example.org",
	    .outboundProxy = "unreachable.proxy.org", // Intentionally set to an unreachable address
	});

	auto poolConfig = config::v2::AccountPool{
	    .registrationRequired = true,
	    .maxCallsPerLine = 1,
	    .loader = {},
	    .outboundProxy = "sip:unreachable.proxy.org", // Intentionally set to an unreachable address
	    .registrar = "sip:127.0.0.1:"s + proxyTwo.getFirstPort() + ";transport=tcp",
	    .registrationThrottlingRateMs = 0,
	};
	auto pool = make_optional<AccountPool>(proxyOne.getRoot(), b2buaOne, "createAccountTest", poolConfig,
	                                       make_unique<StaticAccountLoader>(std::move(accounts)));
	BC_HARD_ASSERT(pool->allAccountsLoaded());

	auto asserter = CoreAssert(proxyOne, b2buaOne, proxyTwo);
	asserter
	    .iterateUpTo(
	        3,
	        [&]() {
		        FAIL_IF(serversOne.registers.size() != 1);
		        FAIL_IF(serversTwo.registers.size() != 1);
		        return ASSERTION_PASSED();
	        },
	        200ms)
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(serversOne.registers.size(), 1);
	BC_ASSERT_CPP_EQUAL(serversTwo.registers.size(), 1);
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
	auto accounts = vector{accountCount, config::v2::Account{}};
	Random random{tester::random::seed()};
	auto stringGenerator = random.string();
	for (auto& account : accounts) {
		account.update({.uri = "sip:uri-" + stringGenerator.generate(10) + "@example.org"});
	}
	auto proxyServer = ProxyServer();
	const auto& proxy = proxyServer.proxy;
	const auto& suRoot = proxy.getRoot();
	const auto core = proxyServer.makeB2buaCoreFromConfig();
	auto asserter = CoreAssert(proxy, core);

	/////////
	/// Rate to 0ms (synchronous)
	/////////
	auto poolConfig = config::v2::AccountPool{
	    .registrationRequired = true,
	    .maxCallsPerLine = 682,
	    .loader = {},
	    .outboundProxy = "<sip:127.0.0.1:"s + proxy.getFirstPort() + ";transport=tcp>",
	    .registrationThrottlingRateMs = 0,
	};
	auto pool = make_optional<AccountPool>(suRoot, core, "perfTestAccountPool", poolConfig,
	                                       make_unique<StaticAccountLoader>(vector{accounts}));
	BC_HARD_ASSERT(pool->allAccountsLoaded());
	auto& registers = proxyServer.registers;
	registers.clear();
	// Let the Proxy receive the REGISTER requests
	asserter.iterateUpTo(3, [&]() { return LOOP_ASSERTION(registers.size() == accountCount); }, 200ms).assert_passed();
	BC_HARD_ASSERT_CPP_EQUAL(registers.size(), accountCount);
	registers.clear();

	/////////
	/// Rate to 100ms
	/////////
	poolConfig.registrationThrottlingRateMs = 100;
	pool.emplace(suRoot, core, "perfTestAccountPool", poolConfig, make_unique<StaticAccountLoader>(vector{accounts}));
	BC_HARD_ASSERT(!pool->allAccountsLoaded());
	const auto aBitMoreThanHalfway = accountCount / 2 + 2;
	asserter
	    .iterateUpTo(
	        aBitMoreThanHalfway, [&]() { return LOOP_ASSERTION(3 < registers.size()); },
	        aBitMoreThanHalfway * chrono::milliseconds(poolConfig.registrationThrottlingRateMs))
	    .assert_passed();

	if (registers.size() < 4 || 7 < registers.size()) {
		auto msg = ostringstream();
		msg << "Received either more, or less REGISTERs than expected.";
		msg << "\nReceived:" << registers;
		msg << "\nAll accounts: " << accounts;
		BC_HARD_FAIL(msg.str().c_str());
	}
}

template <uint32_t accountCount, uint32_t registerIntervalMs>
class AccountPoolConnectedToRedis {
public:
	using AccountCollection = decltype(std::declval<Loader>().loadAll());
	class MockAccountLoader : public Loader {
	public:
		explicit MockAccountLoader(AccountCollection& accounts) : mAccounts(accounts) {
		}

	private:
		vector<config::v2::Account> loadAll() override {
			return mAccounts;
		}

		void accountUpdateNeeded(const RedisAccountPub& redisAccountPub, const OnAccountUpdateCB& callback) override {
			const auto uri = redisAccountPub.uri.str();
			auto accountIt = find_if(mAccounts.cbegin(), mAccounts.cend(),
			                         [&uri](const auto& account) { return account.getUri() == uri; });
			optional<config::v2::Account> account;
			if (accountIt != mAccounts.cend()) account = *accountIt;
			callback(redisAccountPub.uri.str(), account);
		}

		AccountCollection& mAccounts;
	};

	AccountPoolConnectedToRedis()
	    : AccountPoolConnectedToRedis([] {
		      auto dbAccounts = vector{
		          accountCount,
		          config::v2::Account{{.secretType = config::v2::SecretType::Cleartext}},
		      };
		      Random random{random::seed()};
		      auto stringGenerator = random.string();
		      for (auto& account : dbAccounts) {
			      account.update(config::v2::Account::Parameters{
			          .uri = "sip:uri-" + stringGenerator.generate(10) + "@example.org",
			          .userId = "userid-" + stringGenerator.generate(10),
			          .secret = "secret-" + stringGenerator.generate(10),
			          .realm = "realm-" + stringGenerator.generate(10),
			          .alias = "sip:alias-" + stringGenerator.generate(10) + "@example.org",
			      });
		      }
		      return dbAccounts;
	      }()){};

	explicit AccountPoolConnectedToRedis(AccountCollection&& accounts,
	                                     const vector<std::pair<std::string, std::string>>& parameters = {})
	    : proxy(parameters), core(proxy.makeB2buaCoreFromConfig()), dbAccounts(accounts),
	      pool(proxy.proxy.getRoot(),
	           core,
	           "TestAccountPool",
	           config::v2::AccountPool{
	               .registrationRequired = true,
	               .maxCallsPerLine = 100,
	               .loader = {},
	               .outboundProxy = "<sip:127.0.0.1:" + std::string(proxy.proxy.getFirstPort()) + ";transport=tcp>",
	               .registrationThrottlingRateMs = registerIntervalMs,
	           },
	           std::make_unique<MockAccountLoader>(dbAccounts),
	           &sRedisServer->params){};

	auto allAccountsAvailable(BcAssert<>& asserter) {
		auto result = asserter.iterateUpTo(
		    dbAccounts.size() + 5,
		    [this] {
			    FAIL_IF(!pool.allAccountsLoaded());
			    for (const auto& [_, account] : pool) {
				    FAIL_IF(!account->isAvailable());
			    }
			    return ASSERTION_PASSED();
		    },
		    chrono::milliseconds(dbAccounts.size() * registerIntervalMs) + 1s);
		BC_HARD_ASSERT_CPP_EQUAL(pool.size(), accountCount);
		return result;
	}

	ProxyServer proxy{};
	std::shared_ptr<B2buaCore> core{};
	AccountCollection dbAccounts{};
	AccountPool pool;
};

/**
 * After recovering from a Redis connection loss, the B2BUA re-loads all of its accounts from DB, because it might have
 * missed some updates while the connection was down. It must then progressively update its local pool.
 *
 * 1. Build and register a pool subscribed to Redis
 * 2. Break the connection with Redis
 * 3. Change some accounts in the database
 * 4. Let the pool reconnect to Redis
 * 5. Verify the pool is now in sync with the database (params changed, new accounts added, old accounts deleted)
 */
template <uint32_t accountCount, uint32_t registerIntervalMs>
void accountsUpdatedOnRedisResubscribe() {
	auto accountPool = AccountPoolConnectedToRedis<accountCount, registerIntervalMs>();
	auto& registers = accountPool.proxy.registers;
	auto& unregisters = accountPool.proxy.unregisters;
	const auto& core = accountPool.core;
	auto asserter = CoreAssert(accountPool.proxy.proxy, core);
	auto& dbAccounts = accountPool.dbAccounts;
	ASSERT_PASSED(accountPool.allAccountsAvailable(asserter));
	// (+1 because of server's default account)
	BC_HARD_ASSERT_CPP_EQUAL(core->getAccountList().size(), accountCount + 1);
	// Not '+1' because the default account does not have authentication information.
	BC_HARD_ASSERT_CPP_EQUAL(core->getAuthInfoList().size(), accountCount);
	BC_ASSERT_CPP_EQUAL(registers.size(), accountCount);
	BC_ASSERT_CPP_EQUAL(unregisters.size(), 0);
	if (registers.size() != accountCount) {
		auto msg = ostringstream();
		msg << "REGISTERs received: " << registers;
		BC_HARD_FAIL(msg.str().c_str());
	}
	registers.clear();
	unregisters.clear();

	// Trigger reload by breaking the connection with redis
	sRedisServer->redis.restart();

	// Change values in the database
	BC_HARD_ASSERT(5 < accountCount);
	dbAccounts[0].update({.alias = "sip:changed-alias@example.org"});
	dbAccounts[2].update({.userId = "changed-userId", .realm = "changed-realm"});
	const auto& unexpectedUris = array{dbAccounts[3].getUri(), dbAccounts.back().getUri()};
	// Changing the URI is equivalent to deleting an account and creating a new one
	dbAccounts[3].update({.uri = "sip:changed-uri@example.org"});
	dbAccounts.pop_back();
	dbAccounts.emplace_back(config::v2::Account::Parameters{
	    .uri = "sip:added@example.org",
	    .alias = "sip:added-alias@example.org",
	});
	constexpr auto accountsDeleted = 2;
	constexpr auto accountsAdded = accountsDeleted;
	constexpr auto accountsUpdated = 1;
	BC_HARD_ASSERT_CPP_EQUAL(dbAccounts.size(), accountCount);

	// Pool detects the broken connection
	const auto& pool = accountPool.pool;
	asserter
	    .iterateUpTo(
	        3, [&]() { return LOOP_ASSERTION(!pool.allAccountsLoaded()); },
	        sRedisServer->params.mSubSessionKeepAliveTimeout)
	    .hard_assert_passed();

	asserter.iterateUpTo(3, [&]() { return LOOP_ASSERTION(!registers.empty()); }, 1s).assert_passed();
	if constexpr (registerIntervalMs == 0) {
		// All operations are generated in the same loop iteration, and are received in one iteration
		BC_ASSERT_CPP_EQUAL(registers.size(), accountsAdded + accountsUpdated);
	} else {
		// Same behaviour as with the initial load, there exists an intermediate state where some accounts have been
		// updated, but not all
		BC_ASSERT(registers.size() < accountsAdded + accountsUpdated);
	}

	// Accounts are reloaded
	asserter
	    .iterateUpTo(
	        10,
	        [&]() {
		        FAIL_IF(registers.size() != accountsAdded + accountsUpdated);
		        return LOOP_ASSERTION(unregisters.size() == accountsDeleted);
	        },
	        1s)
	    .assert_passed();
	// Accounts have *not* been duplicated (+1 because of server's default account)
	BC_HARD_ASSERT_CPP_EQUAL(core->getAccountList().size(), accountCount + 1);
	// '-1' because the account 'sip:added@example.org' did not provide authentication information.
	BC_HARD_ASSERT_CPP_EQUAL(core->getAuthInfoList().size(), accountCount - 1);
	for (const auto& [_, account] : pool) {
		BC_ASSERT(account->isAvailable());
	}
	const auto& defaultView = pool.getDefaultView().view;
	BC_ASSERT_CPP_EQUAL(defaultView.at(dbAccounts[0].getUri())->getAlias().getUser(), "changed-alias");
	const auto& uri = SipUri(dbAccounts[2].getUri());
	const auto& authInfo = core->findAuthInfo("", uri.getUser(), uri.getHost());
	BC_HARD_ASSERT(authInfo != nullptr);
	BC_ASSERT_CPP_EQUAL(authInfo->getRealm(), "changed-realm");
	BC_ASSERT_CPP_EQUAL(authInfo->getUserid(), "changed-userId");
	BC_ASSERT_CPP_EQUAL(defaultView.at("sip:changed-uri@example.org")->getAlias().str(), dbAccounts[3].getAlias());
	BC_ASSERT_CPP_EQUAL(defaultView.at("sip:added@example.org")->getAlias().getUser(), "added-alias");
	BC_ASSERT_CPP_EQUAL(registers.size(), accountsAdded + accountsUpdated);
	BC_ASSERT_CPP_EQUAL(unregisters.size(), accountsDeleted);

	for (const auto& unexpectedUri : unexpectedUris) {
		BC_ASSERT(defaultView.find(unexpectedUri) == defaultView.end());
	}
}

/**
 * Verify that the system is resilient to frequent (full) reloads, happening before the previous reload has finished
 * processing.
 *
 * If the B2BUA restores its Redis connection twice (or more) in a row before it has finished loading the accounts from
 * the previous reconnection, it could lead to a run-away condition where update tasks pile-up. This test verifies that
 * the running update process is stopped before starting another one in this context.
 *
 * 1. Build and register a pool subscribed to Redis
 * 2. Break the connection with Redis
 * 3. Let the pool detect it, reconnect, and start an update process
 * 4. Break the connection again before that process finishes
 * 5. Let the pool reconnect and finish a second update process
 * 6. Verify that some state in the database that existed only between the two connection losses was never processed
 */
template <uint32_t accountCount, uint32_t registerIntervalMs>
void accountsUpdatePartiallyAbortedOnRapidReload() {
	auto accountPool = AccountPoolConnectedToRedis<accountCount, registerIntervalMs>();
	auto& registers = accountPool.proxy.registers;
	auto& unregisters = accountPool.proxy.unregisters;
	const auto& core = accountPool.core;
	auto asserter = CoreAssert(accountPool.proxy.proxy, core);
	ASSERT_PASSED(accountPool.allAccountsAvailable(asserter));
	BC_HARD_ASSERT_CPP_EQUAL(registers.size(), accountCount);
	BC_HARD_ASSERT_CPP_EQUAL(unregisters.size(), 0);
	registers.clear();
	unregisters.clear();

	static_assert(10 < registerIntervalMs);

	registers.clear();
	unregisters.clear();
	// Reload
	auto& redisServer = sRedisServer->redis;
	redisServer.restart();

	// Change values in the database
	auto& dbAccounts = accountPool.dbAccounts;
	dbAccounts[dbAccounts.size() / 3].update({.uri = "sip:flag@example.org"});
	dbAccounts.back().update({.uri = "sip:cancelled-before-reached@example.org"});

	// Pool detects the broken connection
	const auto& pool = accountPool.pool;
	asserter
	    .iterateUpTo(
	        3, [&]() { return LOOP_ASSERTION(!pool.allAccountsLoaded()); },
	        sRedisServer->params.mSubSessionKeepAliveTimeout)
	    .hard_assert_passed();
	const auto& defaultView = pool.getDefaultView().view;
	asserter
	    .iterateUpTo(
	        accountCount / 2,
	        [&]() { return LOOP_ASSERTION(defaultView.find("sip:flag@example.org") != defaultView.end()); },
	        chrono::milliseconds(accountCount * registerIntervalMs / 2) + 1s)
	    .assert_passed();
	// Trigger another reload before accounts are finished loading
	redisServer.restart();
	dbAccounts.back().update({.uri = "sip:latest-value@example.org"});
	// Pause processing until redis is up again
	std::ignore = redisServer.port();
	// Resume iterating
	ASSERT_PASSED(accountPool.allAccountsAvailable(asserter));
	asserter.iterateUpTo(10, [&]() { return LOOP_ASSERTION(unregisters.size() == 2); }, 1s).assert_passed();
	BC_ASSERT_CPP_EQUAL(registers.size(), 2);
	BC_ASSERT_CPP_EQUAL(unregisters.size(), 2);
	BC_ASSERT_CPP_EQUAL(defaultView.count("sip:latest-value@example.org"), 1);
	for (const auto& uri : registers) {
		BC_ASSERT(uri.getUser() != "cancelled-before-reached");
	}
}

/**
 * Verify that a REGISTER request is sent when a password changes
 * Put the register threshold to 0 in order to receive all registers in the same loop iteration.
 */
void accountRegistrationOnAuthInfoUpdate() {
	constexpr auto accountCount = 2;
	auto accountPool = AccountPoolConnectedToRedis<accountCount, 0>();
	auto& account = accountPool.dbAccounts[0];
	// choose a simple uri and id for the account we want to update
	account = config::v2::Account{{
	    .uri = "sip:user@example.org",
	    .userId = "userId",
	    .secretType = config::v2::SecretType::Cleartext,
	}};
	auto& registers = accountPool.proxy.registers;
	auto& unregisters = accountPool.proxy.unregisters;
	CoreAssert asserter{accountPool.proxy.proxy, accountPool.core};
	ASSERT_PASSED(accountPool.allAccountsAvailable(asserter));
	BC_ASSERT_CPP_EQUAL(registers.size(), accountCount);
	BC_ASSERT_CPP_EQUAL(unregisters.size(), 0);
	if (registers.size() != accountCount) {
		auto msg = ostringstream();
		msg << "REGISTERs received: " << registers;
		BC_HARD_FAIL(msg.str().c_str());
	}
	const auto uri = SipUri(account.getUri());
	Session commandsSession{};
	auto& ready = std::get<Session::Ready>(
	    commandsSession.connect(accountPool.proxy.proxy.getRoot()->getCPtr(), "localhost", sRedisServer->redis.port()));

	// add a password to an account, expect to receive 1 register
	account.update({.secret = "password"});
	registers.clear();
	unregisters.clear();

	{
		ready.command({"PUBLISH", "flexisip/B2BUA/account",
		               R"({"username":"user","domain":"example.org","identifier":"userID"})"},
		              {});
		asserter.iterateUpTo(10, [&registers]() { return LOOP_ASSERTION(registers.size() == 1); }, 1s).assert_passed();

		const auto& authInfo = accountPool.core->findAuthInfo("", uri.getUser(), uri.getHost());
		BC_HARD_ASSERT(authInfo != nullptr);
		BC_ASSERT_CPP_EQUAL(authInfo->getPassword(), account.getSecret());
		BC_ASSERT_CPP_EQUAL(unregisters.size(), 0);
	}

	// change one account password, expect to receive 1 register
	account.update({.secret = "another-password"});
	registers.clear();

	{
		ready.command({"PUBLISH", "flexisip/B2BUA/account",
		               R"({"username":"user","domain":"example.org","identifier":"userID"})"},
		              {});
		asserter.iterateUpTo(10, [&registers]() { return LOOP_ASSERTION(registers.size() == 1); }, 1s).assert_passed();
		const auto& authInfo = accountPool.core->findAuthInfo("", uri.getUser(), uri.getHost());
		BC_HARD_ASSERT(authInfo != nullptr);
		BC_ASSERT_CPP_EQUAL(authInfo->getPassword(), account.getSecret());
		BC_ASSERT_CPP_EQUAL(unregisters.size(), 0);
	}
}

/**
 * Verify that auth info is correctly removed on an account deletion.
 * @tparam authenticationEnabled whether authentication is enabled on the outbound proxy or not.
 */
template <const bool authenticationEnabled>
void authInfoDeletionOnAccountRemoval() {
	TmpDir authDbDirectory{"auth"};
	constexpr int nbAccounts{10};
	const string domain{"example.org"};

	// Create our own accounts database instead of using the one proposed by AccountPoolConnectedToRedis.
	// Warning: realm == domain.
	auto accounts = vector{
	    nbAccounts,
	    config::v2::Account{{.secretType = config::v2::SecretType::Cleartext, .realm = domain}},
	};
	Random random{random::seed()};
	auto stringGenerator = random.string();
	for (auto& account : accounts) {
		const auto username = "uri-" + stringGenerator.generate(10);
		account.update(config::v2::Account::Parameters{
		    .uri = "sip:" + username + "@" + domain,
		    .userId = username,
		    .secret = "secret-" + stringGenerator.generate(10),
		    .alias = "sip:alias-" + stringGenerator.generate(10) + "@" + domain,
		});
	}

	vector<std::pair<std::string, std::string>> extraParameters{};
	if (authenticationEnabled) {
		const auto authDbFilePath = authDbDirectory.path() / "auth-db.txt";
		std::ofstream authDb{authDbFilePath};
		authDb << "version:1\n\n";
		for (const auto& account : accounts)
			authDb << account.getUserId() << "@" << domain << " clrtxt:" + account.getSecret() + " ;\n";

		extraParameters.emplace_back("module::Authentication/enabled", "true");
		extraParameters.emplace_back("module::Authentication/auth-domains", domain);
		extraParameters.emplace_back("module::Authentication/file-path", authDbFilePath);
	}

	AccountPoolConnectedToRedis<nbAccounts, 0> helper{std::move(accounts), extraParameters};
	auto& proxy = helper.proxy;
	auto& pool = helper.pool;
	auto& b2bua = helper.core;
	auto& dbAccounts = helper.dbAccounts;

	CoreAssert asserter{proxy.proxy, b2bua};
	helper.allAccountsAvailable(asserter).hard_assert_passed();
	BC_HARD_ASSERT_CPP_EQUAL(pool.size(), nbAccounts);

	// (+1 because of server's default account)
	BC_HARD_ASSERT_CPP_EQUAL(b2bua->getAccountList().size(), nbAccounts + 1);
	// Not '+1' because the default account does not have authentication information.
	BC_HARD_ASSERT_CPP_EQUAL(b2bua->getAuthInfoList().size(), nbAccounts);
	BC_ASSERT_CPP_EQUAL(proxy.registers.size(), (authenticationEnabled ? 2 : 1) * nbAccounts);
	BC_ASSERT_CPP_EQUAL(proxy.unregisters.size(), 0);
	proxy.registers.clear();
	proxy.unregisters.clear();

	// Trigger reload by breaking the connection with redis.
	sRedisServer->redis.restart();

	constexpr int nbAccountsDeleted{3};
	vector<shared_ptr<linphone::Account>> deletedLinphoneAccounts{};
	vector<shared_ptr<linphone::Account>> stillAliveLinphoneAccounts{};
	auto accountsViewIt = pool.getDefaultView().view.begin();
	for (auto id = 0; id < nbAccounts - nbAccountsDeleted; ++id, ++accountsViewIt)
		stillAliveLinphoneAccounts.emplace_back(accountsViewIt->second->getLinphoneAccount());
	for (auto id = 0; id < nbAccountsDeleted; ++id, ++accountsViewIt)
		deletedLinphoneAccounts.emplace_back(accountsViewIt->second->getLinphoneAccount());

	// As 'accounts' and 'accountsView' are not sorted the same way, find accounts from 'deletedLinphoneAccounts'
	// matching accounts in 'accounts'.
	const auto predicate = [&deletedLinphoneAccounts](const config::v2::Account& account) {
		return any_of(deletedLinphoneAccounts.begin(), deletedLinphoneAccounts.end(),
		              [&account](const shared_ptr<linphone::Account>& deletedAccount) {
			              return deletedAccount->getParams()->getIdentityAddress()->getUsername() ==
			                     account.getUserId();
		              });
	};
	// Remove accounts from the database.
	for (auto id = 0; id < nbAccountsDeleted; ++id)
		dbAccounts.erase(find_if(dbAccounts.begin(), dbAccounts.end(), predicate));

	// Pool detects the broken connection.
	asserter
	    .iterateUpTo(
	        3, [&] { return LOOP_ASSERTION(!pool.allAccountsLoaded()); },
	        sRedisServer->params.mSubSessionKeepAliveTimeout)
	    .hard_assert_passed();

	// Make sure we received at least nbAccountsDeleted unREGISTER requests.
	asserter.iterateUpTo(
	            10, [&] { return LOOP_ASSERTION(proxy.unregisters.size() >= nbAccountsDeleted); }, 1s)
	    .assert_passed();

	BC_HARD_ASSERT_CPP_EQUAL(b2bua->getAccountList().size(), nbAccounts + 1 - nbAccountsDeleted);
	// Verify that the B2BUA server correctly removed auth info.
	BC_HARD_ASSERT_CPP_EQUAL(b2bua->getAuthInfoList().size(), nbAccounts - nbAccountsDeleted);
	for (const auto& [_, account] : pool)
		BC_ASSERT(account->isAvailable());

	for (const auto& account : deletedLinphoneAccounts)
		BC_ASSERT_ENUM_EQUAL(account->getState(), linphone::RegistrationState::Cleared);
	for (const auto& account : stillAliveLinphoneAccounts)
		BC_ASSERT_ENUM_EQUAL(account->getState(), linphone::RegistrationState::Ok);
}

const TestSuite _{
    "b2bua::sip-bridge::account::AccountPool",
    {
        CLASSY_TEST(accountCreation),
        CLASSY_TEST(accountCreationDifferentRegistrarAddresses),
        CLASSY_TEST(accountRegistrationThrottling),
        CLASSY_TEST((accountsUpdatedOnRedisResubscribe<10, 0>)),
        CLASSY_TEST((accountsUpdatedOnRedisResubscribe<10, 1>)),
        CLASSY_TEST((accountsUpdatePartiallyAbortedOnRapidReload<10, 15>)),
        CLASSY_TEST(accountRegistrationOnAuthInfoUpdate),
        CLASSY_TEST(authInfoDeletionOnAccountRemoval<false>),
        CLASSY_TEST(authInfoDeletionOnAccountRemoval<true>),
    },
};

const TestSuite SQL{
    "b2bua::sip-bridge::account::AccountPool-SQL",
    {
        CLASSY_TEST(globalSqlTest),
        CLASSY_TEST(emptyNoRedisSqlTest),
        CLASSY_TEST(emptyThenPublishSqlTest),
    },
    Hooks()
        .beforeEach([] {
	        sSqlScope->sql
	            << R"sql(INSERT INTO users VALUES ("account1", "some.provider.example.com", "", "", "expected-from", "sip.example.org", ""))sql";
	        sSqlScope->sql
	            << R"sql(INSERT INTO users VALUES ("account2", "some.provider.example.com", "userID", "p@$sword", "", "", "<sip:127.0.0.1:5060;transport=tcp>"))sql";
        })
        .afterEach([] { sSqlScope->sql << R"sql(DELETE FROM users)sql"; })
        .afterSuite([] {
	        sSqlScope.reset();
	        sRedisServer.reset();
	        return 0;
        }),
};

} // namespace
} // namespace flexisip::tester