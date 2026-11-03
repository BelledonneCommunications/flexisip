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

#include "b2bua/sip-bridge/sip-bridge.hh"

#include <chrono>

#include "belle-sip/auth-helper.h"
#include "linphone++/linphone.hh"
#include "soci/session.h"
#include "soci/sqlite3/soci-sqlite3.h"

#include "b2bua/b2bua-server.hh"
#include "exceptions/bad-configuration.hh"
#include "registrardb-internal.hh"
#include "utils/bc-utils.hh"
#include "utils/core-assert.hh"
#include "utils/server/proxy-server.hh"
#include "utils/server/redis-server.hh"
#include "utils/string-formatter.hh"
#include "utils/temp-file.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

#include "../helpers.hh"

using namespace linphone;

namespace flexisip::tester {
namespace {

using namespace std;
using namespace std::chrono_literals;
using namespace std::string_literals;

void loadAccountsFromSQL() {
	TmpDir sqliteDbDir{"b2bua::bridge::loadAccountsFromSQL"};
	const auto& sqliteDbFilePath = sqliteDbDir.path() / "db.sqlite";
	const auto& providersConfigPath = sqliteDbDir.path() / "providers.json";
	try {
		soci::session sql(soci::sqlite3, sqliteDbFilePath);
		sql << R"sql(CREATE TABLE users (
                        username TEXT PRIMARY KEY,
                        hostport TEXT,
                        userid TEXT,
                        passwordInDb TEXT,
                        alias_username TEXT,
                        alias_hostport TEXT,
                        outboundProxyInDb TEXT))sql";
		sql << R"sql(INSERT INTO users VALUES ("account1", "some.provider.example.com", "", "", "alias", "sip.example.org", ""))sql";
		sql << R"sql(INSERT INTO users VALUES ("account2", "some.provider.example.com", "test-userID", "clear text passphrase", "", "", "sip.linphone.org"))sql";
		sql << R"sql(INSERT INTO users VALUES ("account3", "some.provider.example.com", "", "", "", "", ""))sql";
	} catch (const soci::soci_error& e) {
		auto msg = "Error initiating DB : "s + e.what();
		BC_HARD_FAIL(msg.c_str());
	}
	StringFormatter jsonConfig{R"json({
        "schemaVersion": 2,
        "providers": [
            {
                "name": "Stub Provider",
                "triggerCondition": { "strategy": "Always" },
                "accountToUse": { "strategy": "Random" },
                "onAccountNotFound": "decline",
                "outgoingInvite": { "to": "{incoming.to}" },
                "accountPool": "FlockOfJabirus"
            }
        ],
        "accountPools": {
            "FlockOfJabirus": {
                "registrationRequired": true,
                "maxCallsPerLine": 3125,
                "registrar": "<sip:127.0.0.1:port;transport=tcp>",
                "loader": {
                    "dbBackend": "sqlite3",
                    "initQuery": "SELECT username, hostport, userid as user_id, \"clrtxt\" as secret_type, \"\" as realm, passwordInDb as secret, alias_username, alias_hostport, outboundProxyInDb as outbound_proxy from users",
                    "updateQuery": "not yet implemented",
                    "connection": "db-file-path"
                }
            }
        }
    })json",
	                           '', ''};
	auto redis = RedisServer();
	Server proxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "some.provider.example.com"},
	    {"module::Registrar/db-implementation", "redis"},
	    {"module::Registrar/redis-server-domain", "localhost"},
	    {"module::Registrar/redis-server-port", std::to_string(redis.port())},
	    {"b2bua-server/application", "sip-bridge"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server::sip-bridge/providers", providersConfigPath},
	    // B2bua use writable-dir instead of var folder
	    {"b2bua-server/data-directory", bcTesterWriteDir()},
	}};
	proxy.start();
	std::ofstream{providersConfigPath} << jsonConfig.format({
	    {"port", proxy.getFirstPort()},
	    {"db-file-path", sqliteDbFilePath},
	});
	const auto b2buaLoop = std::make_shared<sofiasip::SuRoot>();
	const auto b2buaServer = std::make_shared<B2buaServer>(b2buaLoop, proxy.getConfigManager());
	b2buaServer->init();
	CoreAssert asserter{proxy, b2buaLoop};

	const auto& sipProviders =
	    dynamic_cast<const b2bua::bridge::SipBridge&>(b2buaServer->getApplication()).getProviders();
	BC_HARD_ASSERT_CPP_EQUAL(sipProviders.size(), 1);
	const auto& accountPool = sipProviders[0].getAccountPool();
	const auto& accountsByUri = accountPool.getDefaultView().view;
	// Leave it time to connect to Redis, then load accounts
	asserter
	    .iterateUpTo(
	        10,
	        [&accountPool] {
		        FAIL_IF(accountPool.size() != 3);
		        for (const auto& [_, account] : accountPool) {
			        FAIL_IF(!account->isAvailable());
		        }
		        // b2bua accounts registered
		        return ASSERTION_PASSED();
	        },
	        200ms)
	    .assert_passed();
	BC_HARD_ASSERT_CPP_EQUAL(accountPool.size(), 3);
	{
		const auto& account = accountsByUri.at("sip:account1@some.provider.example.com");
		BC_HARD_ASSERT(account != nullptr);
		BC_ASSERT_CPP_EQUAL(account->getAlias().str(), "sip:alias@sip.example.org");
	}
	{
		const auto& account = accountsByUri.at("sip:account2@some.provider.example.com");
		BC_HARD_ASSERT(account != nullptr);
		const auto& authInfo =
		    account->getLinphoneAccount()->getCore()->findAuthInfo("", "account2", "some.provider.example.com");
		BC_HARD_ASSERT(authInfo != nullptr);
		BC_ASSERT_CPP_EQUAL(authInfo->getUserid(), "test-userID");
		BC_ASSERT_CPP_EQUAL(authInfo->getPassword(), "clear text passphrase");
	}
	BC_HARD_ASSERT(accountsByUri.at("sip:account3@some.provider.example.com") != nullptr);

	// shutdown / cleanup
	std::ignore = b2buaServer->stop();
}

/*
 * Test parameter cannot be set to a negative value.
 */
void invalidSQLLoaderThreadPoolSize() {
	const auto& configDir = TmpDir{__FUNCTION__};
	const auto& sipBridgeConfig = configDir.path() / "providers.json";
	const auto& providers = R"json({
        "schemaVersion": 2,
        "providers": [ ],
        "accountPools": {
            "Pool": {
                "outboundProxy": "<sip:127.0.0.1:0;transport=udp>",
                "registrationRequired": true,
                "maxCallsPerLine": 55,
                "loader": {
                    "dbBackend": "sqlite3",
                    "initQuery": "stub-request",
                    "updateQuery": "stub-request",
                    "connection": "",
                    "threadPoolSize": -1
                }
            }
        }
    })json"s;
	ofstream{sipBridgeConfig} << providers;

	const auto& configManager = make_shared<ConfigManager>();
	configManager->setOverrideMap({
	    {"b2bua-server/application", "sip-bridge"},
	    {"b2bua-server/data-directory", bcTesterWriteDir()},
	    {"b2bua-server::sip-bridge/providers", sipBridgeConfig.string()},
	});
	configManager->applyOverrides(true);
	const auto& b2buaServer = make_shared<flexisip::B2buaServer>(make_shared<sofiasip::SuRoot>(), configManager);

	BC_ASSERT_THROWN(b2buaServer->init(), BadConfiguration);

	std::ignore = b2buaServer->stop();
}

/** Test (un)registration of accounts against a proxy that requires authentication.
 *
 * A Flexisip proxy will play the role of an external proxy requiring authentication on REGISTERs.
 * The B2BUA is configured with 4 statically defined accounts:
 * 2 with the domain equal to realm and 2 others with a different domain.
 * For each domain, one account has the full clear-text password, and the other only the HA1.
 * Test that each auth method is succesful, and that accounts are un-registered properly when the B2BUA server shuts
 * down gracefully.
 *
 * The proxy is configured to challenge every request without exception, meaning the client cannot simply send the
 * unREGISTER and delete everything, but has to respond to the proxy's challenge response.
 */
void authenticatedAccounts() {
	const auto domain1 = "domain.example.org";
	const auto domain2 = "another.example.org";
	const auto realm = domain1;
	const auto password = "a-clear-text-password";
	char ha1[33];
	belle_sip_auth_helper_compute_ha1("ha1-md5", realm, password, ha1);
	char anotherHa1[33];
	belle_sip_auth_helper_compute_ha1("another-ha1-md5", realm, password, anotherHa1);

	StringFormatter jsonConfig{R"json({
        "schemaVersion": 2,
        "providers": [
            {
                "name": "Authenticate accounts",
                "triggerCondition": { "strategy": "Always" },
                "accountToUse": { "strategy": "Random" },
                "onAccountNotFound": "decline",
                "outgoingInvite": { "to": "{incoming.to}" },
                "accountPool": "RegisteredAccounts"
            }
        ],
        "accountPools": {
            "RegisteredAccounts": {
                "outboundProxy": "<sip:127.0.0.1:port;transport=tcp>",
                "registrationRequired": true,
                "maxCallsPerLine": 1,
                "loader": [
                    {
                        "uri": "sip:cleartext@domain1",
                        "secretType": "clrtxt",
                        "secret": "password"
                    },
                    {
                        "uri": "sip:ha1-md5@domain1",
                        "secretType": "md5",
                        "secret": "md5"
                    },
                    {
                        "uri": "sip:another-cleartext@domain2",
                        "secretType": "clrtxt",
                        "secret": "password",
                        "realm": "realm"
                    },
                    {
                        "uri": "sip:another-ha1-md5@domain2",
                        "secretType": "md5",
                        "secret": "anotherMd5",
                        "realm": "realm"
                    }
                ]
            }
        }
    })json",
	                           '', ''};
	TempFile providersJson{};

	// Db file backend doesn't support clrtxt if realm is not equal to domain
	char anotherClrTxtHa1[33];
	belle_sip_auth_helper_compute_ha1("another-cleartext", realm, password, anotherClrTxtHa1);

	// clang-format off
    TempFile authDb{"version:1\n\n"s +
        "cleartext@" + domain1 + " clrtxt:" + password + " ;\n"
        "ha1-md5@" + domain1 + " clrtxt:" + password + " ;\n"
        "another-cleartext@" + domain2 + " md5:" + anotherClrTxtHa1 + " ;\n"
        "another-ha1-md5@" + domain2 + " md5:" + anotherHa1 + " ;\n"
    };
	// clang-format on

	const auto serverDomains = std::string(domain1) + " " + domain2;
	Server proxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", serverDomains},
	    {"b2bua-server/application", "sip-bridge"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server::sip-bridge/providers", providersJson.getFilename()},
	    {"module::Authentication/enabled", "true"},
	    {"module::Authentication/auth-domains", serverDomains},
	    {"module::Authentication/realm", realm},
	    {"module::Authentication/db-implementation", "file"},
	    {"module::Authentication/file-path", authDb.getFilename()},
	    // Force all requests to be challenged, even un-REGISTERs
	    {"module::Authentication/nonce-expires", "0"},
	    // B2bua use writable-dir instead of var folder
	    {"b2bua-server/data-directory", bcTesterWriteDir()},
	}};
	proxy.start();
	providersJson.writeStream() << jsonConfig.format({
	    {"port", proxy.getFirstPort()},
	    {"domain1", domain1},
	    {"domain2", domain2},
	    {"password", password},
	    {"md5", ha1},
	    {"anotherMd5", anotherHa1},
	    {"realm", realm},
	});
	const auto b2buaLoop = std::make_shared<sofiasip::SuRoot>();
	const auto b2buaServer = std::make_shared<B2buaServer>(b2buaLoop, proxy.getConfigManager());
	b2buaServer->init();

	CoreAssert(proxy, b2buaLoop)
	    .iterateUpTo(
	        5,
	        [&sipProviders =
	             dynamic_cast<const b2bua::bridge::SipBridge&>(b2buaServer->getApplication()).getProviders()] {
		        for (const auto& provider : sipProviders) {
			        for (const auto& [_, account] : provider.getAccountPool()) {
				        FAIL_IF(!account->isAvailable());
			        }
		        }
		        // b2bua accounts registered
		        return ASSERTION_PASSED();
	        },
	        70ms)
	    .assert_passed();

	// Graceful async shutdown (unREGISTER accounts)
	const auto& asyncCleanup = b2buaServer->stop();
	const auto& registeredUsers =
	    dynamic_cast<const RegistrarDbInternal&>(proxy.getRegistrarDb()->getRegistrarBackend()).getAllRecords();
	BC_ASSERT_CPP_EQUAL(registeredUsers.size(), 4);
	constexpr static auto timeout = 500ms;
	// As of 2024-03-27 and SDK 5.3.33, the SDK goes on a busy loop to wait for accounts to unregister, instead of
	// waiting for iterate to be called again. That blocks the iteration of the proxy, so we spawn a separate cleanup
	// thread to be able to keep iterating the proxy on the main thread (sofia aborts if we attempt to step the main
	// loop on a non-main thread). See SDK-136.
	const auto& cleanupThread = std::async(std::launch::async, [&asyncCleanup = *asyncCleanup]() {
		BcAssert()
		    .iterateUpTo(
		        1, [&asyncCleanup]() { return LOOP_ASSERTION(asyncCleanup.finished()); }, timeout)
		    .assert_passed();
	});
	CoreAssert(proxy)
	    .iterateUpTo(
	        10, [&registeredUsers] { return LOOP_ASSERTION(registeredUsers.size() == 0); }, timeout)
	    .assert_passed();
	proxy.getRoot()->step(1ms);
	// Join proxy iterate thread. Leave ample time to let the asserter time-out first.
	cleanupThread.wait_for(10s);
	BC_ASSERT_CPP_EQUAL(registeredUsers.size(), 0);
}

/** Test the `one-connection-per-account` setting.
 * Spin up a B2BUA to manage 2 external accounts, then check the ports in the addresses they registered.
 * When disabled, both accounts should have the same port in their contact address.
 * When enabled, the ports should be different.
 *
 * Note: This test uses UDP
 */
template <bool separateConnections>
void oneConnectionPerAccount() {
	StringFormatter jsonConfig{R"json({
        "schemaVersion": 2,
        "providers": [ ],
        "accountPools": {
            "twoAccountsTwoConnections": {
                "outboundProxy": "<sip:127.0.0.1:proxyPort;transport=udp>",
                "registrationRequired": true,
                "maxCallsPerLine": 55,
                "loader": [
                    { "uri": "sip:account-1@sip.example.org" },
                    { "uri": "sip:account-2@sip.example.org" }
                ]
            }
        }
    })json",
	                           '', ''};
	const auto& configDir = TmpDir(__FUNCTION__);
	const auto& sipBridgeConfig = configDir.path() / "providers.json";
	auto proxy = Server{
	    {
	        // Force use UDP
	        {"global/transports", "sip:127.0.0.1:0;transport=udp"},
	        {"module::Registrar/enabled", "true"},
	        // The transport here does not matter, what matters is that the B2BUA binds to a random port
	        {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	        {"b2bua-server/application", "sip-bridge"},
	        // B2bua use writable-dir instead of var folder
	        {"b2bua-server/data-directory", bcTesterWriteDir()},
	        {"b2bua-server/one-connection-per-account", std::to_string(separateConnections)},
	        {"b2bua-server::sip-bridge/providers", sipBridgeConfig.string()},
	    },
	};
	proxy.start();
	std::ofstream(sipBridgeConfig) << jsonConfig.format({{"proxyPort", proxy.getFirstPort()}});
	const auto& b2buaServer = std::make_shared<flexisip::B2buaServer>(proxy.getRoot(), proxy.getConfigManager());
	b2buaServer->init();
	const auto& registeredUsers =
	    dynamic_cast<const RegistrarDbInternal&>(proxy.getRegistrarDb()->getRegistrarBackend()).getAllRecords();

	CoreAssert(proxy)
	    .iterateUpTo(
	        3, [&registeredUsers] { return LOOP_ASSERTION(registeredUsers.size() == 2); }, 40ms)
	    .assert_passed();

	BC_HARD_ASSERT_CPP_EQUAL(registeredUsers.size(), 2);
	auto portsUsed = std::unordered_set<std::string_view>();
	for (const auto& record : registeredUsers) {
		const auto& contacts = record.second->getExtendedContacts();
		BC_HARD_ASSERT_CPP_EQUAL(contacts.size(), 1);
		portsUsed.emplace(contacts.begin()->get()->mSipContact->m_url->url_port);
	}
	if constexpr (separateConnections) {
		BC_ASSERT_CPP_EQUAL(portsUsed.size(), 2);
	} else {
		BC_ASSERT_CPP_EQUAL(portsUsed.size(), 1);
	}
}

TestSuite _{
    "b2bua::sip-bridge::accounts",
    {
        CLASSY_TEST(loadAccountsFromSQL),
        CLASSY_TEST(invalidSQLLoaderThreadPoolSize),
        CLASSY_TEST(authenticatedAccounts),
        CLASSY_TEST(oneConnectionPerAccount<false>),
        CLASSY_TEST(oneConnectionPerAccount<true>),
    },
};

} // namespace
} // namespace flexisip::tester
