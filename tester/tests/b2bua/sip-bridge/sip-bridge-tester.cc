/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include "soci/session.h"
#include "soci/sqlite3/soci-sqlite3.h"

#include "belle-sip/auth-helper.h"

#include "b2bua/b2bua-server.hh"
#include "registrardb-internal.hh"
#include "tester.hh"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/proxy-server.hh"
#include "utils/redis-server.hh"
#include "utils/string-formatter.hh"
#include "utils/temp-file.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

namespace flexisip::tester {
namespace {

using namespace std;
using namespace std::chrono_literals;
using namespace std::string_literals;

/*
    Test bridging to *and* from an external sip provider/domain. (Arbitrarily called "Jabiru")
    We configure 2 providers, one for each direction.

    The first, "Outbound" provider will attempt to find an external account matching the caller, and bridge the call
    using that account.
    The second, "Inbound" provider will attempt to find the external account that received the call to determine the uri
    to call in the internal domain, and send the invite to the flexisip proxy.

    We'll need a user registered to the internal Flexisip proxy. Let's call him Felix <sip:felix@flexisip.example.org>.
    Felix will need an account on the external Jabiru proxy, with a potentially different username than the one he uses
    on Flexisip: <sip:definitely-not-felix@jabiru.example.org>. That account will be provisioned in the B2BUA's account
    pool.
    Then we'll need a user registered to the Jabiru proxy, let's call him Jasper <sip:jasper@jabiru.example.org>.

    Felix will first attempt to call Jasper as if he was in the same domain as him, using the address
    <sip:jasper@flexisip.example.org>. Jasper should receive a bridged call coming from
    <sip:definitely-not-felix@jabiru.example.org>, Felix's external account managed by the B2BUA.

    Then Jasper will in turn attempt to call Felix's external account, <sip:definitely-not-felix@jabiru.example.org>,
    and Felix should receive a call form Jasper that should look like it's coming from within the same domain as him:
    <sip:jasper@flexisip.example.org>
*/
template <const std::string& flexisipTransport, const std::string& jabiruTransport>
void bidirectionalBridging() {
	StringFormatter jsonConfig{R"json({
		"schemaVersion": 2,
		"providers": [
			{
				"name": "Flexisip -> Jabiru (Outbound)",
				"triggerCondition": {
					"strategy": "Always"
				},
				"accountToUse": {
					"strategy": "FindInPool",
					"source": "{from}",
					"by": "alias"
				},
				"onAccountNotFound": "nextProvider",
				"outgoingInvite": {
					"to": "sip:{incoming.to.user}@{account.uri.hostport}{incoming.to.uriParameters}",
					"from": "{account.uri}"
				},
				"accountPool": "FlockOfJabirus"
			},
			{
				"name": "Jabiru -> Flexisip (Inbound)",
				"triggerCondition": {
					"strategy": "Always"
				},
				"accountToUse": {
					"strategy": "FindInPool",
					"source": "{to}",
					"by": "uri"
				},
				"onAccountNotFound": "nextProvider",
				"outgoingInvite": {
					"to": "{account.alias}",
					"from": "sip:{incoming.from.user}@{account.alias.hostport}{incoming.from.uriParameters}",
					"outboundProxy": "<sip:127.0.0.1:flexisipPort;transport=flexisipTransport>"
				},
				"accountPool": "FlockOfJabirus"
			}
		],
		"accountPools": {
			"FlockOfJabirus": {
				"outboundProxy": "<sip:127.0.0.1:jabiruPort;transport=jabiruTransport>",
				"registrationRequired": true,
				"maxCallsPerLine": 3125,
				"loader": [
					{
						"uri": "sip:definitely-not-felix@jabiru.example.org",
						"alias": "sip:felix@flexisip.example.org"
					}
				]
			}
		}
	})json",
	                           '', ''};
	TempFile providersJson{};
	Server flexisipProxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport="s + flexisipTransport},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "flexisip.example.org"},
	    {"b2bua-server/application", "sip-bridge"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport="s + flexisipTransport},
	    {"b2bua-server::sip-bridge/providers", providersJson.getFilename()},
	    // B2bua use writable-dir instead of var folder
	    {"b2bua-server/data-directory", bcTesterWriteDir()},
	}};
	flexisipProxy.start();
	Server jabiruProxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport="s + jabiruTransport},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "jabiru.example.org"},
	}};
	jabiruProxy.start();
	providersJson.writeStream() << jsonConfig.format({
	    {"flexisipPort", flexisipProxy.getFirstPort()},
	    {"flexisipTransport", flexisipTransport},
	    {"jabiruPort", jabiruProxy.getFirstPort()},
	    {"jabiruTransport", jabiruTransport},
	});
	const auto b2buaLoop = std::make_shared<sofiasip::SuRoot>();
	const auto& config = flexisipProxy.getConfigManager();
	const auto b2buaServer = std::make_shared<B2buaServer>(b2buaLoop, config);
	b2buaServer->init();
	config->getRoot()
	    ->get<GenericStruct>("module::Router")
	    ->get<ConfigStringList>("static-targets")
	    ->set({"sip:127.0.0.1:" + ("tcp"s == flexisipTransport
	                                   ? std::to_string(b2buaServer->getTcpPort()) + ";transport=tcp"
	                                   : std::to_string(b2buaServer->getUdpPort()) + ";transport=udp")});
	flexisipProxy.getAgent()->findModule("Router")->reload();
	const auto felix = ClientBuilder(*flexisipProxy.getAgent()).build("felix@flexisip.example.org");
	const auto jasper = ClientBuilder(*jabiruProxy.getAgent()).build("jasper@jabiru.example.org");
	CoreAssert asserter{flexisipProxy, *b2buaLoop, jabiruProxy};
	asserter
	    .iterateUpTo(
	        3,
	        [&sipProviders =
	             dynamic_cast<const b2bua::bridge::SipBridge&>(b2buaServer->getApplication()).getProviders()] {
		        for (const auto& provider : sipProviders) {
			        for (const auto& [_, account] : provider.getAccountSelectionStrategy().getAccountPool()) {
				        FAIL_IF(!account->isAvailable());
			        }
		        }
		        // b2bua accounts registered
		        return ASSERTION_PASSED();
	        },
	        40ms)
	    .assert_passed();
	asserter.registerSteppable(felix);
	asserter.registerSteppable(jasper);

	// Flexisip -> Jabiru
	felix.invite("jasper@flexisip.example.org");
	BC_HARD_ASSERT(asserter
	                   .iterateUpTo(
	                       3,
	                       [&jasper] {
		                       const auto& current_call = jasper.getCurrentCall();
		                       FAIL_IF(current_call == std::nullopt);
		                       FAIL_IF(current_call->getState() != linphone::Call::State::IncomingReceived);
		                       // invite received
		                       return ASSERTION_PASSED();
	                       },
	                       300ms)
	                   .assert_passed());
	BC_ASSERT_CPP_EQUAL(jasper.getCurrentCall()->getRemoteAddress()->asStringUriOnly(),
	                    "sip:definitely-not-felix@jabiru.example.org");

	// cleanup
	jasper.getCurrentCall()->accept();
	jasper.getCurrentCall()->terminate();
	asserter
	    .iterateUpTo(
	        10,
	        [&felix] {
		        const auto& current_call = felix.getCurrentCall();
		        FAIL_IF(current_call != std::nullopt);
		        return ASSERTION_PASSED();
	        },
	        200ms)
	    .assert_passed();

	// Jabiru -> Flexisip
	jasper.invite("definitely-not-felix@jabiru.example.org");
	BC_HARD_ASSERT(asserter
	                   .iterateUpTo(
	                       2,
	                       [&felix] {
		                       const auto& current_call = felix.getCurrentCall();
		                       FAIL_IF(current_call == std::nullopt);
		                       FAIL_IF(current_call->getState() != linphone::Call::State::IncomingReceived);
		                       // invite received
		                       return ASSERTION_PASSED();
	                       },
	                       400ms)
	                   .assert_passed());
	BC_ASSERT_CPP_EQUAL(felix.getCurrentCall()->getRemoteAddress()->asStringUriOnly(),
	                    "sip:jasper@flexisip.example.org");

	// shutdown / cleanup
	felix.getCurrentCall()->accept();
	felix.getCurrentCall()->terminate();
	asserter
	    .iterateUpTo(
	        2,
	        [&jasper] {
		        const auto& current_call = jasper.getCurrentCall();
		        FAIL_IF(current_call != std::nullopt);
		        return ASSERTION_PASSED();
	        },
	        400ms)
	    .assert_passed();
	std::ignore = b2buaServer->stop();
}

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
				"outboundProxy": "<sip:127.0.0.1:port;transport=tcp>",
				"registrationRequired": true,
				"maxCallsPerLine": 3125,
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
	CoreAssert asserter{proxy, *b2buaLoop};

	const auto& sipProviders =
	    dynamic_cast<const b2bua::bridge::SipBridge&>(b2buaServer->getApplication()).getProviders();
	BC_HARD_ASSERT_CPP_EQUAL(sipProviders.size(), 1);
	const auto& accountPool = sipProviders[0].getAccountSelectionStrategy().getAccountPool();
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
		const auto& account = accountPool.getAccountByUri("sip:account1@some.provider.example.com");
		BC_HARD_ASSERT(account != nullptr);
		BC_ASSERT_CPP_EQUAL(account->getAlias().str(), "sip:alias@sip.example.org");
	}
	{
		const auto& account = accountPool.getAccountByUri("sip:account2@some.provider.example.com");
		BC_HARD_ASSERT(account != nullptr);
		const auto& authInfo =
		    account->getLinphoneAccount()->getCore()->findAuthInfo("", "account2", "some.provider.example.com");
		BC_HARD_ASSERT(authInfo != nullptr);
		BC_ASSERT_CPP_EQUAL(authInfo->getUserid(), "test-userID");
		BC_ASSERT_CPP_EQUAL(authInfo->getPassword(), "clear text passphrase");
	}
	BC_HARD_ASSERT(accountPool.getAccountByUri("sip:account3@some.provider.example.com") != nullptr);

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

	BC_ASSERT_THROWN(b2buaServer->init(), FlexisipException);

	std::ignore = b2buaServer->stop();
}

/** Everything is setup correctly except the "From" header template contains a mistake that resolves to an invalid uri.
    Test that the B2BUA does not crash, and simply declines the call.
*/
void invalidUriTriggersDecline() {
	TempFile providersJson{R"json({
		"schemaVersion": 2,
		"providers": [
			{
				"name": "Stub Provider Name",
				"triggerCondition": { "strategy": "Always" },
				"accountToUse": { "strategy": "Random" },
				"onAccountNotFound": "decline",
				"outgoingInvite": {
					"to": "{account.alias}",
					"from": "{account.alias.user};woops=invalid-uri"
				},
				"accountPool": "ExamplePoolName"
			}
		],
		"accountPools": {
			"ExamplePoolName": {
				"outboundProxy": "<sip:stub@example.org>",
				"registrationRequired": false,
				"maxCallsPerLine": 55,
				"loader": [
					{
						"uri": "sip:b2bua-account@example.org",
						"alias": "sip:valid@example.org"
					}
				]
			}
		}
	})json"};
	Server proxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "example.org"},
	    {"b2bua-server/application", "sip-bridge"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server::sip-bridge/providers", providersJson.getFilename()},
	    // B2bua use writable-dir instead of var folder
	    {"b2bua-server/data-directory", bcTesterWriteDir()},
	}};
	proxy.start();
	const auto b2buaLoop = std::make_shared<sofiasip::SuRoot>();
	const auto& config = proxy.getConfigManager();
	const auto b2buaServer = std::make_shared<B2buaServer>(b2buaLoop, config);
	b2buaServer->init();
	config->getRoot()
	    ->get<GenericStruct>("module::Router")
	    ->get<ConfigStringList>("static-targets")
	    ->set("sip:127.0.0.1:" + std::to_string(b2buaServer->getTcpPort()) + ";transport=tcp");
	proxy.getAgent()->findModule("Router")->reload();
	const auto caller = ClientBuilder(*proxy.getAgent()).build("caller@example.org");
	CoreAssert asserter{proxy, *b2buaLoop, caller};

	caller.invite("b2bua-account@example.org");
	BC_ASSERT(asserter
	              .iterateUpTo(
	                  2,
	                  [&caller] {
		                  FAIL_IF(caller.getCurrentCall() != std::nullopt);
		                  // invite declined
		                  return ASSERTION_PASSED();
	                  },
	                  400ms)
	              .assert_passed());

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

	CoreAssert(proxy, *b2buaLoop)
	    .iterateUpTo(
	        5,
	        [&sipProviders =
	             dynamic_cast<const b2bua::bridge::SipBridge&>(b2buaServer->getApplication()).getProviders()] {
		        for (const auto& provider : sipProviders) {
			        for (const auto& [_, account] : provider.getAccountSelectionStrategy().getAccountPool()) {
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

/** Test non-(un)registration of accounts on b2bua server shutdown.
 *
 * A Flexisip proxy will play the role of an external proxy.
 * The B2BUA is configured with 2 statically defined accounts.
 * Test that when the B2BUA server shuts down, accounts are still present in the registrarDB, which mean they did not
 * (un)register.
 *
 */
void disableAccountsUnregistrationOnServerShutdown() {
	const auto domain = "example.org";
	StringFormatter jsonConfig{R"json({
		"schemaVersion": 2,
		"providers": [
			{
				"name": "Accounts",
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
				"unregisterOnServerShutdown": false,
				"maxCallsPerLine": 1,
				"loader": [
					{"uri": "sip:user-1@domain"},
					{"uri": "sip:user-2@domain"}
				]
			}
		}
	})json",
	                           '', ''};
	TempFile providersJson{};
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", domain},
	    {"b2bua-server/application", "sip-bridge"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server::sip-bridge/providers", providersJson.getFilename()},
	    // B2bua use writable-dir instead of var folder
	    {"b2bua-server/data-directory", bcTesterWriteDir()},
	}};
	proxy.start();
	providersJson.writeStream() << jsonConfig.format({{"port", proxy.getFirstPort()}, {"domain", domain}});
	const auto b2buaLoop = std::make_shared<sofiasip::SuRoot>();
	const auto b2buaServer = std::make_shared<B2buaServer>(b2buaLoop, proxy.getConfigManager());
	b2buaServer->init();

	CoreAssert(proxy, *b2buaLoop)
	    .iterateUpTo(
	        5,
	        [&sipProviders =
	             dynamic_cast<const b2bua::bridge::SipBridge&>(b2buaServer->getApplication()).getProviders()] {
		        for (const auto& provider : sipProviders) {
			        for (const auto& [_, account] : provider.getAccountSelectionStrategy().getAccountPool()) {
				        FAIL_IF(!account->isAvailable());
			        }
		        }
		        // b2bua accounts registered
		        return ASSERTION_PASSED();
	        },
	        70ms)
	    .assert_passed();

	// Graceful async shutdown.
	const auto& asyncCleanup = b2buaServer->stop();
	const auto& registeredUsers =
	    dynamic_cast<const RegistrarDbInternal&>(proxy.getRegistrarDb()->getRegistrarBackend()).getAllRecords();
	BC_ASSERT_CPP_EQUAL(registeredUsers.size(), 2);

	constexpr static auto timeout = 500ms;
	BcAssert()
	    .iterateUpTo(
	        1, [&asyncCleanup]() { return LOOP_ASSERTION(asyncCleanup->finished()); }, timeout)
	    .assert_passed();
	proxy.getRoot()->step(1ms);
	BC_ASSERT_CPP_EQUAL(registeredUsers.size(), 2);
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

const auto UDP = "udp"s;
const auto TCP = "tcp"s;
TestSuite _{
    "b2bua::bridge",
    {
        CLASSY_TEST((bidirectionalBridging<TCP, TCP>)),
        CLASSY_TEST((bidirectionalBridging<UDP, UDP>)),
        CLASSY_TEST((bidirectionalBridging<TCP, UDP>)),
        CLASSY_TEST((bidirectionalBridging<UDP, TCP>)),
        CLASSY_TEST(loadAccountsFromSQL),
        CLASSY_TEST(invalidSQLLoaderThreadPoolSize),
        CLASSY_TEST(invalidUriTriggersDecline),
        CLASSY_TEST(authenticatedAccounts),
        CLASSY_TEST(disableAccountsUnregistrationOnServerShutdown),
        CLASSY_TEST(oneConnectionPerAccount<false>),
        CLASSY_TEST(oneConnectionPerAccount<true>),
    },
};
} // namespace
} // namespace flexisip::tester