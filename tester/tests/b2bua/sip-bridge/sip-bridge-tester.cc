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
#include <json/reader.h>

#include "soci/session.h"
#include "soci/sqlite3/soci-sqlite3.h"

#include "belle-sip/auth-helper.h"

#include <linphone++/linphone.hh>

#include "b2bua/b2bua-server.hh"
#include "registrardb-internal.hh"
#include "tester.hh"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/server/b2bua-and-proxy-server.hh"
#include "utils/server/proxy-server.hh"
#include "utils/server/redis-server.hh"
#include "utils/string-formatter.hh"
#include "utils/temp-file.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

#include "listeners/mwi-listener.hh"

namespace flexisip::tester {
namespace {

using namespace std;
using namespace std::chrono_literals;
using namespace std::string_literals;

using V1AccountDesc = flexisip::b2bua::bridge::config::v1::AccountDesc;

// The external SIP proxy that the B2BUA will bridge calls to. (For test purposes, it's actually the same proxy)
// MUST match config/flexisip_b2bua.conf:[b2bua-server]:outbound-proxy
static constexpr auto outboundProxy = "sip:127.0.0.1:5860;transport=tcp";

class ExternalClient;

class InternalClient {
	friend class ExternalClient;
	CoreClient client;

	std::shared_ptr<linphone::Address> toInternal(std::shared_ptr<linphone::Address>&& external) const;

public:
	template <typename... _Args>
	InternalClient(_Args&&... __args) : client(std::forward<_Args>(__args)...) {
	}

	std::shared_ptr<linphone::Call> invite(const ExternalClient& external) const;

	std::shared_ptr<linphone::Call> call(const ExternalClient& external);

	void endCurrentCall(const ExternalClient& other);

	auto getCore() {
		return client.getCore();
	}
};

class ExternalClient {
	friend class InternalClient;
	CoreClient client;

	std::shared_ptr<linphone::Address> getAddress() const {
		return client.getAccount()->getContactAddress()->clone();
	}

public:
	ExternalClient(CoreClient&& client) : client(std::move(client)) {
	}
	template <typename... _Args>
	ExternalClient(_Args&&... __args) : client(std::forward<_Args>(__args)...) {
	}

	[[nodiscard]] auto hasReceivedCallFrom(const InternalClient& internal) const {
		return client.hasReceivedCallFrom(internal.client);
	}

	auto getCallLog() const {
		return client.getCallLog();
	}

	auto endCurrentCall(const InternalClient& other) {
		return client.endCurrentCall(other.client);
	}

	auto getCore() {
		return client.getCore();
	}
	auto getCurrentCall() {
		return client.getCurrentCall();
	}
};

std::shared_ptr<linphone::Address> InternalClient::toInternal(std::shared_ptr<linphone::Address>&& external) const {
	external->setDomain(client.getAccount()->getParams()->getIdentityAddress()->getDomain());
	return std::move(external);
}

std::shared_ptr<linphone::Call> InternalClient::invite(const ExternalClient& external) const {
	return client.getCore()->inviteAddress(toInternal(external.getAddress()));
}

std::shared_ptr<linphone::Call> InternalClient::call(const ExternalClient& external) {
	return client.call(external.client, toInternal(external.getAddress()));
}

void InternalClient::endCurrentCall(const ExternalClient& other) {
	client.endCurrentCall(other.client);
}

struct DtmfListener : public linphone::CallListener {
	std::vector<int> received{};

	void onDtmfReceived([[maybe_unused]] const std::shared_ptr<linphone::Call>& _call, int dtmf) {
		received.push_back(dtmf);
	}
};

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

void mwiBridging() {
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
					"outboundProxy": "<sip:127.0.0.1:port;transport=tcp>"
				},
				"accountPool": "FlockOfJabirus"
			}
		],
		"accountPools": {
			"FlockOfJabirus": {
				"outboundProxy": "<sip:127.0.0.1:port;transport=tcp>",
				"registrationRequired": true,
				"maxCallsPerLine": 3125,
				"loader": [
					{
						"uri": "sip:subscriber@jabiru.example.org",
						"alias": "sip:subscriber@flexisip.example.org"
					}
				]
			}
		}
	})json",
	                           '', ''};
	StringFormatter flexisipRoutesConfig{
	    R"str(<sip:127.0.0.1:%port%;transport=tcp>	request.uri.domain == 'jabiru.example.org')str", '%', '%'};

	Server jabiruProxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "jabiru.example.org"},
	}};
	jabiruProxy.start();
	// Get the port that the jabiru proxy has been bound to, to use as outgoing-proxy for b2bua-server
	StringFormatter jabiruProxyUri{R"str(sip:127.0.0.1:%port%;transport=tcp)str", '%', '%'};

	TempFile providersJson{};
	providersJson.writeStream() << jsonConfig.format({{"port", jabiruProxy.getFirstPort()}});
	TempFile flexisipRoutes{};
	Server flexisipProxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "flexisip.example.org"},
	    {"module::Forward/routes-config-path", flexisipRoutes.getFilename()},
	    {"b2bua-server/application", "sip-bridge"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/outbound-proxy", jabiruProxyUri.format({{"port", jabiruProxy.getFirstPort()}})},
	    {"b2bua-server::sip-bridge/providers", providersJson.getFilename()},
	}};
	flexisipProxy.start();
	const auto b2buaLoop = std::make_shared<sofiasip::SuRoot>();
	const auto& flexisipConfig = flexisipProxy.getConfigManager();
	const auto b2buaServer = std::make_shared<B2buaServer>(b2buaLoop, flexisipConfig);
	b2buaServer->init();
	flexisipConfig->getRoot()
	    ->get<GenericStruct>("module::Router")
	    ->get<ConfigStringList>("static-targets")
	    ->set("sip:127.0.0.1:" + std::to_string(b2buaServer->getTcpPort()) + ";transport=tcp");
	flexisipProxy.getAgent()->findModule("Router")->reload();
	flexisipRoutes.writeStream() << flexisipRoutesConfig.format({{"port", std::to_string(b2buaServer->getTcpPort())}});
	flexisipProxy.getAgent()->findModule("Forward")->reload();

	CoreAssert asserter{jabiruProxy, flexisipProxy, *b2buaLoop};

	asserter
	    .iterateUpTo(
	        2,
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

	auto jabiruBuilder = ClientBuilder(*jabiruProxy.getAgent());
	auto flexisipBuilder = ClientBuilder(*flexisipProxy.getAgent());

	// Register subscribee account on jabiru proxy without MWI server address
	const auto subscribee = jabiruBuilder.build("subscribee@jabiru.example.org");
	auto subscribeeMwiListener = std::make_shared<MwiListener>();
	subscribee.addListener(std::static_pointer_cast<linphone::CoreListener>(subscribeeMwiListener));

	// Register subscriber account on flexisip proxy with MWI server address
	flexisipBuilder.setMwiServerAddress(linphone::Factory::get()->createAddress("sip:subscribee@jabiru.example.org"));
	const auto subscriber = flexisipBuilder.build("subscriber@flexisip.example.org");
	auto subscriberMwiListener = std::make_shared<MwiListener>();
	subscriber.addAccountListener(std::static_pointer_cast<linphone::AccountListener>(subscriberMwiListener));

	asserter.registerSteppable(subscribee);
	asserter.registerSteppable(subscriber);

	asserter
	    .waitUntil(std::chrono::milliseconds{200},
	               [&subscribeeMwiListener] {
		               FAIL_IF(subscribeeMwiListener->getStats().nbSubscribeReceived != 1 &&
		                       subscribeeMwiListener->getStats().nbSubscribeActive != 1);
		               return ASSERTION_PASSED();
	               })
	    .assert_passed();
	asserter
	    .waitUntil(std::chrono::milliseconds{200},
	               [&subscriberMwiListener] {
		               const MwiCoreStats& stats = subscriberMwiListener->getStats();
		               FAIL_IF(stats.nbMwiReceived != 1 && stats.nbNewMWIVoice != 4 && stats.nbOldMWIVoice != 8 &&
		                       stats.nbNewUrgentMWIVoice != 1 && stats.nbOldUrgentMWIVoice != 2);
		               return ASSERTION_PASSED();
	               })
	    .assert_passed();

	// Un-register the subscriber to check that the subscription is correctly ended on
	// the subscribee side.
	auto subscriberAccount = subscriber.getAccount();
	auto newAccountParams = subscriberAccount->getParams()->clone();
	newAccountParams->enableRegister(false);
	subscriberAccount->setParams(newAccountParams);

	asserter
	    .waitUntil(std::chrono::milliseconds{200},
	               [&subscribeeMwiListener] {
		               FAIL_IF(subscribeeMwiListener->getStats().nbSubscribeTerminated != 1);
		               return ASSERTION_PASSED();
	               })
	    .assert_passed();

	std::ignore = b2buaServer->stop();
}

void oneProviderOneLine() {
	using namespace flexisip::b2bua;
	auto server = make_shared<B2buaAndProxyServer>("config/flexisip_b2bua.conf");
	const auto line1 = "sip:bridge@sip.provider1.com";
	auto providers = {V1ProviderDesc{"provider1",
	                                 "sip:\\+39.*",
	                                 outboundProxy,
	                                 false,
	                                 1,
	                                 {V1AccountDesc{
	                                     line1,
	                                     "",
	                                     "",
	                                 }}}};
	server->configureExternalProviderBridge(std::move(providers));

	// Doesn't match any external provider
	auto intercom = InternalClient("sip:intercom@sip.company1.com", server->getAgent());
	auto unmatched_phone = ExternalClient("sip:+33937999152@sip.provider1.com", server->getAgent());
	auto invite = intercom.invite(unmatched_phone);
	if (!BC_ASSERT_PTR_NOT_NULL(invite)) return;
	BC_ASSERT_FALSE(unmatched_phone.hasReceivedCallFrom(intercom));

	// Happy path
	auto phone = ExternalClient("sip:+39067362350@sip.provider1.com;user=phone", server->getAgent());
	auto com_to_bridge = intercom.call(phone);
	if (!BC_ASSERT_PTR_NOT_NULL(com_to_bridge)) return;
	auto outgoing_log = phone.getCallLog();
	BC_ASSERT_TRUE(com_to_bridge->getCallLog()->getCallId() != outgoing_log->getCallId());
	BC_ASSERT_TRUE(outgoing_log->getRemoteAddress()->asString() == line1);

	// No external lines available to bridge the call
	auto other_intercom = InternalClient("sip:otherintercom@sip.company1.com", server->getAgent());
	auto other_phone = ExternalClient("sip:+39064181877@sip.provider1.com", server->getAgent());
	invite = other_intercom.invite(other_phone);
	BC_ASSERT_PTR_NOT_NULL(invite);
	BC_ASSERT_FALSE(other_phone.hasReceivedCallFrom(other_intercom));

	// Line available again
	phone.endCurrentCall(intercom);
	com_to_bridge = other_intercom.call(other_phone);
	outgoing_log = other_phone.getCallLog();
	BC_ASSERT_TRUE(com_to_bridge->getCallLog()->getCallId() != outgoing_log->getCallId());
	BC_ASSERT_TRUE(outgoing_log->getRemoteAddress()->asString() == line1);
	other_intercom.endCurrentCall(other_phone);
}

// Assert that when a call ends, the appropriate account is updated
void callRelease() {
	using namespace flexisip::b2bua;
	auto server = make_shared<B2buaAndProxyServer>("config/flexisip_b2bua.conf");
	// We start with 4 empty slots total, divided into 2 lines
	auto providers = {V1ProviderDesc{
	    "2 lines 2 slots",
	    ".*",
	    outboundProxy,
	    false,
	    2,
	    {
	        V1AccountDesc{
	            "sip:line1@sip.provider1.com",
	            "",
	            "",
	        },
	        {V1AccountDesc{
	            "sip:line2@sip.provider1.com",
	            "",
	            "",
	        }},
	    },
	}};
	auto& accman = server->configureExternalProviderBridge(std::move(providers));
	const auto reader = unique_ptr<Json::CharReader>(Json::CharReaderBuilder().newCharReader());
	auto getLinesInfo = [&accman, &reader]() {
		const auto raw = accman.handleCommand("SIP_BRIDGE", vector<string>{"INFO"});
		auto info = Json::Value();
		BC_ASSERT_TRUE(reader->parse(raw.begin().base(), raw.end().base(), &info, nullptr));
		return std::move(info["providers"][0]["accounts"]);
	};
	InternalClient callers[] = {InternalClient("sip:caller1@sip.company1.com", server->getAgent()),
	                            InternalClient("sip:caller2@sip.company1.com", server->getAgent()),
	                            InternalClient("sip:caller3@sip.company1.com", server->getAgent())};
	ExternalClient callees[] = {ExternalClient("sip:callee1@sip.provider1.com", server->getAgent()),
	                            ExternalClient("sip:callee2@sip.provider1.com", server->getAgent()),
	                            ExternalClient("sip:callee3@sip.provider1.com", server->getAgent())};
	// Let's setup a long-running background call that will take the first slot
	// X | _
	// _ | _
	callers[0].call(callees[0]);

	// Call A will take the next slot, so either
	// X | X   OR   X | _
	// _ | _        X | _
	callers[1].call(callees[1]);
	auto lines = getLinesInfo();
	const bool calls_routed_through_different_lines = lines[0]["freeSlots"] == lines[1]["freeSlots"];
	if (calls_routed_through_different_lines) {
		BC_ASSERT_TRUE(lines[0]["freeSlots"] == 1);
	}

	// Call B then fills up a third slot, resulting in
	// X | X
	// X | _
	callers[2].call(callees[2]);

	// We then pick the appropriate call to get back to
	// X | X
	// _ | _
	if (calls_routed_through_different_lines) {
		callers[2].endCurrentCall(callees[2]); // End call B
	} else {
		callers[1].endCurrentCall(callees[1]); // End call A
	}

	// If the `onCallEnd` hook didn't do its job correctly, then we're likely not to end up with what we expect
	lines = getLinesInfo();
	BC_ASSERT_TRUE(lines[0]["freeSlots"] == 1 && lines[1]["freeSlots"] == 1);
}

void loadBalancing() {
	using namespace flexisip::b2bua;
	Server proxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.provider1.com sip.company1.com"},
	}};
	proxy.start();
	const ClientBuilder builder{*proxy.getAgent()};
	const auto intercom = builder.build("sip:caller@sip.company1.com");
	// Fake a call close enough to what the SipBridge will be taking as input
	// Only incoming calls have a request address, so we need a stand-in client to receive it
	const string expectedUsername = "+39067362350";
	auto callee = builder.build("sip:" + expectedUsername + "@sip.company1.com;user=phone");
	intercom.invite(callee);
	BC_HARD_ASSERT_TRUE(callee.hasReceivedCallFrom(intercom));
	const auto call = ClientCall::getLinphoneCall(*callee.getCurrentCall());
	auto& b2buaCore = intercom.getCore();
	auto params = b2buaCore->createCallParams(call);
	vector<V1AccountDesc> lines{
	    V1AccountDesc{
	        "sip:+39068439733@sip.provider1.com",
	        "",
	        "",
	    },
	    V1AccountDesc{
	        "sip:+39063466115@sip.provider1.com",
	        "",
	        "",
	    },
	    V1AccountDesc{
	        "sip:+39064726074@sip.provider1.com",
	        "",
	        "",
	    },
	};
	const uint32_t line_count = lines.size();
	const uint32_t maxCallsPerLine = 5000;
	bridge::SipBridge sipBridge{proxy.getRoot(), b2buaCore,
	                            bridge::config::v2::fromV1({
	                                V1ProviderDesc{
	                                    "provider1",
	                                    "sip:\\+39.*",
	                                    outboundProxy,
	                                    false,
	                                    maxCallsPerLine,
	                                    std::move(lines),
	                                },
	                            }),
	                            nullptr};
	auto tally = unordered_map<const linphone::Account*, uint32_t>();

	uint32_t i = 0;
	for (; i < maxCallsPerLine; i++) {
		const auto result = sipBridge.onCallCreate(*call, *params);
		const auto* callee = get_if<shared_ptr<const linphone::Address>>(&result);
		BC_HARD_ASSERT_TRUE(callee != nullptr);
		BC_ASSERT_CPP_EQUAL((**callee).getUsername(), expectedUsername);
		tally[params->getAccount().get()]++;
	}

	// All lines have been used at least once
	BC_ASSERT_TRUE(tally.size() == line_count);
	// And used slots are normally distributed accross the lines
	const auto expected = maxCallsPerLine / line_count;
	// Within a reasonable margin of error
	const auto margin = expected * 8 / 100;
	for (const auto& pair : tally) {
		const auto slots_used = pair.second;
		bc_assert(__FILE__, __LINE__, expected - margin < slots_used && slots_used < expected + margin,
		          ("Expected " + std::to_string(expected) + " ± " + std::to_string(margin) +
		           " slots used, but found: " + std::to_string(slots_used))
		              .c_str());
	}

	// Finish saturating all the lines
	for (; i < (maxCallsPerLine * line_count); i++) {
		const auto result = sipBridge.onCallCreate(*call, *params);
		const auto* callee = get_if<shared_ptr<const linphone::Address>>(&result);
		BC_HARD_ASSERT_TRUE(callee != nullptr);
		BC_ASSERT_CPP_EQUAL((**callee).getUsername(), expectedUsername);
	}

	// Only now would the call get rejected
	BC_ASSERT_TRUE(holds_alternative<linphone::Reason>(sipBridge.onCallCreate(*call, *params)));
}

// Should display no memory leak when run in sanitizier mode
void cli() {
	using namespace flexisip::b2bua;
	const auto core = linphone::Factory::get()->createCore("", "", nullptr);
	bridge::SipBridge sipBridge{make_shared<sofiasip::SuRoot>(), core,
	                            bridge::config::v2::fromV1({
	                                {
	                                    .name = "provider1",
	                                    .pattern = "regex1",
	                                    .outboundProxy = "sip:107.20.139.176:682;transport=scp",
	                                    .registrationRequired = false,
	                                    .maxCallsPerLine = 682,
	                                    .accounts =
	                                        {
	                                            {
	                                                .uri = "sip:account1@sip.example.org",
	                                                .userid = "",
	                                                .password = "",
	                                            },
	                                        },
	                                },
	                            }),
	                            nullptr};

	// Not a command handled by the bridge
	auto output = sipBridge.handleCommand("REGISTRAR_DUMP", vector<string>{"INFO"});
	auto expected = "";
	BC_ASSERT_TRUE(output == expected);

	// Unknown subcommand
	output = sipBridge.handleCommand("SIP_BRIDGE", {});
	expected = "Valid subcommands for SIP_BRIDGE:\n"
	           "  INFO  displays information on the current state of the bridge.";
	BC_ASSERT_TRUE(output == expected);
	output = sipBridge.handleCommand("SIP_BRIDGE", vector<string>{"anything"});
	BC_ASSERT_TRUE(output == expected);

	// INFO command
	output = sipBridge.handleCommand("SIP_BRIDGE", vector<string>{"INFO"});
	// Fields are sorted alphabetically, and `:` are surrounded by whitespace (` : `) even before linebreaks
	// (Yes, that's important when writing assertions like the following)
	// (No, it can't be configured in Jsoncpp, or I didn't find where)
	expected = R"({
	"providers" : 
	[
		{
			"accounts" : 
			[
				{
					"address" : "sip:account1@sip.example.org",
					"freeSlots" : 682,
					"registerEnabled" : false,
					"status" : "OK"
				}
			],
			"name" : "provider1"
		}
	]
})";
	if (!BC_ASSERT_TRUE(output == expected)) {
		SLOGD << "SIP BRIDGE INFO: " << output;
		SLOGD << "EXPECTED INFO  : " << expected;
		BC_ASSERT_TRUE(output.size() == strlen(expected));
		for (size_t i = 0; i < output.size(); i++) {
			if (output[i] != expected[i]) {
				SLOGD << "DIFFERING AT INDEX " << i << " ('" << output[i] << "' != '" << expected[i] << "')";
				break;
			}
		}
	}
}

void parseRegisterAuthenticate() {
	using namespace flexisip::b2bua;
	auto server = make_shared<B2buaAndProxyServer>("config/flexisip_b2bua.conf", false);
	server->getConfigManager()
	    ->getRoot()
	    ->get<GenericStruct>("b2bua-server")
	    ->get<ConfigString>("application")
	    ->set("sip-bridge");
	server->start();
	auto& sipBridge = dynamic_cast<flexisip::b2bua::bridge::SipBridge&>(server->getModule());
	ClientBuilder builder{*server->getAgent()};

	// Only one account is registered and available
	InternalClient intercom = builder.build("sip:intercom@sip.company1.com");
	ExternalClient phone =
	    builder.setPassword("YKNKdW6rS9sET6G7").build("sip:+39066471266@auth.provider1.com;user=phone");
	if (!intercom.call(phone)) return;
	BC_ASSERT_TRUE(phone.getCallLog()->getRemoteAddress()->asString() == "sip:registered@auth.provider1.com");

	// Other accounts couldn't register, and can't be used to bridge calls
	const auto other_intercom = InternalClient("sip:otherintercom@sip.company1.com", server->getAgent());
	const ExternalClient other_phone =
	    builder.setPassword("RPtTmGH75GWku6bF").build("sip:+39067864963@auth.provider1.com");
	const auto invite = other_intercom.invite(other_phone);
	BC_ASSERT_PTR_NOT_NULL(invite);
	BC_ASSERT_FALSE(other_phone.hasReceivedCallFrom(other_intercom));

	const auto info = sipBridge.handleCommand("SIP_BRIDGE", vector<string>{"INFO"});
	auto parsed = nlohmann::json::parse(info);
	auto& accounts = parsed["providers"][0]["accounts"];
	const std::unordered_set<nlohmann::json> parsedAccountSet{accounts.begin(), accounts.end()};
	accounts.clear();

	BC_ASSERT_CPP_EQUAL(parsed, R"({
		"providers" : 
		[
			{
				"accounts" : [ ],
				"name" : "provider1"
			}
		]
	})"_json);

	const auto expectedAccounts = R"([
		{
			"address" : "sip:registered@auth.provider1.com",
			"freeSlots" : 0,
			"registerEnabled" : true,
			"status" : "OK"
		},
		{
			"address" : "sip:unregistered@auth.provider1.com",
			"status" : "Registration failed: Bad credentials"
		},
		{
			"address" : "sip:wrongpassword@auth.provider1.com",
			"status" : "Registration failed: Bad credentials"
		}
	])"_json;
	decltype(parsedAccountSet) expectedAccountSet{expectedAccounts.begin(), expectedAccounts.end()};
	BC_ASSERT_CPP_EQUAL(parsedAccountSet, expectedAccountSet);

	intercom.endCurrentCall(phone);
}

void b2buaReceivesSeveralForks() {
	/* Intercom  App1  App2  sip.company1.com  B2BUA  sip.provider1.com  Phone
	      |       |     |           |            |            |            |
	      |-A-----|-----|--INVITE-->|            |            |            |
	      |       |     |<-INVITE-A-|            |            |            |
	      |       |     |           |-A1-INVITE->|            |            |
	      |       |<----|--INVITE-A-|            |            |            |
	      |       |     |           |-A2-INVITE->|            |            |
	      |       |     |           |            |-B-INVITE-->|            |
	      |       |     |           |            |            |-B-INVITE-->|
	      |       |     |           |            |-C-INVITE-->|            |
	      |       |     |           |            |            |-C-INVITE-->|
	      |       |     |           |            |            |<--ACCEPT-B-|
	      |       |     |           |            |<--ACCEPT-B-|            |
	      |       |     |           |<-ACCEPT-A1-|            |            |
	      |<------|-----|--ACCEPT-A-|            |            |            |
	      |       |     |           |-A2-CANCEL->|            |            |
	      |       |     |<-CANCEL-A-|            |            |            |
	      |       |<----|--CANCEL-A-|            |            |            |
	      |       |     |           |            |-C-CANCEL-->|            |
	      |       |     |           |            |            |-C-CANCEL-->|
	      |       |     |           |            |            |            |
	*/
	using namespace flexisip::b2bua;
	auto server = make_shared<B2buaAndProxyServer>("config/flexisip_b2bua.conf", false);
	{
		auto* root = server->getConfigManager()->getRoot();
		root->get<GenericStruct>("b2bua-server")->get<ConfigString>("application")->set("sip-bridge");
		root->get<GenericStruct>("b2bua-server::sip-bridge")
		    ->get<ConfigString>("providers")
		    ->set("b2bua-receives-several-forks.sip-providers.json");
		// We don't want *every* call to go through the B2BUA...
		root->get<GenericStruct>("module::B2bua")->get<ConfigValue>("enabled")->set("false");
		// ...Only those tagged with `user=phone`, even (especially) if they are not within our managed domains
		root->get<GenericStruct>("module::Forward")
		    ->get<ConfigValue>("routes-config-path")
		    ->set(bcTesterRes("config/forward_phone_to_b2bua.rules"));
	}
	server->start();

	// 1 Caller
	auto intercom = CoreClient("sip:intercom@sip.company1.com", server->getAgent());
	// 1 Intended destination
	auto address = "sip:app@sip.company1.com";
	// 2 Bystanders used to register the same fallback contact twice.
	auto app1 = ClientBuilder(*server->getAgent())
	                // Whatever follows the @ in a `user=phone` contact has no importance. Only the username (which
	                // should be a phone number) is used for bridging. It would be tempting, then, to set this to the
	                // domain of the proxy, however that's a mistake. Doing so will flag the contact as an alias and the
	                // Router module will discard it before it reaches the Forward module.
	                .setCustomContact("sip:phone@42.42.42.42:12345;user=phone")
	                .build(address);
	auto app2 =
	    ClientBuilder(*server->getAgent()).setCustomContact("sip:phone@24.24.24.24:54321;user=phone").build(address);
	// 1 Client on an external domain that will answer one of the calls
	auto phone = CoreClient("sip:phone@sip.provider1.com", server->getAgent());
	auto phoneCore = phone.getCore();
	// Allow tracking multiple INVITEs received with the same Call-ID
	phoneCore->getConfig()->setBool("sip", "reject_duplicated_calls", false);

	auto call = intercom.invite(address);

	// All have received the invite...
	app1.hasReceivedCallFrom(intercom).assert_passed();
	app2.hasReceivedCallFrom(intercom).assert_passed();
	phone.hasReceivedCallFrom(intercom).assert_passed();
	auto phoneCalls = [&phoneCore = *phoneCore] { return phoneCore.getCalls(); };
	// ...Even twice for the phone
	BC_ASSERT_CPP_EQUAL(phoneCalls().size(), 2);

	CoreAssert asserter{intercom, phoneCore, app1, app2, server};
	asserter
	    .wait([&callerCall = *call] {
		    FAIL_IF(callerCall.getState() != linphone::Call::State::OutgoingRinging);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	// One bridged call successfully established
	auto bridgedCall = phoneCore->getCurrentCall();
	bridgedCall->accept();
	asserter
	    .wait([&callerCall = *call, &bridgedCall = *bridgedCall] {
		    FAIL_IF(callerCall.getState() != linphone::Call::State::StreamsRunning);
		    FAIL_IF(bridgedCall.getState() != linphone::Call::State::StreamsRunning);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	// All others have been cancelled
	BC_ASSERT_FALSE(app1.getCurrentCall().has_value());
	BC_ASSERT_FALSE(app2.getCurrentCall().has_value());

	asserter
	    .forceIterateThenAssert(20, 100ms,
	                            [&callerCall = *call, &bridgedCall = *bridgedCall, &phoneCalls] {
		                            FAIL_IF(callerCall.getState() != linphone::Call::State::StreamsRunning);
		                            FAIL_IF(bridgedCall.getState() != linphone::Call::State::StreamsRunning);
		                            FAIL_IF(phoneCalls().size() != 1);
		                            return ASSERTION_PASSED();
	                            })
	    .assert_passed();
}

void dtmfForwarding() {
	using namespace flexisip::b2bua;
	auto server = make_shared<B2buaAndProxyServer>("config/flexisip_b2bua.conf");
	auto providers = {V1ProviderDesc{"provider1",
	                                 "sip:\\+39.*",
	                                 outboundProxy,
	                                 false,
	                                 1,
	                                 {V1AccountDesc{
	                                     "sip:bridge@sip.provider1.com",
	                                     "",
	                                     "",
	                                 }}}};
	server->configureExternalProviderBridge(std::move(providers));
	auto intercom = InternalClient("sip:intercom@sip.company1.com", server->getAgent());
	auto phone = ExternalClient("sip:+39064728917@sip.provider1.com;user=phone", server->getAgent());
	CoreAssert asserter{intercom.getCore(), phone.getCore(), server};
	auto legAListener = make_shared<DtmfListener>();
	auto legBListener = make_shared<DtmfListener>();

	auto legA = intercom.call(phone);
	if (!BC_ASSERT_PTR_NOT_NULL(legA)) return;
	legA->addListener(legAListener);
	auto legB = ClientCall::getLinphoneCall(*phone.getCurrentCall());
	legB->addListener(legBListener);

	legB->sendDtmf('9');
	const auto& legAReceived = legAListener->received;
	asserter.wait([&legAReceived]() { return !legAReceived.empty(); }).assert_passed();
	BC_ASSERT_EQUAL(legAReceived.size(), 1, size_t, "%zx");
	BC_ASSERT_EQUAL(legAReceived.front(), '9', char, "%c");

	legA->sendDtmf('6');
	const auto& legBReceived = legBListener->received;
	asserter.wait([&legBReceived]() { return !legBReceived.empty(); }).assert_passed();
	BC_ASSERT_EQUAL(legBReceived.size(), 1, size_t, "%zx");
	BC_ASSERT_EQUAL(legBReceived.front(), '6', char, "%c");
}

void overrideSpecialOptions() {
	TempFile providersJson(R"([
		{"mediaEncryption": "none",
		 "enableAvpf": false,
		 "name": "Test Provider",
		 "pattern": "sip:unique-pattern.*",
		 "outboundProxy": "<sip:127.0.0.1:3125;transport=scp>",
		 "maxCallsPerLine": 173,
		 "accounts": [
			{"uri": "sip:bridge@sip.provider1.com"}
		 ]
		}
	])");
	b2bua::bridge::SipBridge sipBridge{make_shared<sofiasip::SuRoot>()};
	Server proxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.example.com"},
	    {"b2bua-server::sip-bridge/providers", providersJson.getFilename().c_str()},
	}};

	proxy.start();

	const ClientBuilder builder{*proxy.getAgent()};
	const auto caller = builder.build("sip:caller@sip.example.com");
	// Fake a call close enough to what the SipBridge will be taking as input
	// Only incoming calls have a request address, so we need a stand-in client to receive it
	auto callee = builder.build("sip:unique-pattern@sip.example.com");
	caller.invite(callee);
	BC_HARD_ASSERT_TRUE(callee.hasReceivedCallFrom(caller));
	const auto call = ClientCall::getLinphoneCall(*callee.getCurrentCall());
	BC_HARD_ASSERT_TRUE(call->getRequestAddress()->asStringUriOnly() != "");
	const auto core = minimalCore(*linphone::Factory::get());
	sipBridge.init(core, proxy.getAgent()->getConfigManager());
	auto params = core->createCallParams(call);
	params->setMediaEncryption(linphone::MediaEncryption::ZRTP);
	params->enableAvpf(true);

	const auto calleeAddres = sipBridge.onCallCreate(*call, *params);

	BC_ASSERT_TRUE(holds_alternative<shared_ptr<const linphone::Address>>(calleeAddres));
	// Special call params overriden
	BC_ASSERT_TRUE(params->getMediaEncryption() == linphone::MediaEncryption::None);
	BC_ASSERT_TRUE(params->avpfEnabled() == false);
}

void maxCallDuration() {
	TempFile providersJson{};
	Server proxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "sip-bridge"},
	    // Call will be interrupted after 1s
	    {"b2bua-server/max-call-duration", "1"},
	    {"b2bua-server::sip-bridge/providers", providersJson.getFilename()},
	    // Forward everything to the b2bua
	    {"module::B2bua/enabled", "true"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.provider1.com sip.company1.com"},
	    // Media Relay has problem when everyone is running on localhost
	    {"module::MediaRelay/enabled", "false"},
	    // B2bua use writable-dir instead of var folder
	    {"b2bua-server/data-directory", bcTesterWriteDir()},
	}};
	proxy.start();
	providersJson.writeStream() << R"([
		{"mediaEncryption": "none",
		 "enableAvpf": false,
		 "name": "Max call duration test provider",
		 "pattern": "sip:.*",
		 "outboundProxy": "<sip:127.0.0.1:)"
	                            << proxy.getFirstPort() << R"(;transport=tcp>",
		 "maxCallsPerLine": 682,
		 "accounts": [
			{"uri": "sip:max-call-duration@sip.provider1.com"}
		 ]
		}
	])";
	const auto b2bua = make_shared<flexisip::B2buaServer>(proxy.getRoot(), proxy.getConfigManager());
	b2bua->init();
	proxy.getConfigManager()
	    ->getRoot()
	    ->get<GenericStruct>("module::B2bua")
	    ->get<ConfigString>("b2bua-server")
	    ->set("sip:127.0.0.1:" + to_string(b2bua->getTcpPort()) + ";transport=tcp");
	proxy.getAgent()->findModule("B2bua")->reload();
	ClientBuilder builder{*proxy.getAgent()};
	InternalClient caller = builder.build("sip:caller@sip.company1.com");
	ExternalClient callee = builder.build("sip:callee@sip.provider1.com");
	CoreAssert asserter{caller.getCore(), proxy, callee.getCore()};

	caller.invite(callee);
	ASSERT_PASSED(callee.hasReceivedCallFrom(caller));
	callee.getCurrentCall()->accept();
	asserter
	    .iterateUpTo(3,
	                 [&callee]() {
		                 const auto calleeCall = callee.getCurrentCall();
		                 FAIL_IF(calleeCall == nullopt);
		                 FAIL_IF(calleeCall->getState() != linphone::Call::State::StreamsRunning);
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();

	// None of the clients terminated the call, but the B2BUA dropped it on its own
	asserter.iterateUpTo(
	            10, [&callee]() { return LOOP_ASSERTION(callee.getCurrentCall() == nullopt); }, 2100ms)
	    .assert_passed();
}

/**
 * In this scenario, it is the B2BUA that is subscribing for MWI.
 * Therefore the accounts from the account provider register on jabiru.example.org
 * and then subscribe for MWI to the MWI server, handled here by a Linphone client
 * (subscribee). Upon subscription, the MWI server sends back a NOTIFY containing
 * the message waiting indication. The B2BUA then forwards this NOTIFY out-of-dialog
 * to the alias of the account that has subscribed, via flexisip.example.org that
 * then delivers it to the client (subscriber).
 *
 * Here is the message flow:
 *
 * subscriber  flexisip.example.org  B2BUA  jabiru.example.org  MWI-server(subscribee)
 *     |               |              |            |                    |
 *     |               |              |--REGISTER->|                    |
 *     |               |              |<---200 OK--|                    |
 *     |               |              |-SUBSCRIBE->|                    |
 *     |               |              |            |-----SUBSCRIBE----->|
 *     |               |              |            |<------200 OK-------|
 *     |               |              |<---200 OK--|                    |
 *     |               |              |            |<------NOTIFY-------|
 *     |               |              |<---NOTIFY--|                    |
 *     |               |<----NOTIFY---|            |                    |
 *     |<----NOTIFY----|              |            |                    |
 *     |               |              |            |                    |
 */
void mwiB2buaSubscription() {
	StringFormatter providersJsonConfig{R"json({
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
					"outboundProxy": "<sip:127.0.0.1:flexisipport;transport=tcp>"
				},
				"outgoingNotify": {
					"outboundProxy": "<sip:127.0.0.1:flexisipport;transport=tcp>"
				},
				"accountPool": "FlockOfJabirus"
			}
		],
		"accountPools": {
			"FlockOfJabirus": {
				"outboundProxy": "<sip:127.0.0.1:jabiruport;transport=tcp>",
				"registrationRequired": true,
				"maxCallsPerLine": 3125,
				"loader": [
					{
						"uri": "sip:subscriber@jabiru.example.org",
						"alias": "sip:subscriber@flexisip.example.org"
					}
				],
				"mwiServerUri": "sip:subscribee@jabiru.example.org"
			}
		}
	})json",
	                                    '', ''};
	StringFormatter flexisipRoutesConfig{
	    R"str(<sip:127.0.0.1:%port%;transport=tcp>	request.uri.domain == 'jabiru.example.org')str", '%', '%'};

	Server jabiruProxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "jabiru.example.org"},
	}};
	jabiruProxy.start();
	// Get the port that the jabiru proxy has been bound to, to use as outgoing-proxy for b2bua-server
	StringFormatter jabiruProxyUri{R"str(sip:127.0.0.1:%port%;transport=tcp)str", '%', '%'};

	// Register subscribee account on jabiru proxy without MWI server address
	auto jabiruBuilder = ClientBuilder(*jabiruProxy.getAgent());
	const auto subscribee = jabiruBuilder.build("subscribee@jabiru.example.org");
	auto subscribeeMwiListener = std::make_shared<MwiListener>();
	subscribee.addListener(std::static_pointer_cast<linphone::CoreListener>(subscribeeMwiListener));

	CoreAssert asserter{jabiruProxy, subscribee};

	// Wait for subscribee to be registered on the jabiru proxy.
	const auto& jabiruRegisteredUsers =
	    dynamic_cast<const RegistrarDbInternal&>(jabiruProxy.getRegistrarDb()->getRegistrarBackend()).getAllRecords();
	asserter
	    .iterateUpTo(
	        10, [&jabiruRegisteredUsers] { return LOOP_ASSERTION(jabiruRegisteredUsers.size() == 1); }, 200ms)
	    .assert_passed();

	TempFile providersJson{};
	TempFile flexisipRoutes{};
	Server flexisipProxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "flexisip.example.org"},
	    {"module::Forward/routes-config-path", flexisipRoutes.getFilename()},
	    {"b2bua-server/application", "sip-bridge"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/outbound-proxy", jabiruProxyUri.format({{"port", jabiruProxy.getFirstPort()}})},
	    {"b2bua-server::sip-bridge/providers", providersJson.getFilename()},
	}};
	flexisipProxy.start();

	const auto b2buaLoop = std::make_shared<sofiasip::SuRoot>();
	const auto& flexisipConfig = flexisipProxy.getConfigManager();
	providersJson.writeStream() << providersJsonConfig.format(
	    {{"flexisipport", flexisipProxy.getFirstPort()}, {"jabiruport", jabiruProxy.getFirstPort()}});
	const auto b2buaServer = std::make_shared<B2buaServer>(b2buaLoop, flexisipConfig);
	b2buaServer->init();
	flexisipConfig->getRoot()
	    ->get<GenericStruct>("module::Router")
	    ->get<ConfigStringList>("static-targets")
	    ->set("sip:127.0.0.1:" + std::to_string(b2buaServer->getTcpPort()) + ";transport=tcp");
	flexisipProxy.getAgent()->findModule("Router")->reload();
	flexisipRoutes.writeStream() << flexisipRoutesConfig.format({{"port", std::to_string(b2buaServer->getTcpPort())}});
	flexisipProxy.getAgent()->findModule("Forward")->reload();

	asserter.registerSteppable(flexisipProxy);
	asserter.registerSteppable(*b2buaLoop);

	asserter
	    .iterateUpTo(
	        2,
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

	// Register subscriber account on flexisip proxy also without MWI server address, the subscription will be done by
	// the B2BUA.
	auto flexisipBuilder = ClientBuilder(*flexisipProxy.getAgent());
	const auto subscriber = flexisipBuilder.build("subscriber@flexisip.example.org");
	auto subscriberMwiListener = std::make_shared<MwiListener>();
	subscriber.addAccountListener(std::static_pointer_cast<linphone::AccountListener>(subscriberMwiListener));
	asserter.registerSteppable(subscriber);

	asserter
	    .waitUntil(std::chrono::milliseconds{200},
	               [&subscribeeMwiListener] {
		               FAIL_IF(subscribeeMwiListener->getStats().nbSubscribeReceived != 1);
		               FAIL_IF(subscribeeMwiListener->getStats().nbSubscribeActive != 1);
		               return ASSERTION_PASSED();
	               })
	    .assert_passed();
	asserter
	    .waitUntil(std::chrono::milliseconds{200},
	               [&subscriberMwiListener] {
		               const MwiCoreStats& stats = subscriberMwiListener->getStats();
		               FAIL_IF(stats.nbMwiReceived != 1);
		               FAIL_IF(stats.nbNewMWIVoice != 4);
		               FAIL_IF(stats.nbOldMWIVoice != 8);
		               FAIL_IF(stats.nbNewUrgentMWIVoice != 1);
		               FAIL_IF(stats.nbOldUrgentMWIVoice != 2);
		               return ASSERTION_PASSED();
	               })
	    .assert_passed();

	std::ignore = b2buaServer->stop();
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
        CLASSY_TEST(mwiBridging),
        CLASSY_TEST(oneProviderOneLine),
        CLASSY_TEST(callRelease),
        CLASSY_TEST(loadBalancing),
        CLASSY_TEST(cli),
        CLASSY_TEST(parseRegisterAuthenticate),
        CLASSY_TEST(b2buaReceivesSeveralForks),
        CLASSY_TEST(dtmfForwarding),
        CLASSY_TEST(overrideSpecialOptions),
        CLASSY_TEST(maxCallDuration),
        CLASSY_TEST(mwiB2buaSubscription),
        CLASSY_TEST(oneConnectionPerAccount<false>),
        CLASSY_TEST(oneConnectionPerAccount<true>),
    },
};

} // namespace
} // namespace flexisip::tester