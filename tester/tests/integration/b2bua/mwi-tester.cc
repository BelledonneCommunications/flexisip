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

#include "linphone++/linphone.hh"

#include "b2bua/b2bua-server.hh"
#include "utils/client-builder.hh"
#include "utils/core-assert.hh"
#include "utils/listeners/mwi-listener.hh"
#include "utils/server/proxy-server.hh"
#include "utils/string-formatter.hh"
#include "utils/temp-file.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace linphone;

namespace flexisip::tester {
namespace {

using namespace std;

/**
 * Test case: verify that MWI subscriptions are correctly bridged between Flexisip and External proxies.
 */
void mwiBridging() {
	StringFormatter jsonConfig{
	    R"json({
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
                    "outboundProxy": "<sip:127.0.0.1:#port#;transport=tcp>"
                },
                "accountPool": "FlockOfJabirus"
            }
        ],
        "accountPools": {
            "FlockOfJabirus": {
                "outboundProxy": "<sip:127.0.0.1:#port#;transport=tcp>",
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
	    '#',
	    '#',
	};

	StringFormatter flexisipRoutesConfig{
	    R"str(<sip:127.0.0.1:%port%;transport=tcp>    request.uri.domain == 'jabiru.example.org')str",
	    '%',
	    '%',
	};

	Server jabiruProxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "jabiru.example.org"},
	}};
	jabiruProxy.start();

	// Get the port that the jabiru proxy has been bound to, to use as outgoing-proxy for b2bua-server.
	StringFormatter jabiruProxyUri{R"str(sip:127.0.0.1:%port%;transport=tcp)str", '%', '%'};

	TempFile providersJson{};
	providersJson.writeStream() << jsonConfig.format({{"port", jabiruProxy.getFirstPort()}});

	TempFile flexisipRoutes{};
	Server flexisipProxy{{
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

	flexisipProxy.setConfigParameter({
	    "module::Router/static-targets",
	    "sip:127.0.0.1:" + std::to_string(b2buaServer->getTcpPort()) + ";transport=tcp",
	});
	flexisipProxy.getAgent()->findModuleByRole("Router")->reload();

	flexisipRoutes.writeStream() << flexisipRoutesConfig.format({{"port", std::to_string(b2buaServer->getTcpPort())}});
	flexisipProxy.getAgent()->findModuleByRole("Forward")->reload();

	CoreAssert asserter{jabiruProxy, flexisipProxy, *b2buaLoop};

	asserter
	    .iterateUpTo(
	        2,
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
	        40ms)
	    .assert_passed();

	auto jabiruBuilder = ClientBuilder(jabiruProxy.getAgent());
	auto flexisipBuilder = ClientBuilder(flexisipProxy.getAgent());

	// Register subscribee (will act as the MWI Server) account on jabiru proxy without MWI server address
	const auto mwiServer = jabiruBuilder.build("subscribee@jabiru.example.org");
	auto subscribeeMwiListener = std::make_shared<MwiListener>();
	mwiServer.addListener(std::static_pointer_cast<linphone::CoreListener>(subscribeeMwiListener));

	// Register subscriber account on flexisip proxy with MWI server address.
	flexisipBuilder.setMwiServerAddress(linphone::Factory::get()->createAddress("sip:subscribee@jabiru.example.org"));
	const auto subscriber = flexisipBuilder.build("subscriber@flexisip.example.org");
	auto subscriberMwiListener = std::make_shared<MwiListener>();
	subscriber.addAccountListener(std::static_pointer_cast<linphone::AccountListener>(subscriberMwiListener));

	asserter.registerSteppable(mwiServer);
	asserter.registerSteppable(subscriber);

	asserter
	    .iterateUpTo(
	        0x20,
	        [&subscribeeMwiListener] {
		        FAIL_IF(subscribeeMwiListener->getStats().nbSubscribeReceived != 1);
		        FAIL_IF(subscribeeMwiListener->getStats().nbSubscribeActive != 1);
		        return ASSERTION_PASSED();
	        },
	        400ms)
	    .assert_passed();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&subscriberMwiListener] {
		        const auto& stats = subscriberMwiListener->getStats();
		        FAIL_IF(stats.nbMwiReceived != 1);
		        FAIL_IF(stats.nbNewMWIVoice != 4);
		        FAIL_IF(stats.nbOldMWIVoice != 8);
		        FAIL_IF(stats.nbNewUrgentMWIVoice != 1);
		        FAIL_IF(stats.nbOldUrgentMWIVoice != 2);
		        return ASSERTION_PASSED();
	        },
	        400ms)
	    .assert_passed();

	// Un-register the subscriber to check that the subscription is correctly ended on
	// the subscribee (MWI server) side.
	const auto& subscriberAccount = subscriber.getAccount();
	auto newAccountParams = subscriberAccount->getParams()->clone();
	newAccountParams->enableRegister(false);
	subscriberAccount->setParams(newAccountParams);

	asserter
	    .iterateUpTo(
	        0x20,
	        [&subscribeeMwiListener] {
		        return LOOP_ASSERTION(subscribeeMwiListener->getStats().nbSubscribeTerminated == 1);
	        },
	        400ms)
	    .assert_passed();

	std::ignore = b2buaServer->stop();
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
	StringFormatter providersJsonConfig{
	    R"json({
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
                    "outboundProxy": "<sip:127.0.0.1:#flexisipport#;transport=tcp>"
                },
                "outgoingNotify": {
                    "outboundProxy": "<sip:127.0.0.1:#flexisipport#;transport=tcp>"
                },
                "accountPool": "FlockOfJabirus"
            }
        ],
        "accountPools": {
            "FlockOfJabirus": {
                "outboundProxy": "<sip:127.0.0.1:#jabiruport#;transport=tcp>",
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
	    '#',
	    '#',
	};

	StringFormatter flexisipRoutesConfig{
	    R"str(<sip:127.0.0.1:%port%;transport=tcp> request.uri.domain == 'jabiru.example.org')str",
	    '%',
	    '%',
	};

	Server jabiruProxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "jabiru.example.org"},
	}};
	jabiruProxy.start();

	// Get the port that the jabiru proxy has been bound to, to use as outgoing-proxy for b2bua-server.
	StringFormatter jabiruProxyUri{R"str(sip:127.0.0.1:%port%;transport=tcp)str", '%', '%'};

	// Register subscribee (will act as MWI server) account on jabiru proxy *without* MWI server address.
	auto jabiruBuilder = ClientBuilder(jabiruProxy.getAgent());
	const auto mwiServer = jabiruBuilder.build("subscribee@jabiru.example.org");
	auto subscribeeMwiListener = std::make_shared<MwiListener>();
	mwiServer.addListener(std::static_pointer_cast<linphone::CoreListener>(subscribeeMwiListener));

	CoreAssert asserter{jabiruProxy, mwiServer};

	// Wait for MWI server (subscribee) to be registered on the jabiru proxy.
	mwiServer.isRegistered(asserter).hard_assert_passed();

	TempFile providersJson{};
	TempFile flexisipRoutes{};
	Server flexisipProxy{{
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
	providersJson.writeStream() << providersJsonConfig.format({
	    {"flexisipport", flexisipProxy.getFirstPort()},
	    {"jabiruport", jabiruProxy.getFirstPort()},
	});

	const auto b2buaServer = std::make_shared<B2buaServer>(b2buaLoop, flexisipConfig);
	b2buaServer->init();

	flexisipProxy.setConfigParameter({
	    "module::Router/static-targets",
	    "sip:127.0.0.1:" + std::to_string(b2buaServer->getTcpPort()) + ";transport=tcp",
	});
	flexisipProxy.getAgent()->findModuleByRole("Router")->reload();

	flexisipRoutes.writeStream() << flexisipRoutesConfig.format({{"port", std::to_string(b2buaServer->getTcpPort())}});
	flexisipProxy.getAgent()->findModuleByRole("Forward")->reload();

	asserter.registerSteppable(flexisipProxy);
	asserter.registerSteppable(*b2buaLoop);

	asserter
	    .iterateUpTo(
	        2,
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
	        40ms)
	    .assert_passed();

	// Register subscriber account on flexisip proxy also without MWI server address, the subscription will be done by
	// the B2BUA.
	auto flexisipBuilder = ClientBuilder(flexisipProxy.getAgent());
	const auto subscriber = flexisipBuilder.build("subscriber@flexisip.example.org");
	auto subscriberMwiListener = std::make_shared<MwiListener>();
	subscriber.addAccountListener(std::static_pointer_cast<linphone::AccountListener>(subscriberMwiListener));
	asserter.registerSteppable(subscriber);

	asserter
	    .iterateUpTo(
	        0x20,
	        [&subscribeeMwiListener] {
		        FAIL_IF(subscribeeMwiListener->getStats().nbSubscribeReceived != 1);
		        FAIL_IF(subscribeeMwiListener->getStats().nbSubscribeActive != 1);
		        return ASSERTION_PASSED();
	        },
	        400ms)
	    .assert_passed();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&subscriberMwiListener] {
		        const MwiCoreStats& stats = subscriberMwiListener->getStats();
		        FAIL_IF(stats.nbMwiReceived != 1);
		        FAIL_IF(stats.nbNewMWIVoice != 5);
		        FAIL_IF(stats.nbOldMWIVoice != 8);
		        FAIL_IF(stats.nbNewUrgentMWIVoice != 1);
		        FAIL_IF(stats.nbOldUrgentMWIVoice != 2);
		        return ASSERTION_PASSED();
	        },
	        400ms)
	    .assert_passed();

	std::ignore = b2buaServer->stop();
}

TestSuite _{
    "integration::b2bua::sip-bridge::mwi",
    {
        CLASSY_TEST(mwiBridging),
        CLASSY_TEST(mwiB2buaSubscription),
    },
};

} // namespace
} // namespace flexisip::tester