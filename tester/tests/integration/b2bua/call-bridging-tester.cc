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

#include <fstream>

#include <json/reader.h>

#include "linphone++/linphone.hh"

#include "b2bua/b2bua-server.hh"
#include "flexisip/module-router.hh"
#include "utils/bc-utils.hh"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/server/b2bua-and-proxy-server.hh"
#include "utils/server/proxy-server.hh"
#include "utils/string-formatter.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

using namespace linphone;

namespace flexisip::tester {
namespace {

using namespace std;
using namespace std::chrono_literals;
using namespace std::string_literals;

const auto UDP = "udp"s;
const auto TCP = "tcp"s;

/*
 * Account that is both registered on Flexisip and external server.
 */
struct BridgingAccount {
	const std::string displayName;
	const std::string usernameOnFlexisip;
	const std::string usernameOnExternal;
};

/**
 * Account that is only registered on the external server.
 */
struct ExternalAccount {
	const std::string displayName;
	const std::string username;
};

/**
 * Settings for the test environment.
 */
struct Settings {
	const StringFormatter providersConfig;

	const std::string flexisipTransport;
	const std::string flexisipDomain;

	const std::string externalTransport;
	const std::string externalDomain;
};

void test(Settings settings,
          const BridgingAccount& user1Account,
          const BridgingAccount& user2Account,
          const ExternalAccount& user3Account) {
	auto toUriOnExternal = "unexpected"s;
	auto fromUriOnExternal = "unexpected"s;
	InjectedHooks hooks{
	    // Save SIP uris from "To" and "From" headers when Jabiru receive INVITE requests.
	    .onRequest =
	        [&toUriOnExternal, &fromUriOnExternal](std::unique_ptr<RequestSipEvent>&& requestEvent) {
		        const auto* sip = requestEvent->getSip();
		        if (!sip or !sip->sip_request or sip->sip_request->rq_method != sip_method_invite or !sip->sip_cseq or
		            sip->sip_cseq->cs_seq != 20) {
			        return std::move(requestEvent);
		        }
		        if (!BC_ASSERT(sip->sip_from and sip->sip_to and sip->sip_request)) {
			        return std::move(requestEvent);
		        }
		        toUriOnExternal = SipUri{sip->sip_to->a_url}.str();
		        fromUriOnExternal = SipUri{sip->sip_from->a_url}.str();
		        return std::move(requestEvent);
	        },
	};

	TmpDir tmpDir{__func__};
	const string providersConfigPath{tmpDir.path() / "providers.json"};

	B2buaAndProxyServer flexisipServer{
	    {
	        {"global/transports", "sip:127.0.0.1:0;transport="s + settings.flexisipTransport},
	        {"module::Registrar/enabled", "true"},
	        {"module::Registrar/reg-domains", settings.flexisipDomain},
	        {"module::B2bua/enabled", "true"},
	        {"module::MediaRelay/prevent-loops", "false"},
	        // Config for B2bua server.
	        {"b2bua-server/application", "sip-bridge"},
	        {"b2bua-server/transport", "sip:127.0.0.2:0;transport="s + settings.flexisipTransport},
	        {"b2bua-server/one-connection-per-account", "true"},
	        {"b2bua-server/data-directory", bcTesterWriteDir()},
	        {"b2bua-server::sip-bridge/providers", providersConfigPath},
	    },
	    false,
	};
	flexisipServer.startProxy();

	Server externalServer{
	    {
	        {"global/transports", "sip:127.0.0.3:0;transport="s + settings.externalTransport},
	        {"module::Registrar/enabled", "true"},
	        {"module::Registrar/reg-domains", settings.externalDomain},
	        {"module::MediaRelay/enabled", "false"},
	    },
	    &hooks,
	};
	externalServer.start();

	const string user1UriOnFlexisip{"sip:"s + user1Account.usernameOnFlexisip + "@" + settings.flexisipDomain};
	const string user1UriOnExternal{"sip:"s + user1Account.usernameOnExternal + "@" + settings.externalDomain};
	const string user2UriOnFlexisip{"sip:"s + user2Account.usernameOnFlexisip + "@" + settings.flexisipDomain};
	const string user2UriOnExternal{"sip:"s + user2Account.usernameOnExternal + "@" + settings.externalDomain};
	const string user3UriOnExternal{"sip:"s + user3Account.username + "@" + settings.externalDomain};

	ofstream providersConfigFile{providersConfigPath};
	providersConfigFile << settings.providersConfig.format({
	    {"flexisipPort", flexisipServer.getFirstPort()},
	    {"flexisipTransport", settings.flexisipTransport},
	    {"externalPort", externalServer.getFirstPort()},
	    {"externalTransport", settings.externalTransport},
	    {"user1UriOnExternal", user1UriOnExternal},
	    {"user1UriOnFlexisip", user1UriOnFlexisip},
	    {"user2UriOnExternal", user2UriOnExternal},
	    {"user2UriOnFlexisip", user2UriOnFlexisip},
	});
	providersConfigFile.close();

	flexisipServer.startB2bua();
	flexisipServer.waitForB2buaAccountsToBeAvailable(externalServer).assert_passed();

	const auto& flexisipAgent = flexisipServer.getAgent();
	const auto& externalAgent = externalServer.getAgent();

	// Get Router module of external proxy in order to access forked calls statistics.
	const auto externalRouter = dynamic_pointer_cast<ModuleRouter>(externalAgent->findModuleByRole("Router"));
	BC_HARD_ASSERT(externalRouter != nullptr);

	auto user1 = ClientBuilder(flexisipAgent).build(user1UriOnFlexisip, user1Account.displayName);
	auto user2 = ClientBuilder(flexisipAgent).build(user2UriOnFlexisip, user2Account.displayName);
	auto user3 = ClientBuilder(externalAgent).build(user3UriOnExternal);

	const auto factory = linphone::Factory::get();
	CoreAssert asserter{flexisipServer, externalServer, user1, user2, user3};

	// Test outgoing call: user1 (internal) -> user3 (external).
	{
		BC_HARD_ASSERT(user1.call(user3, factory->createAddress(user3UriOnExternal)) != nullptr);
		const auto& user3Call = user3.getCurrentCall();

		// Verify "To" and "From" headers in INVITE request received by external proxy from B2BUA.
		BC_ASSERT_CPP_EQUAL(toUriOnExternal, user3UriOnExternal);
		BC_ASSERT_CPP_EQUAL(fromUriOnExternal, user1UriOnExternal);
		BC_ASSERT_CPP_EQUAL(user3Call->getRemoteAddress()->asStringUriOnly(), user1UriOnExternal);
		BC_ASSERT_CPP_EQUAL(user3Call->getRemoteAddress()->getDisplayName(), user1Account.displayName);

		// Verify that external proxy actually created a ForkCallContext for this call.
		BC_ASSERT_CPP_EQUAL(externalRouter->mStats.mForkStats->mCountCallForks->start->read(), 1);
		BC_ASSERT_CPP_EQUAL(externalRouter->mStats.mForkStats->mCountCallForks->finish->read(), 1);

		BC_ASSERT(user3.endCurrentCall(user1));
	}

	fromUriOnExternal = toUriOnExternal = "unexpected"; // Reset.

	// Test outgoing/incoming (bounce-back on external proxy) call: user1 (internal) -> user2 (internal).
	{
		BC_HARD_ASSERT(user1.call(user2, factory->createAddress(user2UriOnFlexisip), nullptr, nullptr, {},
		                          externalAgent) != nullptr);
		const auto& user2Call = user2.getCurrentCall();

		// Verify "To" and "From" headers in INVITE request received by external proxy from B2BUA.
		BC_ASSERT_CPP_EQUAL(toUriOnExternal, user2UriOnExternal);
		BC_ASSERT_CPP_EQUAL(fromUriOnExternal, user1UriOnExternal);
		BC_ASSERT_CPP_EQUAL(user2Call->getRemoteAddress()->asStringUriOnly(), user1UriOnFlexisip);
		BC_ASSERT_CPP_EQUAL(user2Call->getRemoteAddress()->getDisplayName(), user1Account.displayName);

		// Verify that external proxy actually created a ForkCallContext for this call.
		BC_ASSERT_CPP_EQUAL(externalRouter->mStats.mForkStats->mCountCallForks->start->read(), 2);
		BC_ASSERT_CPP_EQUAL(externalRouter->mStats.mForkStats->mCountCallForks->finish->read(), 2);

		BC_ASSERT(user2.endCurrentCall(user1, externalAgent));
	}

	fromUriOnExternal = toUriOnExternal = "unexpected"; // Reset.

	// Test incoming call: user3 (external) -> user2 (internal).
	{
		BC_HARD_ASSERT(user3.call(user2, factory->createAddress(user2UriOnExternal)) != nullptr);
		const auto& user2Call = user2.getCurrentCall();

		// Verify "To" and "From" headers in INVITE request received by external proxy from B2BUA.
		BC_ASSERT_CPP_EQUAL(toUriOnExternal, user2UriOnExternal);
		BC_ASSERT_CPP_EQUAL(fromUriOnExternal, user3UriOnExternal);
		const string expectedRemoteAddress = "sip:"s + user3Account.username + "@" + settings.flexisipDomain;
		BC_ASSERT_CPP_EQUAL(user2Call->getRemoteAddress()->asStringUriOnly(), expectedRemoteAddress);
		BC_ASSERT(user2Call->getRemoteAddress()->getDisplayName().empty());

		// Verify that external proxy actually created a ForkCallContext for this call.
		BC_ASSERT_CPP_EQUAL(externalRouter->mStats.mForkStats->mCountCallForks->start->read(), 3);
		BC_ASSERT_CPP_EQUAL(externalRouter->mStats.mForkStats->mCountCallForks->finish->read(), 3);

		BC_ASSERT(user2.endCurrentCall(user3));
	}
}

const StringFormatter kProvidersConfig{
    R"json({
        "schemaVersion": 2,
        "providers": [
            {
                "name": "Flexisip -> External (Outbound)",
                "triggerCondition": {
                    "strategy": "Always"
                },
				"accountPool": "Accounts",
                "accountToUse": {
                    "strategy": "FindInPool",
                    "source": "{from}",
                    "by": "{alias}"
                },
                "onAccountNotFound": "nextProvider",
                "outgoingInvite": {
                    "to": "{incoming.to.displayName} sip:{incoming.to.user}@{account.uri.hostport}{incoming.to.uriParameters}",
                    "from": "{incoming.from.displayName} {account.uri}"
                }
            },
            {
                "name": "External -> Flexisip (Inbound)",
                "triggerCondition": {
                    "strategy": "Always"
                },
				"accountPool": "Accounts",
                "accountToUse": {
                    "strategy": "FindInPool",
                    "source": "{to}",
                    "by": "{uri}"
                },
                "onAccountNotFound": "nextProvider",
                "outgoingInvite": {
                    "to": "{incoming.to.displayName} {account.alias}",
                    "from": "{incoming.from.displayName} sip:{incoming.from.user}@{account.alias.hostport}{incoming.from.uriParameters}",
                    "outboundProxy": "<sip:127.0.0.1:#flexisipPort#;transport=#flexisipTransport#>"
                }
            }
        ],
        "accountPools": {
            "Accounts": {
                "outboundProxy": "<sip:127.0.0.3:#externalPort#;transport=#externalTransport#>",
                "registrationRequired": true,
                "maxCallsPerLine": 3125,
                "loader": [
                    {
                        "uri": "#user1UriOnExternal#",
                        "alias": "#user1UriOnFlexisip#"
                    },
                    {
                        "uri": "#user2UriOnExternal#",
                        "alias": "#user2UriOnFlexisip#"
                    }
                ]
            }
        }
    })json",
    '#',
    '#',
};

namespace shared_usernames {

BridgingAccount kUser1{R"("User1")"s, "user1", "user1"};
BridgingAccount kUser2{R"("User2")"s, "user2", "user2"};
ExternalAccount kUser3{R"("User3")"s, "user3"};

void bridgingTCP() {
	Settings settings{kProvidersConfig, TCP, "flexisip.example.org", TCP, "external.example.org"};
	test(settings, kUser1, kUser2, kUser3);
}

void bridgingUDP() {
	Settings settings{kProvidersConfig, UDP, "flexisip.example.org", UDP, "external.example.org"};
	test(settings, kUser1, kUser2, kUser3);
}

void bridgingTCPFlexisipUDPExternal() {
	Settings settings{kProvidersConfig, TCP, "flexisip.example.org", UDP, "external.example.org"};
	test(settings, kUser1, kUser2, kUser3);
}

void bridgingUDPFlexisipTCPExternal() {
	Settings settings{kProvidersConfig, UDP, "flexisip.example.org", TCP, "external.example.org"};
	test(settings, kUser1, kUser2, kUser3);
}

} // namespace shared_usernames

BridgingAccount kUser1{R"("User1")"s, "user1", "1resu"};
BridgingAccount kUser2{R"("User2")"s, "user2", "2resu"};
ExternalAccount kUser3{R"("User3")"s, "user3"};

void bridgingTCP() {
	Settings settings{kProvidersConfig, TCP, "flexisip.example.org", TCP, "external.example.org"};
	test(settings, kUser1, kUser2, kUser3);
}

void bridgingUDP() {
	Settings settings{kProvidersConfig, UDP, "flexisip.example.org", UDP, "external.example.org"};
	test(settings, kUser1, kUser2, kUser3);
}

void bridgingTCPFlexisipUDPExternal() {
	Settings settings{kProvidersConfig, TCP, "flexisip.example.org", UDP, "external.example.org"};
	test(settings, kUser1, kUser2, kUser3);
}

void bridgingUDPFlexisipTCPExternal() {
	Settings settings{kProvidersConfig, UDP, "flexisip.example.org", TCP, "external.example.org"};
	test(settings, kUser1, kUser2, kUser3);
}

TestSuite _{
    "integration::b2bua::sip-bridge::call-bridging",
    {
        CLASSY_TEST(shared_usernames::bridgingTCP),
        CLASSY_TEST(shared_usernames::bridgingUDP),
        CLASSY_TEST(shared_usernames::bridgingTCPFlexisipUDPExternal),
        CLASSY_TEST(shared_usernames::bridgingUDPFlexisipTCPExternal),

        CLASSY_TEST(bridgingTCP).tag("Skip"),
        CLASSY_TEST(bridgingUDP).tag("Skip"),
        CLASSY_TEST(bridgingTCPFlexisipUDPExternal).tag("Skip"),
        CLASSY_TEST(bridgingUDPFlexisipTCPExternal).tag("Skip"),
    },
};

} // namespace
} // namespace flexisip::tester