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

#include <fstream>

#include "linphone++/linphone.hh"

#include "b2bua/b2bua-core.hh"
#include "b2bua/b2bua-server.hh"
#include "helpers.hh"
#include "utils/bc-utils.hh"
#include "utils/client-builder.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/server/b2bua-and-proxy-server.hh"
#include "utils/server/proxy-server.hh"
#include "utils/string-formatter.hh"
#include "utils/temp-file.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

using namespace linphone;

namespace flexisip::tester {
namespace {

using namespace std;
using namespace std::chrono_literals;
using namespace std::string_literals;

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
	proxy.getAgent()->findModuleByRole("Router")->reload();
	const auto caller = ClientBuilder(proxy.getAgent()).build("caller@example.org");
	CoreAssert asserter{proxy, b2buaLoop, caller};

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
	BC_ASSERT_FALSE(unmatched_phone.hasReceivedCallFrom(
	    intercom, CoreAssert{server, intercom.getCore(), unmatched_phone.getCore()}));

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
	BC_ASSERT_FALSE(other_phone.hasReceivedCallFrom(
	    other_intercom, CoreAssert{server, other_intercom.getCore(), other_phone.getCore()}));

	// Line available again
	phone.endCurrentCall(intercom);
	com_to_bridge = other_intercom.call(other_phone);
	BC_HARD_ASSERT(com_to_bridge != nullptr);
	outgoing_log = other_phone.getCallLog();
	BC_ASSERT_TRUE(com_to_bridge->getCallLog()->getCallId() != outgoing_log->getCallId());
	BC_ASSERT_TRUE(outgoing_log->getRemoteAddress()->asString() == line1);
	other_intercom.endCurrentCall(other_phone);
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
	const ClientBuilder builder{proxy.getAgent()};
	const auto intercom = builder.build("sip:caller@sip.company1.com");
	// Fake a call close enough to what the SipBridge will be taking as input
	// Only incoming calls have a request address, so we need a stand-in client to receive it
	const string expectedUsername = "+39067362350";
	auto callee = builder.build("sip:" + expectedUsername + "@sip.company1.com;user=phone");
	intercom.invite(callee);
	BC_HARD_ASSERT_TRUE(callee.hasReceivedCallFrom(intercom, CoreAssert{proxy, intercom, callee}));
	const auto call = ClientCall::getLinphoneCall(*callee.getCurrentCall());
	// For this test, it's okay that this client core isn't configured exactly as that of a B2buaServer
	const auto& b2buaCore = reinterpret_pointer_cast<B2buaCore>(intercom.getCore());
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
	auto app1 = ClientBuilder(server->getAgent())
	                // Whatever follows the @ in a `user=phone` contact has no importance. Only the username (which
	                // should be a phone number) is used for bridging. It would be tempting, then, to set this to the
	                // domain of the proxy, however that's a mistake. Doing so will flag the contact as an alias and the
	                // Router module will discard it before it reaches the Forward module.
	                .setCustomContact("sip:phone@42.42.42.42:12345;user=phone")
	                .build(address);
	auto app2 =
	    ClientBuilder(server->getAgent()).setCustomContact("sip:phone@24.24.24.24:54321;user=phone").build(address);
	// 1 Client on an external domain that will answer one of the calls
	auto phone = CoreClient("sip:phone@sip.provider1.com", server->getAgent());
	auto phoneCore = phone.getCore();
	// Allow tracking multiple INVITEs received with the same Call-ID
	phoneCore->getConfig()->setBool("sip", "reject_duplicated_calls", false);

	auto call = intercom.invite(address);

	// All have received the invite...
	CoreAssert asserter{intercom, phoneCore, app1, app2, server};
	app1.hasReceivedCallFrom(intercom, asserter).assert_passed();
	app2.hasReceivedCallFrom(intercom, asserter).assert_passed();
	phone.hasReceivedCallFrom(intercom, asserter).assert_passed();
	auto phoneCalls = [&phoneCore = *phoneCore] { return phoneCore.getCalls(); };
	// ...Even twice for the phone
	BC_ASSERT_CPP_EQUAL(phoneCalls().size(), 2);

	asserter
	    .wait([&callerCall = *call] {
		    return LOOP_ASSERTION(callerCall.getState() == linphone::Call::State::OutgoingRinging);
	    })
	    .hard_assert_passed();

	// One bridged call successfully established
	auto bridgedCall = phoneCore->getCurrentCall();
	BC_HARD_ASSERT(bridgedCall != nullptr);
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

void externalAccountUsingCustomRegistrarAndOutboundProxy() {
	TmpDir directory{"b2bua::sip-bridge::"s + __func__};
	const auto providersConfigPath = directory.path() / "providers.json";

	StringFormatter jsonConfig{
	    R"json({
        "schemaVersion": 2,
        "providers": [
            {
                "name": "Internal --> External",
                "triggerCondition": {
                    "strategy": "Always"
                },
                "accountToUse": {
                    "strategy": "FindInPool",
                    "source": "{from}",
                    "by": "{alias}"
                },
                "onAccountNotFound": "nextProvider",
                "outgoingInvite": {
                    "to": "sip:{incoming.to.user}@{account.uri.hostport}{incoming.to.uriParameters}",
                    "from": "{account.uri}"
                },
                "accountPool": "ExternalAccounts"
            },
            {
                "name": "External --> Internal",
                "triggerCondition": {
                    "strategy": "Always"
                },
                "accountToUse": {
                    "strategy": "FindInPool",
                    "source": "{to}",
                    "by": "{uri}"
                },
                "onAccountNotFound": "nextProvider",
                "outgoingInvite": {
                    "to": "{account.alias}",
                    "from": "sip:{incoming.from.user}@{account.alias.hostport}{incoming.from.uriParameters}",
                    "outboundProxy": "<sip:127.0.0.4:#internalProxyPort#;transport=tcp>"
                },
                "accountPool": "ExternalAccounts"
            }
        ],
        "accountPools": {
            "ExternalAccounts": {
                "outboundProxy": "<sip:unreachable.example.org:5060>",
                "registrar": "<sip:another.unreachable.example.org:5060>",
                "registrationRequired": true,
                "maxCallsPerLine": 1,
                "loader": [
                    {
                        "uri": "#uriOnExternalDomain#",
                        "alias": "#uriOnInternalDomain#",
                        "outboundProxy": "#outboundProxyHostport#",
                        "registrar": "#registrarHostPort#",
                        "encrypted": false,
                        "protocol": "tcp"
                    }
                ]
            }
        }
    })json",
	    '#',
	    '#',
	};

	Server externalProxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.external.example.org"},
	    {"module::MediaRelay/enabled", "false"},
	}};
	externalProxy.start();

	string toUri{};
	string fromUri{};
	InjectedHooks hooks{
	    .onRequest =
	        [&toUri, &fromUri](std::unique_ptr<RequestSipEvent>&& requestEvent) {
		        const auto* sip = requestEvent->getSip();
		        if (!sip or !sip->sip_request or sip->sip_request->rq_method != sip_method_invite or !sip->sip_cseq or
		            sip->sip_cseq->cs_seq != 20)
			        return std::move(requestEvent);
		        if (!BC_ASSERT(sip->sip_from and sip->sip_to and sip->sip_request)) return std::move(requestEvent);
		        auto to = SipUri{sip->sip_to->a_url};
		        to.removeParam("gr");
		        toUri = to.str();
		        fromUri = SipUri{sip->sip_from->a_url}.str();
		        return std::move(requestEvent);
	        },
	};

	Server outboundProxyServer{
	    {
	        {"global/transports", "sip:127.0.0.2:0;transport=tcp"},
	        {"module::Registrar/enabled", "false"},
	        {"module::MediaRelay/enabled", "false"},
	    },
	    &hooks,
	};
	outboundProxyServer.start();

	B2buaAndProxyServer b2buaAndProxy{
	    {
	        {"global/transports", "sip:127.0.0.3:0;transport=tcp"},
	        {"b2bua-server/application", "sip-bridge"},
	        {"b2bua-server/transport", "sip:127.0.0.4:0;transport=tcp"},
	        {"b2bua-server/enable-ice", "false"},
	        {"b2bua-server/one-connection-per-account", "true"},
	        {"b2bua-server::sip-bridge/providers", providersConfigPath.string()},
	        {"module::B2bua/enabled", "true"},
	        {"module::MediaRelay/enabled", "false"},
	        {"module::Registrar/enabled", "true"},
	        {"module::Registrar/reg-domains", "sip.internal.example.org"},
	    },
	    false,
	};
	b2buaAndProxy.startProxy();

	// Instantiate clients.
	const string internalUserUri{"sip:internal-user@sip.internal.example.org"};
	const string internalUserUriOnExternal{"sip:internal-user@sip.external.example.org"};
	auto internalUser = ClientBuilder{b2buaAndProxy.getAgent()}.build(internalUserUri);
	const string externalUserUri{"sip:external-user@sip.external.example.org"};
	const string externalUserUriOnInternal{"sip:external-user@sip.internal.example.org"};
	auto externalUser = ClientBuilder{externalProxy.getAgent()}.build(externalUserUri);

	ofstream{providersConfigPath} << jsonConfig.format({
	    {"internalProxyPort", b2buaAndProxy.getFirstPort()},
	    {"uriOnExternalDomain", internalUserUriOnExternal},
	    {"uriOnInternalDomain", internalUserUri},
	    {"outboundProxyHostport", "127.0.0.2:"s + outboundProxyServer.getFirstPort()},
	    {"registrarHostPort", "127.0.0.1:"s + externalProxy.getFirstPort()},
	});

	b2buaAndProxy.startB2bua();

	// Verify B2BUA accounts are registered on Jabiru proxy.
	CoreAssert asserter{b2buaAndProxy, outboundProxyServer, externalProxy, internalUser, externalUser};
	asserter
	    .iterateUpTo(
	        0x20,
	        [&sipProviders = dynamic_cast<const b2bua::bridge::SipBridge&>(b2buaAndProxy.getModule()).getProviders()] {
		        for (const auto& provider : sipProviders) {
			        for (const auto& [_, account] : provider.getAccountSelectionStrategy().getAccountPool()) {
				        FAIL_IF(!account->isAvailable());
			        }
		        }
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Assert that the outbound proxy received the INVITE request.
	std::ignore = internalUser.invite(externalUser);
	asserter
	    .iterateUpTo(
	        128,
	        [&] {
		        FAIL_IF(fromUri != internalUserUriOnExternal);
		        FAIL_IF(toUri != externalUserUri);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();
}

TestSuite _{
    "b2bua::sip-bridge::bridging",
    {
        CLASSY_TEST(invalidUriTriggersDecline),
        CLASSY_TEST(oneProviderOneLine),
        CLASSY_TEST(loadBalancing),
        CLASSY_TEST(b2buaReceivesSeveralForks),
        CLASSY_TEST(externalAccountUsingCustomRegistrarAndOutboundProxy),
    },
};

} // namespace
} // namespace flexisip::tester
