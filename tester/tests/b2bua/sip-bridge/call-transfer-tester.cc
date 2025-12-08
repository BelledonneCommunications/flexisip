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

#include "utils/call-listeners.hh"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"
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
using namespace std;

namespace flexisip::tester {
namespace {

constexpr auto internalDomain = "flexisip.example.org";
constexpr auto externalDomain = "jabiru.example.org";

// User: "Transferee"
const SipUri transfereeIntern{"sip:transferee@"s + internalDomain};
const SipUri transfereeExtern{"sip:transferee@"s + externalDomain};
// user: "Transferor"
const SipUri transferorIntern{"sip:transferor@"s + internalDomain};
const SipUri transferorExtern{"sip:transferor@"s + externalDomain};
// User: "TransferTarget"
const SipUri transferTIntern{"sip:transferTarget@"s + internalDomain};
const SipUri transferTExtern{"sip:transferTarget@"s + externalDomain};

/**
 * @brief Configuration to use for call transfer tests.
 *
 * Strings to replace:
 * - flexisipPort
 * - flexisipDomain
 * - jabiruPort
 * - jabiruDomain
 * - b2buaAccounts
 */
const StringFormatter callTransferSipBridgeProvidersConfiguration{
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
                    "source": "sip:{from.user}@{from.hostport}",
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
                    "source": "sip:{to.user}@{to.hostport}",
                    "by": "uri"
                },
                "onAccountNotFound": "nextProvider",
                "outgoingInvite": {
                    "to": "{account.alias}",
                    "from": "sip:{incoming.from.user}@{account.alias.hostport}{incoming.from.uriParameters}",
                    "outboundProxy": "<sip:127.0.0.1:#flexisipPort#;transport=tcp>"
                },
                "accountPool": "FlockOfJabirus"
            }
        ],
        "accountPools": {
            "FlockOfJabirus": {
                "outboundProxy": "<sip:127.0.0.1:#jabiruPort#;transport=tcp>",
                "registrationRequired": true,
                "maxCallsPerLine": 10,
                "loader": [#b2buaAccounts#]
            }
        }
    })json",
    '#',
    '#',
};

const StringFormatter b2buaSipBridgeProviderAccountConfiguration{
    R"json(
{
    "uri": "sip:#userName#@#externalDomain#",
    "alias": "sip:#userName#@#internalDomain#"
})json",
    '#',
    '#',
};

/*
 * Test successful blind call transfer.
 * This test implements the following scenario: https://datatracker.ietf.org/doc/html/rfc5589#autoid-7
 *
 * Architecture:
 * - One Proxy server (flexisip.example.org)
 * - One B2BUA server (application: SIP-Bridge)
 * - One "external" Proxy server (jabiru.example.org)
 * - Three clients {"Transferee", "Transferor", "TransferTarget"} that may be registered on flexisip or on jabiru
 */
template <const SipUri& transfereeUri, const SipUri& transferorUri, const SipUri& transferTargetUri>
void blindCallTransferSuccessful() {
	TmpDir directory{"b2bua::sip-bridge::"s + __func__};
	const auto providersConfigPath = directory.path() / "providers.json";

	Server jabiruProxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", externalDomain},
	    {"module::MediaRelay/enabled", "false"},
	}};
	jabiruProxy.start();

	B2buaAndProxyServer b2buaAndProxy{
	    {
	        {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	        {"b2bua-server/application", "sip-bridge"},
	        {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	        {"b2bua-server/enable-ice", "false"},
	        {"b2bua-server/one-connection-per-account", "true"},
	        {"b2bua-server::sip-bridge/providers", providersConfigPath.string()},
	        {"module::B2bua/enabled", "true"},
	        {"module::MediaRelay/enabled", "false"},
	        {"module::Registrar/enabled", "true"},
	        {"module::Registrar/reg-domains", internalDomain},
	    },
	    false,
	};
	b2buaAndProxy.startProxy();

	const auto clientBuilders = [&]() {
		auto map = unordered_map<string, ClientBuilder>{2};
		map.emplace(internalDomain, std::move(ClientBuilder(b2buaAndProxy.getAgent()).setVideoSend(OnOff::Off)));
		map.emplace(externalDomain, std::move(ClientBuilder(jabiruProxy.getAgent()).setVideoSend(OnOff::Off)));
		return map;
	}();

	vector<string> b2buaAccounts{};
	for (const auto& uri : {transfereeUri, transferorUri, transferTargetUri}) {
		if (uri.getHost() == internalDomain) {
			b2buaAccounts.push_back(b2buaSipBridgeProviderAccountConfiguration.format({
			    {"userName", uri.getUser()},
			    {"internalDomain", internalDomain},
			    {"externalDomain", externalDomain},
			}));
		}
	}

	ofstream{providersConfigPath} << callTransferSipBridgeProvidersConfiguration.format({
	    {"flexisipPort", b2buaAndProxy.getFirstPort()},
	    {"flexisipDomain", internalDomain},
	    {"jabiruPort", jabiruProxy.getFirstPort()},
	    {"jabiruDomain", externalDomain},
	    {"b2buaAccounts", string_utils::join(b2buaAccounts, 0, ",")},
	});
	b2buaAndProxy.startB2bua();

	// Instantiate clients.
	auto transferee = clientBuilders.at(transfereeUri.getHost()).build(transfereeUri.str());
	auto transferor = clientBuilders.at(transferorUri.getHost()).build(transferorUri.str());
	auto transferTarget = clientBuilders.at(transferTargetUri.getHost()).build(transferTargetUri.str());

	// Verify B2BUA accounts are registered on Jabiru proxy.
	CoreAssert asserter{b2buaAndProxy, jabiruProxy, transferee, transferor, transferTarget};
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

	// Create call from "Transferee" to "Transferor".
	const auto transferorAor = SipUri{transferor.getMe()->asString()}.replaceHost(transfereeUri.getHost()).str();
	const auto transfereeCallToTransferor = ClientCall::tryFrom(transferee.invite(transferorAor));
	BC_HARD_ASSERT(transfereeCallToTransferor.has_value());
	transferor.hasReceivedCallFrom(transferee, asserter).hard_assert_passed();

	// Accept call from "Transferee".
	const auto transferorCallFromTransferee = transferor.getCurrentCall();
	BC_HARD_ASSERT(transferorCallFromTransferee.has_value());
	transferorCallFromTransferee->accept();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Transfer call to "TransferTarget", initiated by "Transferor".
	const auto transferListener = make_shared<CallTransferListener>();
	transferorCallFromTransferee->addListener(transferListener);
	const auto transferTargetAor = transferTarget.getMe()->clone();
	transferTargetAor->setDomain(transferorUri.getHost());
	transferorCallFromTransferee->transferTo(transferTargetAor);

	// Verify "TransferTarget" received a call from "Transferee".
	transferTarget.hasReceivedCallFrom(transferee, asserter).hard_assert_passed();
	const auto transfereeCallToTransferTarget = transferee.getCurrentCall();
	BC_HARD_ASSERT(transfereeCallToTransferTarget.has_value());
	const auto transferTargetCallFromTransferee = transferTarget.getCurrentCall();
	BC_HARD_ASSERT(transferTargetCallFromTransferee.has_value());

	// Verify that call between "Transferee" and "Transferor" is paused while waiting for "TransferTarget" answer.
	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::Paused);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::PausedByRemote);
		        FAIL_IF(transfereeCallToTransferTarget->getState() != linphone::Call::State::OutgoingRinging);
		        FAIL_IF(transferTargetCallFromTransferee->getState() != linphone::Call::State::IncomingReceived);
		        // Verify "transferor" received NOTIFY 100 Trying.
		        FAIL_IF(transferListener->mLastState != linphone::Call::State::OutgoingProgress);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Verify content of "Referred-By" header.
	const SipUri referredByAddress{transferTargetCallFromTransferee->getReferredByAddress()->asStringUriOnly()};
	const SipUri transferorAddressOnJabiru = transferorUri.replaceHost(transfereeUri.getHost());
	BC_ASSERT(referredByAddress.compareAll(transferorAddressOnJabiru));

	// Accept call from "Transferee" to "TransferTarget".
	transferTargetCallFromTransferee->accept();

	// Verify "Transferor" received NOTIFY 200 Ok.
	transferListener->assertNotifyReceived(asserter, linphone::Call::State::Connected).assert_passed();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::Released);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::Released);
		        FAIL_IF(transfereeCallToTransferTarget->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transferTargetCallFromTransferee->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	const auto& externalProxy = (transferTargetUri.getHost() == externalDomain) ? b2buaAndProxy : jabiruProxy;
	BC_ASSERT(transferTarget.endCurrentCall(transferee, externalProxy.getAgent()));
}

/*
 * Test blind call transfer when "TransferTarget" declines the call.
 * This test implements the following scenario: https://datatracker.ietf.org/doc/html/rfc5589#autoid-10
 *
 * Architecture:
 * - One Proxy server (flexisip.example.org)
 * - One B2BUA server (application: SIP-Bridge)
 * - One "external" Proxy server (jabiru.example.org)
 * - Three clients {"Transferee", "Transferor", "TransferTarget"} that may be registered on flexisip or on jabiru
 */
template <const SipUri& transfereeUri, const SipUri& transferorUri, const SipUri& transferTargetUri>
void blindCallTransferDeclined() {
	TmpDir directory{"b2bua::sip-bridge::"s + __func__};
	const auto providersConfigPath = directory.path() / "providers.json";

	Server jabiruProxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", externalDomain},
	    {"module::MediaRelay/enabled", "false"},
	}};
	jabiruProxy.start();

	B2buaAndProxyServer b2buaAndProxy{
	    {
	        {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	        {"b2bua-server/application", "sip-bridge"},
	        {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	        {"b2bua-server/enable-ice", "false"},
	        {"b2bua-server/one-connection-per-account", "true"},
	        {"b2bua-server::sip-bridge/providers", providersConfigPath.string()},
	        {"module::B2bua/enabled", "true"},
	        {"module::MediaRelay/enabled", "false"},
	        {"module::Registrar/enabled", "true"},
	        {"module::Registrar/reg-domains", internalDomain},
	    },
	    false,
	};
	b2buaAndProxy.startProxy();

	const auto clientBuilders = [&]() {
		auto map = unordered_map<string, ClientBuilder>{2};
		map.emplace(internalDomain, std::move(ClientBuilder(b2buaAndProxy.getAgent()).setVideoSend(OnOff::Off)));
		map.emplace(externalDomain, std::move(ClientBuilder(jabiruProxy.getAgent()).setVideoSend(OnOff::Off)));
		return map;
	}();

	vector<string> b2buaAccounts{};
	for (const auto& uri : {transfereeUri, transferorUri, transferTargetUri}) {
		if (uri.getHost() == internalDomain) {
			b2buaAccounts.push_back(b2buaSipBridgeProviderAccountConfiguration.format({
			    {"userName", uri.getUser()},
			    {"internalDomain", internalDomain},
			    {"externalDomain", externalDomain},
			}));
		}
	}

	ofstream{providersConfigPath} << callTransferSipBridgeProvidersConfiguration.format({
	    {"flexisipPort", b2buaAndProxy.getFirstPort()},
	    {"flexisipDomain", internalDomain},
	    {"jabiruPort", jabiruProxy.getFirstPort()},
	    {"jabiruDomain", externalDomain},
	    {"b2buaAccounts", string_utils::join(b2buaAccounts, 0, ",")},
	});
	b2buaAndProxy.startB2bua();

	// Instantiate clients.
	auto transferee = clientBuilders.at(transfereeUri.getHost()).build(transfereeUri.str());
	auto transferor = clientBuilders.at(transferorUri.getHost()).build(transferorUri.str());
	auto transferTarget = clientBuilders.at(transferTargetUri.getHost()).build(transferTargetUri.str());

	// Verify B2BUA accounts are registered on Jabiru proxy.
	CoreAssert asserter{b2buaAndProxy, jabiruProxy, transferor, transferee, transferTarget};
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

	// Create call from "Transferee" to "Transferor".
	const auto transferorAor = SipUri{transferor.getMe()->asString()}.replaceHost(transfereeUri.getHost()).str();
	const auto transfereeCallToTransferor = ClientCall::tryFrom(transferee.invite(transferorAor));
	BC_HARD_ASSERT(transfereeCallToTransferor.has_value());
	transferor.hasReceivedCallFrom(transferee, asserter).hard_assert_passed();

	// Accept call from "Transferee".
	const auto transferorCallFromTransferee = transferor.getCurrentCall();
	BC_HARD_ASSERT(transferorCallFromTransferee.has_value());
	transferorCallFromTransferee->accept();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Transfer call to "TransferTarget", initiated by "Transferor".
	const auto transferListener = make_shared<CallTransferListener>();
	transferorCallFromTransferee->addListener(transferListener);
	const auto transferTargetAor = transferTarget.getMe()->clone();
	transferTargetAor->setDomain(transferorUri.getHost());
	transferorCallFromTransferee->transferTo(transferTargetAor);

	// Verify "TransferTarget" received a call from "Transferee".
	transferTarget.hasReceivedCallFrom(transferee, asserter).hard_assert_passed();
	const auto transfereeCallToTransferTarget = transferee.getCurrentCall();
	BC_HARD_ASSERT(transfereeCallToTransferTarget.has_value());
	const auto transferTargetCallFromTransferee = transferTarget.getCurrentCall();
	BC_HARD_ASSERT(transferTargetCallFromTransferee.has_value());

	// Verify that call between "Transferee" and "Transferor" is paused while waiting for "TransferTarget" answer.
	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::Paused);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::PausedByRemote);
		        FAIL_IF(transfereeCallToTransferTarget->getState() != linphone::Call::State::OutgoingRinging);
		        FAIL_IF(transferTargetCallFromTransferee->getState() != linphone::Call::State::IncomingReceived);
		        // Verify "Transferor" received NOTIFY 100 Trying.
		        FAIL_IF(transferListener->mLastState != linphone::Call::State::OutgoingProgress);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Verify content of "Referred-By" header.
	const SipUri referredByAddress{transferTargetCallFromTransferee->getReferredByAddress()->asStringUriOnly()};
	const SipUri transferorAddressOnJabiru = transferorUri.replaceHost(transfereeUri.getHost());
	BC_ASSERT(referredByAddress.compareAll(transferorAddressOnJabiru));

	// Decline call from "Transferee" to "TransferTarget".
	transferTargetCallFromTransferee->decline(linphone::Reason::Declined);

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::Paused);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::PausedByRemote);
		        FAIL_IF(transfereeCallToTransferTarget->getState() != linphone::Call::State::Released);
		        FAIL_IF(transferTargetCallFromTransferee->getState() != linphone::Call::State::Released);
		        // Verify "Transferor" received NOTIFY 500 Internal Server Error.
		        FAIL_IF(transferListener->mLastState != linphone::Call::State::Error);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Resume call after failed call transfer.
	transfereeCallToTransferor->resume();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::StreamsRunning);
		        // FIXME: it should always be in state StreamsRunning. See SDK-314.
		        if (transferorUri.getHost() == externalDomain and transfereeUri.getHost() == internalDomain) {
			        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::PausedByRemote);
		        } else {
			        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::StreamsRunning);
		        }
		        FAIL_IF(transfereeCallToTransferTarget->getState() != linphone::Call::State::Released);
		        FAIL_IF(transferTargetCallFromTransferee->getState() != linphone::Call::State::Released);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	const auto& externalProxyEndCall = (transfereeUri.getHost() == externalDomain) ? b2buaAndProxy : jabiruProxy;
	BC_ASSERT(transferee.endCurrentCall(transferor, externalProxyEndCall.getAgent()));
}

/*
 * Test successful attended call transfer.
 * This test almost implements the following scenario: https://datatracker.ietf.org/doc/html/rfc5589#autoid-15
 *
 * Architecture:
 * - One Proxy server (flexisip.example.org)
 * - One B2BUA server (application: SIP-Bridge)
 * - One "external" Proxy server (jabiru.example.org)
 * - Three clients {"Transferee", "Transferor", "TransferTarget"} that may be registered on flexisip or on jabiru
 */
template <const SipUri& transfereeUri, const SipUri& transferorUri, const SipUri& transferTargetUri>
void attendedCallTransferSuccessful() {
	TmpDir directory{"b2bua::sip-bridge::"s + __func__};
	const auto providersConfigPath = directory.path() / "providers.json";

	Server jabiruProxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", externalDomain},
	    {"module::MediaRelay/enabled", "false"},
	}};
	jabiruProxy.start();

	B2buaAndProxyServer b2buaAndProxy{
	    {
	        {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	        {"b2bua-server/application", "sip-bridge"},
	        {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	        {"b2bua-server/enable-ice", "false"},
	        {"b2bua-server/one-connection-per-account", "true"},
	        {"b2bua-server::sip-bridge/providers", providersConfigPath.string()},
	        {"module::B2bua/enabled", "true"},
	        {"module::MediaRelay/enabled", "false"},
	        {"module::Registrar/enabled", "true"},
	        {"module::Registrar/reg-domains", internalDomain},
	    },
	    false,
	};
	b2buaAndProxy.startProxy();

	const auto clientBuilders = [&]() {
		auto map = unordered_map<string, ClientBuilder>{2};
		map.emplace(internalDomain, std::move(ClientBuilder(b2buaAndProxy.getAgent()).setVideoSend(OnOff::Off)));
		map.emplace(externalDomain, std::move(ClientBuilder(jabiruProxy.getAgent()).setVideoSend(OnOff::Off)));
		return map;
	}();

	vector<string> b2buaAccounts{};
	for (const auto& uri : {transfereeUri, transferorUri, transferTargetUri}) {
		if (uri.getHost() == internalDomain) {
			b2buaAccounts.push_back(b2buaSipBridgeProviderAccountConfiguration.format({
			    {"userName", uri.getUser()},
			    {"internalDomain", internalDomain},
			    {"externalDomain", externalDomain},
			}));
		}
	}

	ofstream{providersConfigPath} << callTransferSipBridgeProvidersConfiguration.format({
	    {"flexisipPort", b2buaAndProxy.getFirstPort()},
	    {"flexisipDomain", internalDomain},
	    {"jabiruPort", jabiruProxy.getFirstPort()},
	    {"jabiruDomain", externalDomain},
	    {"b2buaAccounts", string_utils::join(b2buaAccounts, 0, ",")},
	});
	b2buaAndProxy.startB2bua();

	// Instantiate clients.
	auto transferee = clientBuilders.at(transfereeUri.getHost()).build(transfereeUri.str());
	auto transferor = clientBuilders.at(transferorUri.getHost()).build(transferorUri.str());
	auto transferTarget = clientBuilders.at(transferTargetUri.getHost()).build(transferTargetUri.str());

	// Verify B2BUA accounts are registered on Jabiru proxy.
	CoreAssert asserter{b2buaAndProxy, jabiruProxy, transferor, transferee, transferTarget};
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

	// Create call from "Transferee" to "Transferor".
	const auto transferorAor = transferorUri.replaceHost(transfereeUri.getHost()).str();
	const auto transfereeCallToTransferor = ClientCall::tryFrom(transferee.invite(transferorAor));
	BC_HARD_ASSERT(transfereeCallToTransferor.has_value());
	transferor.hasReceivedCallFrom(transferee, asserter).hard_assert_passed();

	// Accept call from "Transferee".
	const auto transferorCallFromTransferee = transferor.getCurrentCall();
	BC_HARD_ASSERT(transferorCallFromTransferee.has_value());
	transferorCallFromTransferee->accept();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Create call from "Transferor" to "TransferTarget".
	const auto transferTargetAor = transferTargetUri.replaceHost(transferorUri.getHost()).str();
	const auto transferorCallToTransferTarget = ClientCall::tryFrom(transferor.invite(transferTargetAor));
	transferTarget.hasReceivedCallFrom(transferor, asserter).hard_assert_passed();

	// Accept call from "Transferor".
	const auto transferTargetCallFromTransferor = transferTarget.getCurrentCall();
	BC_HARD_ASSERT(transferTargetCallFromTransferor.has_value());
	transferTargetCallFromTransferor->accept();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::Paused);
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::PausedByRemote);
		        FAIL_IF(transferorCallToTransferTarget->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transferTargetCallFromTransferor->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Transfer call between "Transferee" and "Transferor" to call between "Transferor" and "TransferTarget".
	const auto transferListener = make_shared<CallTransferListener>();
	transferorCallFromTransferee->addListener(transferListener);
	transferorCallFromTransferee->transferToAnother(*transferorCallToTransferTarget);

	// Verify "Transferor" received NOTIFY 100 Trying.
	transferListener->assertNotifyReceived(asserter, linphone::Call::State::OutgoingProgress).assert_passed();

	// Verify "TransferTarget" received a call from "Transferee" and accept it.
	auto transferTargetCallFromTransferee = optional<ClientCall>();
	asserter
	    .iterateUpTo(
	        0x20,
	        [&, &targetCore = *transferTarget.getCore(), transfereeUser = transfereeUri.getUser()]() {
		        for (auto&& call : targetCore.getCalls()) {
			        if (call->getRemoteAddress()->getUsername() == transfereeUser) {
				        transferTargetCallFromTransferee = ClientCall::tryFrom(std::move(call));
				        FAIL_IF(transferTargetCallFromTransferee == nullopt);
				        return ASSERTION_PASSED();
			        }
		        }

		        return ASSERTION_FAILED("Transfer target has not received any call from transferee");
	        },
	        2s)
	    .hard_assert_passed();

	const auto transfereeCallToTransferTarget = transferee.getCurrentCall();
	BC_HARD_ASSERT(transfereeCallToTransferTarget.has_value());
	BC_ASSERT_CPP_EQUAL(transfereeCallToTransferTarget->getRemoteAddress()->getUsername(), transferTargetUri.getUser());

	// Verify "Transferor" received NOTIFY 200 Ok.
	transferListener->assertNotifyReceived(asserter, linphone::Call::State::Connected).assert_passed();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::Released);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::Released);
		        FAIL_IF(transferorCallToTransferTarget->getState() != linphone::Call::State::Released);
		        FAIL_IF(transferTargetCallFromTransferor->getState() != linphone::Call::State::Released);
		        FAIL_IF(transfereeCallToTransferTarget->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transferTargetCallFromTransferee->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();
}

/*
 * Test attended call transfer when "TransferTarget" declines the call.
 *
 * Architecture:
 * - One Proxy server (flexisip.example.org)
 * - One B2BUA server (application: SIP-Bridge)
 * - One "external" Proxy server (jabiru.example.org)
 * - Three clients {"Transferee", "Transferor", "TransferTarget"} that may be registered on flexisip or on jabiru
 */
template <const SipUri& transfereeUri, const SipUri& transferorUri, const SipUri& transferTargetUri>
void attendedCallTransferDeclined() {
	TmpDir directory{"b2bua::sip-bridge::"s + __func__};
	const auto providersConfigPath = directory.path() / "providers.json";

	Server jabiruProxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", externalDomain},
	    {"module::MediaRelay/enabled", "false"},
	}};
	jabiruProxy.start();

	B2buaAndProxyServer b2buaAndProxy{
	    {
	        {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	        {"b2bua-server/application", "sip-bridge"},
	        {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	        {"b2bua-server/enable-ice", "false"},
	        {"b2bua-server/one-connection-per-account", "true"},
	        {"b2bua-server::sip-bridge/providers", providersConfigPath.string()},
	        {"module::B2bua/enabled", "true"},
	        {"module::MediaRelay/enabled", "false"},
	        {"module::Registrar/enabled", "true"},
	        {"module::Registrar/reg-domains", internalDomain},
	    },
	    false,
	};
	b2buaAndProxy.startProxy();

	const auto clientBuilders = [&]() {
		auto map = unordered_map<string, ClientBuilder>{2};
		map.emplace(internalDomain, std::move(ClientBuilder(b2buaAndProxy.getAgent())
		                                          .setVideoSend(OnOff::Off)
		                                          .setAutoAnswerReplacingCalls(OnOff::Off)));
		map.emplace(externalDomain, std::move(ClientBuilder(jabiruProxy.getAgent())
		                                          .setVideoSend(OnOff::Off)
		                                          .setAutoAnswerReplacingCalls(OnOff::Off)));
		return map;
	}();

	vector<string> b2buaAccounts{};
	for (const auto& uri : {transfereeUri, transferorUri, transferTargetUri}) {
		if (uri.getHost() == internalDomain) {
			b2buaAccounts.push_back(b2buaSipBridgeProviderAccountConfiguration.format({
			    {"userName", uri.getUser()},
			    {"internalDomain", internalDomain},
			    {"externalDomain", externalDomain},
			}));
		}
	}

	ofstream{providersConfigPath} << callTransferSipBridgeProvidersConfiguration.format({
	    {"flexisipPort", b2buaAndProxy.getFirstPort()},
	    {"flexisipDomain", internalDomain},
	    {"jabiruPort", jabiruProxy.getFirstPort()},
	    {"jabiruDomain", externalDomain},
	    {"b2buaAccounts", string_utils::join(b2buaAccounts, 0, ",")},
	});
	b2buaAndProxy.startB2bua();

	// Instantiate clients.
	CoreClient transferee = clientBuilders.at(transfereeUri.getHost()).build(transfereeUri.str());
	CoreClient transferor = clientBuilders.at(transferorUri.getHost()).build(transferorUri.str());
	CoreClient transferTarget = clientBuilders.at(transferTargetUri.getHost()).build(transferTargetUri.str());

	// Verify B2BUA accounts are registered on Jabiru proxy.
	CoreAssert asserter{b2buaAndProxy, jabiruProxy, transferor, transferee, transferTarget};
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

	// Create call from "Transferee" to "Transferor".
	const auto transferorAor = transferorUri.replaceHost(transfereeUri.getHost()).str();
	const auto transfereeCallToTransferor = ClientCall::tryFrom(transferee.invite(transferorAor));
	BC_HARD_ASSERT(transfereeCallToTransferor.has_value());
	transferor.hasReceivedCallFrom(transferee, asserter).hard_assert_passed();

	// Accept call from "Transferee".
	const auto transferorCallFromTransferee = transferor.getCurrentCall();
	BC_HARD_ASSERT(transferorCallFromTransferee.has_value());
	transferorCallFromTransferee->accept();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        ASSERT_CALL(transfereeCallToTransferor, Call::State::StreamsRunning, MediaDirection::SendRecv);
		        ASSERT_CALL(transferorCallFromTransferee, Call::State::StreamsRunning, MediaDirection::SendRecv);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Create call from "Transferor" to "TransferTarget".
	const auto transferTargetAor = transferTargetUri.replaceHost(transferorUri.getHost()).str();
	const auto transferorCallToTransferTarget = ClientCall::tryFrom(transferor.invite(transferTargetAor));
	BC_HARD_ASSERT(transferorCallToTransferTarget.has_value());
	transferTarget.hasReceivedCallFrom(transferor, asserter).hard_assert_passed();

	// Accept call from "Transferor".
	const auto transferTargetCallFromTransferor = transferTarget.getCurrentCall();
	BC_HARD_ASSERT(transferTargetCallFromTransferor.has_value());
	transferTargetCallFromTransferor->accept();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        ASSERT_CALL(transfereeCallToTransferor, Call::State::PausedByRemote, MediaDirection::RecvOnly);
		        ASSERT_CALL(transferorCallFromTransferee, Call::State::Paused, MediaDirection::SendOnly);
		        ASSERT_CALL(transferorCallToTransferTarget, Call::State::StreamsRunning, MediaDirection::SendRecv);
		        ASSERT_CALL(transferTargetCallFromTransferor, Call::State::StreamsRunning, MediaDirection::SendRecv);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Transfer call between "Transferee" and "Transferor" to call between "Transferor" and "TransferTarget".
	const auto transferListener = make_shared<CallTransferListener>();
	transferorCallFromTransferee->addListener(transferListener);
	transferorCallFromTransferee->transferToAnother(*transferorCallToTransferTarget);

	// Verify "Transferor" received NOTIFY 100 Trying.
	transferListener->assertNotifyReceived(asserter, Call::State::OutgoingProgress).assert_passed();

	// Verify that both "Transferor" and "Transferee" are now in the Paused state.
	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        ASSERT_CALL(transfereeCallToTransferor, Call::State::Paused, MediaDirection::Inactive);
		        ASSERT_CALL(transferorCallFromTransferee, Call::State::Paused, MediaDirection::Inactive);
		        ASSERT_CALL(transferorCallToTransferTarget, Call::State::StreamsRunning, MediaDirection::SendRecv);
		        ASSERT_CALL(transferTargetCallFromTransferor, Call::State::StreamsRunning, MediaDirection::SendRecv);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Verify "TransferTarget" received a call from "Transferee" and decline it.
	auto transferTargetCallFromTransferee = optional<ClientCall>();
	asserter
	    .iterateUpTo(
	        0x20,
	        [&, &targetCore = *transferTarget.getCore(), transfereeUser = transfereeUri.getUser()]() {
		        for (auto&& call : targetCore.getCalls()) {
			        if (call->getRemoteAddress()->getUsername() == transfereeUser) {
				        transferTargetCallFromTransferee = ClientCall::tryFrom(std::move(call));
				        FAIL_IF(transferTargetCallFromTransferee == nullopt);
				        transferTargetCallFromTransferee->decline(Reason::Declined);
				        return ASSERTION_PASSED();
			        }
		        }

		        return ASSERTION_FAILED("Transfer target has not received any call from transferee");
	        },
	        2s)
	    .hard_assert_passed();

	const auto transfereeCallToTransferTarget = transferee.getCurrentCall();
	BC_HARD_ASSERT(transfereeCallToTransferTarget.has_value());
	BC_ASSERT_CPP_EQUAL(transfereeCallToTransferTarget->getRemoteAddress()->getUsername(), transferTargetUri.getUser());

	// Verify "Transferor" received NOTIFY 500 Internal Server Error.
	transferListener->assertNotifyReceived(asserter, Call::State::Error).assert_passed();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        ASSERT_CALL(transfereeCallToTransferor, Call::State::Paused, MediaDirection::Inactive);
		        ASSERT_CALL(transferorCallFromTransferee, Call::State::Paused, MediaDirection::Inactive);
		        ASSERT_CALL(transferorCallToTransferTarget, Call::State::StreamsRunning, MediaDirection::SendRecv);
		        ASSERT_CALL(transferTargetCallFromTransferor, Call::State::StreamsRunning, MediaDirection::SendRecv);
		        ASSERT_CALL(transfereeCallToTransferTarget, Call::State::Released);
		        ASSERT_CALL(transferTargetCallFromTransferee, Call::State::Released);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();

	// "TransferTarget" terminates its call with "Transferor".
	transferTargetCallFromTransferor->terminate();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        ASSERT_CALL(transfereeCallToTransferor, Call::State::Paused, MediaDirection::Inactive);
		        ASSERT_CALL(transferorCallFromTransferee, Call::State::Paused, MediaDirection::Inactive);
		        ASSERT_CALL(transferorCallToTransferTarget, Call::State::Released);
		        ASSERT_CALL(transferTargetCallFromTransferor, Call::State::Released);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();

	// "Transferor" resumes its call with "Transferee".
	transferorCallFromTransferee->resume();
	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        ASSERT_CALL(transfereeCallToTransferor, Call::State::Paused, MediaDirection::SendOnly);
		        ASSERT_CALL(transferorCallFromTransferee, Call::State::PausedByRemote, MediaDirection::RecvOnly);

		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();

	// "Transferee" resumes its call with "Transferor"
	transfereeCallToTransferor->resume();
	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        ASSERT_CALL(transfereeCallToTransferor, Call::State::StreamsRunning, MediaDirection::SendRecv);
		        ASSERT_CALL(transferorCallFromTransferee, Call::State::StreamsRunning, MediaDirection::SendRecv);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();
}

/*
 * TE: Transferee
 * TO: Transferor
 * TT: TransferTarget
 * ---x--> INVITE with Call-Id 'x'
 *
 * TE calls TO
 * TO calls TT
 * TO sends a REFER to TE containing the call-Id that TO has with TT
 * TE calls TT with a 'Replaces' header containing the call-Id that TT has with TO
 */

/*
 * FLEXISIP    B2BUA    JABIRU
 *     TE ---1--> ---2--> TO
 *
 *     					  TO --3╷
 *                        TT <--╵
 *                                   TO sends a REFER to TE with call-ID 3
 *     TE ---4--> ---5--> TT         TT must receive a 'Replaces' header containing call-ID 3
 */
void attendedCallTransferSuccessful_noBridgeForReplacementCall() {
	attendedCallTransferSuccessful<transfereeIntern, transferorExtern, transferTExtern>();
}

/*
 * FLEXISIP    B2BUA    JABIRU
 *     TO <--2--- <--1--- TE
 *
 *     TO ---3--> ---4--> TT
 *                                   TO sends a REFER to TE with call-ID 3
 *     					  TE --5╷
 *                        TT <--╵    TT must receive a 'Replaces' header containing call-ID 4
 */
void attendedCallTransferSuccessful_unidirectionalBridgeForReplacementCall() {
	attendedCallTransferSuccessful<transfereeExtern, transferorIntern, transferTExtern>();
}

/*
 * FLEXISIP    B2BUA    JABIRU
 *     					  TE --1╷
 *                        TO <--╵
 *
 *     TT <--3--- <--2--- TO
 *                                   TO sends a REFER to TE with call-ID 2
 *     TT <--5--- <--4--- TE         TT must receive a 'Replaces' header containing call-ID 3
 */
void attendedCallTransferSuccessful_unidirectionalBridgeForReplacementCallAndFromTEtoTT() {
	attendedCallTransferSuccessful<transfereeExtern, transferorExtern, transferTIntern>();
}

void attendedCallTransferDeclined_unidirectionalBridgeForReplacementCall() {
	attendedCallTransferDeclined<transfereeExtern, transferorIntern, transferTExtern>();
}

/*
 * FLEXISIP    B2BUA    JABIRU
 *     TE ---1--> ---2-->
 *     TO <--3--- <--2---
 *
 *     TO ---4--> ---5-->
 *     TT <--6--- <--5---
 *                                   TO send a REFER to TE with call-ID 4
 *     TE ---7--> ---8-->
 *     TT <--9--- <--8---            TT must receive a 'Replaces' header containing call-ID 6
 */
void attendedCallTransferSuccessful_bidirectionalBridgeForAll() {
	attendedCallTransferSuccessful<transfereeIntern, transferorIntern, transferTIntern>();
}

void attendedCallTransferDeclined_bidirectionalBridgeForAll() {
	attendedCallTransferDeclined<transfereeIntern, transferorIntern, transferTIntern>();
}

TestSuite _{
    "b2bua::sip-bridge::callTransfer",
    {
        CLASSY_TEST((blindCallTransferSuccessful<transfereeIntern, transferorIntern, transferTIntern>)).tag("skip"),
        CLASSY_TEST((blindCallTransferSuccessful<transfereeIntern, transferorIntern, transferTExtern>)),
        CLASSY_TEST((blindCallTransferSuccessful<transfereeIntern, transferorExtern, transferTIntern>)).tag("skip"),
        CLASSY_TEST((blindCallTransferSuccessful<transfereeIntern, transferorExtern, transferTExtern>)).tag("skip"),
        CLASSY_TEST((blindCallTransferSuccessful<transfereeExtern, transferorIntern, transferTIntern>)).tag("skip"),
        CLASSY_TEST((blindCallTransferSuccessful<transfereeExtern, transferorIntern, transferTExtern>)).tag("skip"),
        CLASSY_TEST((blindCallTransferSuccessful<transfereeExtern, transferorExtern, transferTIntern>)),
        CLASSY_TEST((blindCallTransferSuccessful<transfereeExtern, transferorExtern, transferTExtern>)).tag("skip"),

        CLASSY_TEST((blindCallTransferDeclined<transfereeIntern, transferorIntern, transferTIntern>)).tag("skip"),
        CLASSY_TEST((blindCallTransferDeclined<transfereeIntern, transferorIntern, transferTExtern>)),
        CLASSY_TEST((blindCallTransferDeclined<transfereeIntern, transferorExtern, transferTIntern>)).tag("skip"),
        CLASSY_TEST((blindCallTransferDeclined<transfereeIntern, transferorExtern, transferTExtern>)).tag("skip"),
        CLASSY_TEST((blindCallTransferDeclined<transfereeExtern, transferorIntern, transferTIntern>)).tag("skip"),
        CLASSY_TEST((blindCallTransferDeclined<transfereeExtern, transferorIntern, transferTExtern>)).tag("skip"),
        CLASSY_TEST((blindCallTransferDeclined<transfereeExtern, transferorExtern, transferTIntern>)),
        CLASSY_TEST((blindCallTransferDeclined<transfereeExtern, transferorExtern, transferTExtern>)).tag("skip"),

        CLASSY_TEST(attendedCallTransferSuccessful_noBridgeForReplacementCall),
        CLASSY_TEST(attendedCallTransferSuccessful_unidirectionalBridgeForReplacementCall),
        CLASSY_TEST(attendedCallTransferSuccessful_unidirectionalBridgeForReplacementCallAndFromTEtoTT),
        CLASSY_TEST(attendedCallTransferSuccessful_bidirectionalBridgeForAll),

        CLASSY_TEST(attendedCallTransferDeclined_unidirectionalBridgeForReplacementCall),
        CLASSY_TEST(attendedCallTransferDeclined_bidirectionalBridgeForAll),
    },
};
} // namespace
} // namespace flexisip::tester
