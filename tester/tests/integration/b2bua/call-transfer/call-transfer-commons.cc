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

#include "call-transfer-commons.hh"

#include <fstream>
#include <utility>

#include "utils/call-listeners.hh"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/server/b2bua-and-proxy-server.hh"
#include "utils/server/proxy-server.hh"
#include "utils/string-formatter.hh"
#include "utils/test-patterns/test.hh"
#include "utils/tmp-dir.hh"

using namespace linphone;
using namespace std;

namespace flexisip::tester {

namespace blind {

/*
 * Test successful blind call transfer.
 * This test implements the following scenario: https://datatracker.ietf.org/doc/html/rfc5589#autoid-7
 *
 * Architecture:
 * - One Proxy server (flexisip.example.org)
 * - One B2BUA server (application: SIP-Bridge)
 * - One external Proxy server (external.example.org)
 * - Three clients {"Transferee", "Transferor", "TransferTarget"} that may be registered on flexisip or on external
 */
void successful(const Settings& settings,
                const CallTransferAccount& transfereeAccount,
                const CallTransferAccount& transferorAccount,
                const CallTransferAccount& transferTargetAccount) {
	TmpDir directory{"b2bua::sip-bridge::"s + __func__};
	const auto providersConfigPath = directory.path() / "providers.json";

	Server externalServer{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", kExternalDomain},
	    {"module::MediaRelay/enabled", "false"},
	}};
	externalServer.start();

	B2buaAndProxyServer flexisipServer{
	    {
	        {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	        {"module::Registrar/enabled", "true"},
	        {"module::Registrar/reg-domains", kFlexisipDomain},
	        {"module::MediaRelay/enabled", "false"},
	        {"module::B2bua/enabled", "true"},
	        {"module::B2bua/filter", settings.b2buaFilter},
	        // Config for B2bua server.
	        {"b2bua-server/application", "sip-bridge"},
	        {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	        {"b2bua-server/enable-ice", "false"},
	        {"b2bua-server/one-connection-per-account", "true"},
	        {"b2bua-server::sip-bridge/providers", providersConfigPath.string()},
	    },
	    false,
	};
	flexisipServer.startProxy();

	const auto clientBuilders = [&]() {
		auto map = unordered_map<string, ClientBuilder>{2};
		map.emplace(kFlexisipDomain, std::move(ClientBuilder(flexisipServer.getAgent()).setVideoSend(OnOff::Off)));
		map.emplace(kExternalDomain, std::move(ClientBuilder(externalServer.getAgent()).setVideoSend(OnOff::Off)));
		return map;
	}();

	vector<string> b2buaAccounts{};
	for (const auto& account : {transfereeAccount, transferorAccount, transferTargetAccount}) {
		if (account.mDomain == Domain::Flexisip) {
			b2buaAccounts.push_back(kB2buaProviderAccountConfiguration.format({
			    {"userNameOnFlexisip", account.mUsernameOnFlexisip},
			    {"userNameOnExternal", account.mUsernameOnExternal},
			    {"internalDomain", kFlexisipDomain},
			    {"externalDomain", kExternalDomain},
			}));
		}
	}

	ofstream{providersConfigPath} << settings.providersConfig.format({
	    {"flexisipPort", flexisipServer.getFirstPort()},
	    {"flexisipDomain", kFlexisipDomain},
	    {"externalPort", externalServer.getFirstPort()},
	    {"externalDomain", kExternalDomain},
	    {"b2buaAccounts", string_utils::join(b2buaAccounts, 0, ",")},
	});
	flexisipServer.startB2bua();

	// Instantiate clients.
	auto transferee = clientBuilders.at(transfereeAccount.domain()).build(transfereeAccount.uri().str());
	auto transferor = clientBuilders.at(transferorAccount.domain()).build(transferorAccount.uri().str());
	auto transferTarget = clientBuilders.at(transferTargetAccount.domain()).build(transferTargetAccount.uri().str());

	// Verify B2BUA accounts are registered on the external proxy.
	CoreAssert asserter{flexisipServer, externalServer, transferee, transferor, transferTarget};
	flexisipServer.waitForB2buaAccountsToBeAvailable(externalServer).hard_assert_passed();

	// Create call from "Transferee" to "Transferor".
	const auto transferorAor = transferorAccount.uriOn(transfereeAccount.mDomain).str();
	const auto transfereeCallToTransferor = ClientCall::tryFrom(transferee.invite(transferorAor));
	BC_HARD_ASSERT(transfereeCallToTransferor.has_value());
	transferor.hasReceivedCallFrom(transferee, asserter).hard_assert_passed();

	// Accept call from "Transferee".
	const auto transferorCallFromTransferee = transferor.getCurrentCall();
	BC_HARD_ASSERT(transferorCallFromTransferee.has_value());
	transferorCallFromTransferee->accept();

	asserter
	    .wait([&]() {
		    FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::StreamsRunning);
		    FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::StreamsRunning);
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	// Transfer call to "TransferTarget", initiated by "Transferor".
	const auto transferListener = make_shared<CallTransferListener>();
	transferorCallFromTransferee->addListener(transferListener);
	const auto transferTargetAor = transferTarget.getMe()->clone();
	transferTargetAor->setUsername(transferTargetAccount.uriOn(transferorAccount.mDomain).getUser());
	transferTargetAor->setDomain(transferorAccount.domain());
	transferorCallFromTransferee->transferTo(transferTargetAor);

	// Verify "TransferTarget" received a call from "Transferee".
	transferTarget.hasReceivedCallFrom(transferee, asserter).hard_assert_passed();
	const auto transfereeCallToTransferTarget = transferee.getCurrentCall();
	BC_HARD_ASSERT(transfereeCallToTransferTarget.has_value());
	const auto transferTargetCallFromTransferee = transferTarget.getCurrentCall();
	BC_HARD_ASSERT(transferTargetCallFromTransferee.has_value());

	// Verify that call between "Transferee" and "Transferor" is paused while waiting for "TransferTarget" answer.
	asserter
	    .wait([&]() {
		    FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::Paused);
		    FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::PausedByRemote);
		    FAIL_IF(transfereeCallToTransferTarget->getState() != linphone::Call::State::OutgoingRinging);
		    FAIL_IF(transferTargetCallFromTransferee->getState() != linphone::Call::State::IncomingReceived);
		    // Verify "transferor" received NOTIFY 100 Trying.
		    FAIL_IF(transferListener->mLastState != linphone::Call::State::OutgoingProgress);
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	// Verify content of "Referred-By" header.
	const SipUri referredByAddress{transferTargetCallFromTransferee->getReferredByAddress()->asStringUriOnly()};
	BC_ASSERT(referredByAddress.compareAll(transferorAccount.uriOn(transfereeAccount.mDomain)));

	// Accept call from "Transferee" to "TransferTarget".
	transferTargetCallFromTransferee->accept();

	// Verify "Transferor" received NOTIFY 200 Ok.
	transferListener->assertNotifyReceived(asserter, linphone::Call::State::Connected).assert_passed();

	asserter
	    .wait([&]() {
		    FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::Released);
		    FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::Released);
		    FAIL_IF(transfereeCallToTransferTarget->getState() != linphone::Call::State::StreamsRunning);
		    FAIL_IF(transferTargetCallFromTransferee->getState() != linphone::Call::State::StreamsRunning);
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	const auto& transferTargetProxy =
	    (transferTargetAccount.mDomain == Domain::External) ? flexisipServer : externalServer;
	BC_ASSERT(transferTarget.endCurrentCall(transferee, transferTargetProxy.getAgent()));
}

/*
 * Test blind call transfer when "TransferTarget" declines the call.
 * This test implements the following scenario: https://datatracker.ietf.org/doc/html/rfc5589#autoid-10
 *
 * Architecture:
 * - One Proxy server (flexisip.example.org)
 * - One B2BUA server (application: SIP-Bridge)
 * - One external Proxy server (external.example.org)
 * - Three clients {"Transferee", "Transferor", "TransferTarget"} that may be registered on flexisip or on external
 */
void declined(const Settings& settings,
              const CallTransferAccount& transfereeAccount,
              const CallTransferAccount& transferorAccount,
              const CallTransferAccount& transferTargetAccount) {
	TmpDir directory{"b2bua::sip-bridge::"s + __func__};
	const auto providersConfigPath = directory.path() / "providers.json";

	Server externalServer{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", kExternalDomain},
	    {"module::MediaRelay/enabled", "false"},
	}};
	externalServer.start();

	B2buaAndProxyServer flexisipServer{
	    {
	        {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	        {"module::Registrar/enabled", "true"},
	        {"module::Registrar/reg-domains", kFlexisipDomain},
	        {"module::MediaRelay/enabled", "false"},
	        {"module::B2bua/enabled", "true"},
	        {"module::B2bua/filter", settings.b2buaFilter},
	        // Config for B2bua server.
	        {"b2bua-server/application", "sip-bridge"},
	        {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	        {"b2bua-server/enable-ice", "false"},
	        {"b2bua-server/one-connection-per-account", "true"},
	        {"b2bua-server::sip-bridge/providers", providersConfigPath.string()},
	    },
	    false,
	};
	flexisipServer.startProxy();

	const auto clientBuilders = [&]() {
		auto map = unordered_map<string, ClientBuilder>{2};
		map.emplace(kFlexisipDomain, std::move(ClientBuilder(flexisipServer.getAgent()).setVideoSend(OnOff::Off)));
		map.emplace(kExternalDomain, std::move(ClientBuilder(externalServer.getAgent()).setVideoSend(OnOff::Off)));
		return map;
	}();

	vector<string> b2buaAccounts{};
	for (const auto& account : {transfereeAccount, transferorAccount, transferTargetAccount}) {
		if (account.mDomain == Domain::Flexisip) {
			b2buaAccounts.push_back(kB2buaProviderAccountConfiguration.format({
			    {"userNameOnFlexisip", account.mUsernameOnFlexisip},
			    {"userNameOnExternal", account.mUsernameOnExternal},
			    {"internalDomain", kFlexisipDomain},
			    {"externalDomain", kExternalDomain},
			}));
		}
	}

	ofstream{providersConfigPath} << settings.providersConfig.format({
	    {"flexisipPort", flexisipServer.getFirstPort()},
	    {"flexisipDomain", kFlexisipDomain},
	    {"externalPort", externalServer.getFirstPort()},
	    {"externalDomain", kExternalDomain},
	    {"b2buaAccounts", string_utils::join(b2buaAccounts, 0, ",")},
	});
	flexisipServer.startB2bua();

	// Instantiate clients.
	auto transferee = clientBuilders.at(transfereeAccount.domain()).build(transfereeAccount.uri().str());
	auto transferor = clientBuilders.at(transferorAccount.domain()).build(transferorAccount.uri().str());
	auto transferTarget = clientBuilders.at(transferTargetAccount.domain()).build(transferTargetAccount.uri().str());

	// Verify B2BUA accounts are registered on the external proxy.
	CoreAssert asserter{flexisipServer, externalServer, transferee, transferor, transferTarget};
	flexisipServer.waitForB2buaAccountsToBeAvailable(externalServer).hard_assert_passed();

	// Create call from "Transferee" to "Transferor".
	const auto transferorAor = transferorAccount.uriOn(transfereeAccount.mDomain).str();
	const auto transfereeCallToTransferor = ClientCall::tryFrom(transferee.invite(transferorAor));
	BC_HARD_ASSERT(transfereeCallToTransferor.has_value());
	transferor.hasReceivedCallFrom(transferee, asserter).hard_assert_passed();

	// Accept call from "Transferee".
	const auto transferorCallFromTransferee = transferor.getCurrentCall();
	BC_HARD_ASSERT(transferorCallFromTransferee.has_value());
	transferorCallFromTransferee->accept();

	asserter
	    .wait([&]() {
		    FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::StreamsRunning);
		    FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::StreamsRunning);
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	// Transfer call to "TransferTarget", initiated by "Transferor".
	const auto transferListener = make_shared<CallTransferListener>();
	transferorCallFromTransferee->addListener(transferListener);
	const auto transferTargetAor = transferTarget.getMe()->clone();
	transferTargetAor->setUsername(transferTargetAccount.uriOn(transferorAccount.mDomain).getUser());
	transferTargetAor->setDomain(transferorAccount.domain());
	transferorCallFromTransferee->transferTo(transferTargetAor);

	// Verify "TransferTarget" received a call from "Transferee".
	transferTarget.hasReceivedCallFrom(transferee, asserter).hard_assert_passed();
	const auto transfereeCallToTransferTarget = transferee.getCurrentCall();
	BC_HARD_ASSERT(transfereeCallToTransferTarget.has_value());
	const auto transferTargetCallFromTransferee = transferTarget.getCurrentCall();
	BC_HARD_ASSERT(transferTargetCallFromTransferee.has_value());

	// Verify that call between "Transferee" and "Transferor" is paused while waiting for "TransferTarget" answer.
	asserter
	    .wait([&]() {
		    FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::Paused);
		    FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::PausedByRemote);
		    FAIL_IF(transfereeCallToTransferTarget->getState() != linphone::Call::State::OutgoingRinging);
		    FAIL_IF(transferTargetCallFromTransferee->getState() != linphone::Call::State::IncomingReceived);
		    // Verify "Transferor" received NOTIFY 100 Trying.
		    FAIL_IF(transferListener->mLastState != linphone::Call::State::OutgoingProgress);
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	// Verify content of "Referred-By" header.
	const SipUri referredByAddress{transferTargetCallFromTransferee->getReferredByAddress()->asStringUriOnly()};
	BC_ASSERT(referredByAddress.compareAll(transferorAccount.uriOn(transfereeAccount.mDomain)));

	// Decline call from "Transferee" to "TransferTarget".
	transferTargetCallFromTransferee->decline(linphone::Reason::Declined);

	asserter
	    .wait([&]() {
		    FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::Paused);
		    FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::PausedByRemote);
		    FAIL_IF(transfereeCallToTransferTarget->getState() != linphone::Call::State::Released);
		    FAIL_IF(transferTargetCallFromTransferee->getState() != linphone::Call::State::Released);
		    // Verify "Transferor" received NOTIFY 500 Internal Server Error.
		    FAIL_IF(transferListener->mLastState != linphone::Call::State::Error);
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	// Let the B2BUA complete the closure of the REFER subscription before resuming.
	// Right after the transfer outcome, the B2BUA sends a final NOTIFY on the peer leg. While it is in flight,
	// belle-sip refuses to create the resume re-INVITE on the same dialog (SDK-314 glare). No API exposes the
	// NOTIFY completion, so settle for a bounded duration while iterating every core.
	asserter.forceIterateThenAssert(0, 500ms, []() { return ASSERTION_PASSED(); }).hard_assert_passed();

	// Resume call after failed call transfer.
	// We have to wait for resume to return 0 because if "Transferee" didn't receive
	// the 200 OK from the NOTIFY yet, then it will fail.
	asserter
	    .wait([&transfereeCallToTransferor]() {
		    FAIL_IF(transfereeCallToTransferor->resume() != 0);
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	asserter
	    .wait([&]() {
		    FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::StreamsRunning);
		    FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::StreamsRunning);
		    FAIL_IF(transfereeCallToTransferTarget->getState() != linphone::Call::State::Released);
		    FAIL_IF(transferTargetCallFromTransferee->getState() != linphone::Call::State::Released);
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	const auto& transfereeProxy = (transfereeAccount.mDomain == Domain::External) ? flexisipServer : externalServer;
	BC_ASSERT(transferee.endCurrentCall(transferor, transfereeProxy.getAgent()));
}

} // namespace blind

namespace attended {

/*
 * Test successful attended call transfer.
 * This test almost implements the following scenario: https://datatracker.ietf.org/doc/html/rfc5589#autoid-15
 *
 * Architecture:
 * - One Proxy server (flexisip.example.org)
 * - One B2BUA server (application: SIP-Bridge)
 * - One external Proxy server (external.example.org)
 * - Three clients {"Transferee", "Transferor", "TransferTarget"} that may be registered on flexisip or on external
 */
void successful(const Settings& settings,
                const CallTransferAccount& transfereeAccount,
                const CallTransferAccount& transferorAccount,
                const CallTransferAccount& transferTargetAccount) {
	TmpDir directory{"b2bua::sip-bridge::"s + __func__};
	const auto providersConfigPath = directory.path() / "providers.json";

	Server externalServer{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", kExternalDomain},
	    {"module::MediaRelay/enabled", "false"},
	}};
	externalServer.start();

	B2buaAndProxyServer flexisipServer{
	    {
	        {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	        {"module::Registrar/enabled", "true"},
	        {"module::Registrar/reg-domains", kFlexisipDomain},
	        {"module::MediaRelay/enabled", "false"},
	        {"module::B2bua/enabled", "true"},
	        {"module::B2bua/filter", settings.b2buaFilter},
	        // Config for B2bua server.
	        {"b2bua-server/application", "sip-bridge"},
	        {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	        {"b2bua-server/enable-ice", "false"},
	        {"b2bua-server/one-connection-per-account", "true"},
	        {"b2bua-server::sip-bridge/providers", providersConfigPath.string()},
	    },
	    false,
	};
	flexisipServer.startProxy();

	const auto clientBuilders = [&]() {
		auto map = unordered_map<string, ClientBuilder>{2};
		map.emplace(
		    kFlexisipDomain,
		    std::move(ClientBuilder(flexisipServer.getAgent()).setVideoSend(OnOff::Off).setReferToUsesAor(OnOff::On)));
		map.emplace(
		    kExternalDomain,
		    std::move(ClientBuilder(externalServer.getAgent()).setVideoSend(OnOff::Off).setReferToUsesAor(OnOff::On)));
		return map;
	}();

	vector<string> b2buaAccounts{};
	for (const auto& account : {transfereeAccount, transferorAccount, transferTargetAccount}) {
		if (account.mDomain == Domain::Flexisip) {
			b2buaAccounts.push_back(kB2buaProviderAccountConfiguration.format({
			    {"userNameOnFlexisip", account.mUsernameOnFlexisip},
			    {"userNameOnExternal", account.mUsernameOnExternal},
			    {"internalDomain", kFlexisipDomain},
			    {"externalDomain", kExternalDomain},
			}));
		}
	}

	ofstream{providersConfigPath} << settings.providersConfig.format({
	    {"flexisipPort", flexisipServer.getFirstPort()},
	    {"flexisipDomain", kFlexisipDomain},
	    {"externalPort", externalServer.getFirstPort()},
	    {"externalDomain", kExternalDomain},
	    {"b2buaAccounts", string_utils::join(b2buaAccounts, 0, ",")},
	});
	flexisipServer.startB2bua();

	// Instantiate clients.
	auto transferee = clientBuilders.at(transfereeAccount.domain()).build(transfereeAccount.uri().str());
	auto transferor = clientBuilders.at(transferorAccount.domain()).build(transferorAccount.uri().str());
	auto transferTarget = clientBuilders.at(transferTargetAccount.domain()).build(transferTargetAccount.uri().str());

	// Verify B2BUA accounts are registered on the external proxy.
	CoreAssert asserter{flexisipServer, externalServer, transferee, transferor, transferTarget};
	flexisipServer.waitForB2buaAccountsToBeAvailable(externalServer).hard_assert_passed();

	// Create call from "Transferee" to "Transferor".
	const auto transferorAor = transferorAccount.uriOn(transfereeAccount.mDomain).str();
	const auto transfereeCallToTransferor = ClientCall::tryFrom(transferee.invite(transferorAor));
	BC_HARD_ASSERT(transfereeCallToTransferor.has_value());
	transferor.hasReceivedCallFrom(transferee, asserter).hard_assert_passed();

	// Accept call from "Transferee".
	const auto transferorCallFromTransferee = transferor.getCurrentCall();
	BC_HARD_ASSERT(transferorCallFromTransferee.has_value());
	transferorCallFromTransferee->accept();

	asserter
	    .wait([&]() {
		    FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::StreamsRunning);
		    FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::StreamsRunning);
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	// Create call from "Transferor" to "TransferTarget".
	const auto transferTargetAor = transferTargetAccount.uriOn(transferorAccount.mDomain).str();
	const auto transferorCallToTransferTarget = ClientCall::tryFrom(transferor.invite(transferTargetAor));
	transferTarget.hasReceivedCallFrom(transferor, asserter).hard_assert_passed();

	// Accept call from "Transferor".
	const auto transferTargetCallFromTransferor = transferTarget.getCurrentCall();
	BC_HARD_ASSERT(transferTargetCallFromTransferor.has_value());
	transferTargetCallFromTransferor->accept();

	asserter
	    .wait([&]() {
		    FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::Paused);
		    FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::PausedByRemote);
		    FAIL_IF(transferorCallToTransferTarget->getState() != linphone::Call::State::StreamsRunning);
		    FAIL_IF(transferTargetCallFromTransferor->getState() != linphone::Call::State::StreamsRunning);
		    return ASSERTION_PASSED();
	    })
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
	    .wait([&, &targetCore = *transferTarget.getCore(),
	           transfereeUser = transfereeAccount.uriOn(transferTargetAccount.mDomain).getUser()]() {
		    for (auto&& call : targetCore.getCalls()) {
			    if (call->getRemoteAddress()->getUsername() == transfereeUser) {
				    transferTargetCallFromTransferee = ClientCall::tryFrom(std::move(call));
				    FAIL_IF(transferTargetCallFromTransferee == nullopt);
				    return ASSERTION_PASSED();
			    }
		    }

		    return ASSERTION_FAILED("Transfer target has not received any call from transferee");
	    })
	    .hard_assert_passed();

	const auto transfereeCallToTransferTarget = transferee.getCurrentCall();
	BC_HARD_ASSERT(transfereeCallToTransferTarget.has_value());
	BC_ASSERT_CPP_EQUAL(transfereeCallToTransferTarget->getRemoteAddress()->getUsername(),
	                    transferTargetAccount.uriOn(transfereeAccount.mDomain).getUser());

	// Verify "Transferor" received NOTIFY 200 Ok.
	transferListener->assertNotifyReceived(asserter, linphone::Call::State::Connected).assert_passed();

	asserter
	    .wait([&]() {
		    FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::Released);
		    FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::Released);
		    FAIL_IF(transferorCallToTransferTarget->getState() != linphone::Call::State::Released);
		    FAIL_IF(transferTargetCallFromTransferor->getState() != linphone::Call::State::Released);
		    FAIL_IF(transfereeCallToTransferTarget->getState() != linphone::Call::State::StreamsRunning);
		    FAIL_IF(transferTargetCallFromTransferee->getState() != linphone::Call::State::StreamsRunning);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();
}

/*
 * Test attended call transfer when "TransferTarget" declines the call.
 *
 * Architecture:
 * - One Proxy server (flexisip.example.org)
 * - One B2BUA server (application: SIP-Bridge)
 * - One external Proxy server (external.example.org)
 * - Three clients {"Transferee", "Transferor", "TransferTarget"} that may be registered on flexisip or on external
 */
void declined(const Settings& settings,
              const CallTransferAccount& transfereeAccount,
              const CallTransferAccount& transferorAccount,
              const CallTransferAccount& transferTargetAccount) {
	TmpDir directory{"b2bua::sip-bridge::"s + __func__};
	const auto providersConfigPath = directory.path() / "providers.json";

	Server externalServer{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", kExternalDomain},
	    {"module::MediaRelay/enabled", "false"},
	}};
	externalServer.start();

	B2buaAndProxyServer flexisipServer{
	    {
	        {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	        {"module::Registrar/enabled", "true"},
	        {"module::Registrar/reg-domains", kFlexisipDomain},
	        {"module::MediaRelay/enabled", "false"},
	        {"module::B2bua/enabled", "true"},
	        {"module::B2bua/filter", settings.b2buaFilter},
	        // Config for B2bua server.
	        {"b2bua-server/application", "sip-bridge"},
	        {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	        {"b2bua-server/enable-ice", "false"},
	        {"b2bua-server/one-connection-per-account", "true"},
	        {"b2bua-server::sip-bridge/providers", providersConfigPath.string()},
	    },
	    false,
	};
	flexisipServer.startProxy();

	const auto clientBuilders = [&]() {
		auto map = unordered_map<string, ClientBuilder>{2};
		map.emplace(kFlexisipDomain, std::move(ClientBuilder(flexisipServer.getAgent())
		                                           .setVideoSend(OnOff::Off)
		                                           .setAutoAnswerReplacingCalls(OnOff::Off)
		                                           .setReferToUsesAor(OnOff::On)));
		map.emplace(kExternalDomain, std::move(ClientBuilder(externalServer.getAgent())
		                                           .setVideoSend(OnOff::Off)
		                                           .setAutoAnswerReplacingCalls(OnOff::Off)
		                                           .setReferToUsesAor(OnOff::On)));
		return map;
	}();

	vector<string> b2buaAccounts{};
	for (const auto& account : {transfereeAccount, transferorAccount, transferTargetAccount}) {
		if (account.mDomain == Domain::Flexisip) {
			b2buaAccounts.push_back(kB2buaProviderAccountConfiguration.format({
			    {"userNameOnFlexisip", account.mUsernameOnFlexisip},
			    {"userNameOnExternal", account.mUsernameOnExternal},
			    {"internalDomain", kFlexisipDomain},
			    {"externalDomain", kExternalDomain},
			}));
		}
	}

	ofstream{providersConfigPath} << settings.providersConfig.format({
	    {"flexisipPort", flexisipServer.getFirstPort()},
	    {"flexisipDomain", kFlexisipDomain},
	    {"externalPort", externalServer.getFirstPort()},
	    {"externalDomain", kExternalDomain},
	    {"b2buaAccounts", string_utils::join(b2buaAccounts, 0, ",")},
	});
	flexisipServer.startB2bua();

	// Instantiate clients.
	auto transferee = clientBuilders.at(transfereeAccount.domain()).build(transfereeAccount.uri().str());
	auto transferor = clientBuilders.at(transferorAccount.domain()).build(transferorAccount.uri().str());
	auto transferTarget = clientBuilders.at(transferTargetAccount.domain()).build(transferTargetAccount.uri().str());

	// Verify B2BUA accounts are registered on the external proxy.
	CoreAssert asserter{flexisipServer, externalServer, transferee, transferor, transferTarget};
	flexisipServer.waitForB2buaAccountsToBeAvailable(externalServer).hard_assert_passed();

	// Create call from "Transferee" to "Transferor".
	const auto transferorAor = transferorAccount.uriOn(transfereeAccount.mDomain).str();
	const auto transfereeCallToTransferor = ClientCall::tryFrom(transferee.invite(transferorAor));
	BC_HARD_ASSERT(transfereeCallToTransferor.has_value());
	transferor.hasReceivedCallFrom(transferee, asserter).hard_assert_passed();

	// Accept call from "Transferee".
	const auto transferorCallFromTransferee = transferor.getCurrentCall();
	BC_HARD_ASSERT(transferorCallFromTransferee.has_value());
	transferorCallFromTransferee->accept();

	asserter
	    .wait([&]() {
		    ASSERT_CALL(transfereeCallToTransferor, Call::State::StreamsRunning, MediaDirection::SendRecv);
		    ASSERT_CALL(transferorCallFromTransferee, Call::State::StreamsRunning, MediaDirection::SendRecv);
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	// Create call from "Transferor" to "TransferTarget".
	const auto transferTargetAor = transferTargetAccount.uriOn(transferorAccount.mDomain).str();
	const auto transferorCallToTransferTarget = ClientCall::tryFrom(transferor.invite(transferTargetAor));
	BC_HARD_ASSERT(transferorCallToTransferTarget.has_value());
	transferTarget.hasReceivedCallFrom(transferor, asserter).hard_assert_passed();

	// Accept call from "Transferor".
	const auto transferTargetCallFromTransferor = transferTarget.getCurrentCall();
	BC_HARD_ASSERT(transferTargetCallFromTransferor.has_value());
	transferTargetCallFromTransferor->accept();

	asserter
	    .wait([&]() {
		    ASSERT_CALL(transfereeCallToTransferor, Call::State::PausedByRemote, MediaDirection::RecvOnly);
		    ASSERT_CALL(transferorCallFromTransferee, Call::State::Paused, MediaDirection::SendOnly);
		    ASSERT_CALL(transferorCallToTransferTarget, Call::State::StreamsRunning, MediaDirection::SendRecv);
		    ASSERT_CALL(transferTargetCallFromTransferor, Call::State::StreamsRunning, MediaDirection::SendRecv);
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	// Transfer call between "Transferee" and "Transferor" to call between "Transferor" and "TransferTarget".
	const auto transferListener = make_shared<CallTransferListener>();
	transferorCallFromTransferee->addListener(transferListener);
	transferorCallFromTransferee->transferToAnother(*transferorCallToTransferTarget);

	// Verify "Transferor" received NOTIFY 100 Trying.
	transferListener->assertNotifyReceived(asserter, Call::State::OutgoingProgress).assert_passed();

	// Verify that both "Transferor" and "Transferee" are now in the Paused state.
	asserter
	    .wait([&]() {
		    ASSERT_CALL(transfereeCallToTransferor, Call::State::Paused, MediaDirection::Inactive);
		    ASSERT_CALL(transferorCallFromTransferee, Call::State::Paused, MediaDirection::Inactive);
		    ASSERT_CALL(transferorCallToTransferTarget, Call::State::StreamsRunning, MediaDirection::SendRecv);
		    ASSERT_CALL(transferTargetCallFromTransferor, Call::State::StreamsRunning, MediaDirection::SendRecv);
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	// Verify "TransferTarget" received a call from "Transferee" and decline it.
	auto transferTargetCallFromTransferee = optional<ClientCall>();
	asserter
	    .wait([&, &targetCore = *transferTarget.getCore(),
	           transfereeUser = transfereeAccount.uriOn(transferTargetAccount.mDomain).getUser()]() {
		    for (auto&& call : targetCore.getCalls()) {
			    if (call->getRemoteAddress()->getUsername() == transfereeUser) {
				    transferTargetCallFromTransferee = ClientCall::tryFrom(std::move(call));
				    FAIL_IF(transferTargetCallFromTransferee == nullopt);
				    transferTargetCallFromTransferee->decline(Reason::Declined);
				    return ASSERTION_PASSED();
			    }
		    }

		    return ASSERTION_FAILED("Transfer target has not received any call from transferee");
	    })
	    .hard_assert_passed();

	const auto transfereeCallToTransferTarget = transferee.getCurrentCall();
	BC_HARD_ASSERT(transfereeCallToTransferTarget.has_value());
	BC_ASSERT_CPP_EQUAL(transfereeCallToTransferTarget->getRemoteAddress()->getUsername(),
	                    transferTargetAccount.uriOn(transfereeAccount.mDomain).getUser());

	// Verify "Transferor" received NOTIFY 500 Internal Server Error.
	transferListener->assertNotifyReceived(asserter, Call::State::Error).assert_passed();

	asserter
	    .wait([&]() {
		    ASSERT_CALL(transfereeCallToTransferor, Call::State::Paused, MediaDirection::Inactive);
		    ASSERT_CALL(transferorCallFromTransferee, Call::State::Paused, MediaDirection::Inactive);
		    ASSERT_CALL(transferorCallToTransferTarget, Call::State::StreamsRunning, MediaDirection::SendRecv);
		    ASSERT_CALL(transferTargetCallFromTransferor, Call::State::StreamsRunning, MediaDirection::SendRecv);
		    ASSERT_CALL(transfereeCallToTransferTarget, Call::State::Released);
		    ASSERT_CALL(transferTargetCallFromTransferee, Call::State::Released);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	// "TransferTarget" terminates its call with "Transferor".
	transferTargetCallFromTransferor->terminate();

	asserter
	    .wait([&]() {
		    ASSERT_CALL(transfereeCallToTransferor, Call::State::Paused, MediaDirection::Inactive);
		    ASSERT_CALL(transferorCallFromTransferee, Call::State::Paused, MediaDirection::Inactive);
		    ASSERT_CALL(transferorCallToTransferTarget, Call::State::Released);
		    ASSERT_CALL(transferTargetCallFromTransferor, Call::State::Released);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	// "Transferor" resumes its call with "Transferee".
	transferorCallFromTransferee->resume();
	asserter
	    .wait([&]() {
		    ASSERT_CALL(transfereeCallToTransferor, Call::State::Paused, MediaDirection::SendOnly);
		    ASSERT_CALL(transferorCallFromTransferee, Call::State::PausedByRemote, MediaDirection::RecvOnly);

		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	// "Transferee" resumes its call with "Transferor"
	transfereeCallToTransferor->resume();
	asserter
	    .wait([&]() {
		    ASSERT_CALL(transfereeCallToTransferor, Call::State::StreamsRunning, MediaDirection::SendRecv);
		    ASSERT_CALL(transferorCallFromTransferee, Call::State::StreamsRunning, MediaDirection::SendRecv);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();
}

} // namespace attended

} // namespace flexisip::tester