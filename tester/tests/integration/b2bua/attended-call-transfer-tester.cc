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
#include <utility>

#include "call-transfer-tester.hh"
#include "utils/call-listeners.hh"
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
using namespace std;

namespace flexisip::tester {
namespace {

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
template <ExternalUsernameDialing dialing = ExternalUsernameDialing::Disabled>
void successful(const CallTransferAccount& transfereeAccount,
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

	ofstream{providersConfigPath} << kCallTransferProvidersConfiguration.format({
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
	const auto transferorAor = transferorAccount.dialUri(transfereeAccount, dialing).str();
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
	const auto transferTargetAor = transferTargetAccount.dialUri(transferorAccount, dialing).str();
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
	           transfereeUser = transfereeAccount.seenUriOn(transferTargetAccount.mDomain, dialing).getUser()]() {
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
	                    transferTargetAccount.seenUriOn(transfereeAccount.mDomain, dialing).getUser());

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
template <ExternalUsernameDialing dialing = ExternalUsernameDialing::Disabled>
void declined(const CallTransferAccount& transfereeAccount,
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
		                                           .setAutoAnswerReplacingCalls(OnOff::Off)));
		map.emplace(kExternalDomain, std::move(ClientBuilder(externalServer.getAgent())
		                                           .setVideoSend(OnOff::Off)
		                                           .setAutoAnswerReplacingCalls(OnOff::Off)));
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

	ofstream{providersConfigPath} << kCallTransferProvidersConfiguration.format({
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
	const auto transferorAor = transferorAccount.dialUri(transfereeAccount, dialing).str();
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
	const auto transferTargetAor = transferTargetAccount.dialUri(transferorAccount, dialing).str();
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
	           transfereeUser = transfereeAccount.seenUriOn(transferTargetAccount.mDomain, dialing).getUser()]() {
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
	                    transferTargetAccount.seenUriOn(transfereeAccount.mDomain, dialing).getUser());

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

namespace tests {

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
 * FLEXISIP    B2BUA    EXTERNAL
 *     TE ---1--> ---2--> TO
 *
 *     					  TO --3╷
 *                        TT <--╵
 *                                   TO sends a REFER to TE with call-ID 3
 *     TE ---4--> ---5--> TT         TT must receive a 'Replaces' header containing call-ID 3
 */
void noBridgeForReplacementCall(const CallTransferAccount& transfereeIntern,
                                const CallTransferAccount& transferorExtern,
                                const CallTransferAccount& transferTExtern) {
	successful(transfereeIntern, transferorExtern, transferTExtern);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     TO <--2--- <--1--- TE
 *
 *     TO ---3--> ---4--> TT
 *                                   TO sends a REFER to TE with call-ID 3
 *     					  TE --5╷
 *                        TT <--╵    TT must receive a 'Replaces' header containing call-ID 4
 */
void unidirectionalBridgeForReplacementCall(const CallTransferAccount& transfereeExtern,
                                            const CallTransferAccount& transferorIntern,
                                            const CallTransferAccount& transferTExtern) {
	successful(transfereeExtern, transferorIntern, transferTExtern);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     					  TE --1╷
 *                        TO <--╵
 *
 *     TT <--3--- <--2--- TO
 *                                   TO sends a REFER to TE with call-ID 2
 *     TT <--5--- <--4--- TE         TT must receive a 'Replaces' header containing call-ID 3
 */
void unidirectionalBridgeForReplacementCallAndFromTEtoTT(const CallTransferAccount& transfereeExtern,
                                                         const CallTransferAccount& transferorExtern,
                                                         const CallTransferAccount& transferTIntern) {
	successful(transfereeExtern, transferorExtern, transferTIntern);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     TE ---1--> ---2-->
 *     TO <--3--- <--2---
 *
 *     TO ---4--> ---5-->
 *     TT <--6--- <--5---
 *                                   TO send a REFER to TE with call-ID 4
 *     TE ---7--> ---8-->
 *     TT <--9--- <--8---            TT must receive a 'Replaces' header containing call-ID 6
 */
void bidirectionalBridgeForAll(const CallTransferAccount& transfereeIntern,
                               const CallTransferAccount& transferorIntern,
                               const CallTransferAccount& transferTIntern) {
	successful(transfereeIntern, transferorIntern, transferTIntern);
}

void declined_unidirectionalBridgeForReplacementCall(const CallTransferAccount& transfereeExtern,
                                                     const CallTransferAccount& transferorIntern,
                                                     const CallTransferAccount& transferTExtern) {
	declined(transfereeExtern, transferorIntern, transferTExtern);
}

void declined_bidirectionalBridgeForAll(const CallTransferAccount& transfereeIntern,
                                        const CallTransferAccount& transferorIntern,
                                        const CallTransferAccount& transferTIntern) {
	declined(transfereeIntern, transferorIntern, transferTIntern);
}

} // namespace tests

namespace shared_usernames {

void noBridgeForReplacementCall() {
	tests::noBridgeForReplacementCall(kTransfereeIntern, kTransferorExtern, kTransferTExtern);
}

void unidirectionalBridgeForReplacementCall() {
	tests::unidirectionalBridgeForReplacementCall(kTransfereeExtern, kTransferorIntern, kTransferTExtern);
}

void unidirectionalBridgeForReplacementCallAndFromTEtoTT() {
	tests::unidirectionalBridgeForReplacementCallAndFromTEtoTT(kTransfereeExtern, kTransferorExtern, kTransferTIntern);
}

void bidirectionalBridgeForAll() {
	tests::bidirectionalBridgeForAll(kTransfereeIntern, kTransferorIntern, kTransferTIntern);
}

void declined_unidirectionalBridgeForReplacementCall() {
	tests::declined_unidirectionalBridgeForReplacementCall(kTransfereeExtern, kTransferorIntern, kTransferTExtern);
}

void declined_bidirectionalBridgeForAll() {
	tests::declined_bidirectionalBridgeForAll(kTransfereeIntern, kTransferorIntern, kTransferTIntern);
}

TestSuite _{
    "b2bua::sip-bridge::attended-call-transfer::shared-usernames",
    {
        CLASSY_TEST(noBridgeForReplacementCall),
        CLASSY_TEST(unidirectionalBridgeForReplacementCall),
        CLASSY_TEST(unidirectionalBridgeForReplacementCallAndFromTEtoTT),
        CLASSY_TEST(bidirectionalBridgeForAll),

        CLASSY_TEST(declined_unidirectionalBridgeForReplacementCall),
        CLASSY_TEST(declined_bidirectionalBridgeForAll),
    },
};

} // namespace shared_usernames

void noBridgeForReplacementCall() {
	tests::noBridgeForReplacementCall(kTransfereeInternD, kTransferorExtern, kTransferTExtern);
}

void unidirectionalBridgeForReplacementCall() {
	tests::unidirectionalBridgeForReplacementCall(kTransfereeExtern, kTransferorInternD, kTransferTExtern);
}

void unidirectionalBridgeForReplacementCallAndFromTEtoTT() {
	tests::unidirectionalBridgeForReplacementCallAndFromTEtoTT(kTransfereeExtern, kTransferorExtern, kTransferTInternD);
}

void bidirectionalBridgeForAll() {
	tests::bidirectionalBridgeForAll(kTransfereeInternD, kTransferorInternD, kTransferTInternD);
}

void declined_unidirectionalBridgeForReplacementCall() {
	tests::declined_unidirectionalBridgeForReplacementCall(kTransfereeExtern, kTransferorInternD, kTransferTExtern);
}

void declined_bidirectionalBridgeForAll() {
	tests::declined_bidirectionalBridgeForAll(kTransfereeInternD, kTransferorInternD, kTransferTInternD);
}

TestSuite _{
    "b2bua::sip-bridge::attended-call-transfer",
    {
        CLASSY_TEST(noBridgeForReplacementCall).tag("Skip"),
        CLASSY_TEST(unidirectionalBridgeForReplacementCall).tag("Skip"),
        CLASSY_TEST(unidirectionalBridgeForReplacementCallAndFromTEtoTT).tag("Skip"),
        CLASSY_TEST(bidirectionalBridgeForAll).tag("Skip"),

        CLASSY_TEST(declined_unidirectionalBridgeForReplacementCall).tag("Skip"),
        CLASSY_TEST(declined_bidirectionalBridgeForAll).tag("Skip"),
    },
};

} // namespace
} // namespace flexisip::tester