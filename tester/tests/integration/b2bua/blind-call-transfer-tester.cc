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
 * Test successful blind call transfer.
 * This test implements the following scenario: https://datatracker.ietf.org/doc/html/rfc5589#autoid-7
 *
 * Architecture:
 * - One Proxy server (flexisip.example.org)
 * - One B2BUA server (application: SIP-Bridge)
 * - One external Proxy server (external.example.org)
 * - Three clients {"Transferee", "Transferor", "TransferTarget"} that may be registered on flexisip or on external
 */
template <const CallTransferAccount& transfereeAccount,
          const CallTransferAccount& transferorAccount,
          const CallTransferAccount& transferTargetAccount,
          ExternalUsernameDialing dialing = ExternalUsernameDialing::Disabled>
void successful() {
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
	const SipUri transferorAddressOnTransfereeDomain = transferorAccount.uriOn(transfereeAccount.mDomain);
	BC_ASSERT(referredByAddress.compareAll(transferorAddressOnTransfereeDomain));

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
template <const CallTransferAccount& transfereeAccount,
          const CallTransferAccount& transferorAccount,
          const CallTransferAccount& transferTargetAccount,
          ExternalUsernameDialing dialing = ExternalUsernameDialing::Disabled>
void declined() {
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
	const SipUri transferorAddressOnTransfereeDomain = transferorAccount.uriOn(transfereeAccount.mDomain);
	BC_ASSERT(referredByAddress.compareAll(transferorAddressOnTransfereeDomain));

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
		    // FIXME: it should always be in state StreamsRunning. See SDK-314.
		    if (transferorAccount.mDomain == Domain::External and transfereeAccount.mDomain == Domain::Flexisip) {
			    FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::PausedByRemote);
		    } else {
			    FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::StreamsRunning);
		    }
		    FAIL_IF(transfereeCallToTransferTarget->getState() != linphone::Call::State::Released);
		    FAIL_IF(transferTargetCallFromTransferee->getState() != linphone::Call::State::Released);
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	const auto& transfereeProxy = (transfereeAccount.mDomain == Domain::External) ? flexisipServer : externalServer;
	BC_ASSERT(transferee.endCurrentCall(transferor, transfereeProxy.getAgent()));
}

namespace shared_usernames {

TestSuite _{
    "b2bua::sip-bridge::blind-call-transfer::shared-usernames",
    {
        CLASSY_TEST((successful<kTransfereeIntern, kTransferorIntern, kTransferTIntern>)).tag("skip"),
        CLASSY_TEST((successful<kTransfereeIntern, kTransferorIntern, kTransferTExtern>)),
        CLASSY_TEST((successful<kTransfereeIntern, kTransferorExtern, kTransferTIntern>)).tag("skip"),
        CLASSY_TEST((successful<kTransfereeIntern, kTransferorExtern, kTransferTExtern>)).tag("skip"),
        CLASSY_TEST((successful<kTransfereeExtern, kTransferorIntern, kTransferTIntern>)).tag("skip"),
        CLASSY_TEST((successful<kTransfereeExtern, kTransferorIntern, kTransferTExtern>)).tag("skip"),
        CLASSY_TEST((successful<kTransfereeExtern, kTransferorExtern, kTransferTIntern>)),
        CLASSY_TEST((successful<kTransfereeExtern, kTransferorExtern, kTransferTExtern>)).tag("skip"),

        CLASSY_TEST((declined<kTransfereeIntern, kTransferorIntern, kTransferTIntern>)).tag("skip"),
        CLASSY_TEST((declined<kTransfereeIntern, kTransferorIntern, kTransferTExtern>)),
        CLASSY_TEST((declined<kTransfereeIntern, kTransferorExtern, kTransferTIntern>)).tag("skip"),
        CLASSY_TEST((declined<kTransfereeIntern, kTransferorExtern, kTransferTExtern>)).tag("skip"),
        CLASSY_TEST((declined<kTransfereeExtern, kTransferorIntern, kTransferTIntern>)).tag("skip"),
        CLASSY_TEST((declined<kTransfereeExtern, kTransferorIntern, kTransferTExtern>)).tag("skip"),
        CLASSY_TEST((declined<kTransfereeExtern, kTransferorExtern, kTransferTIntern>)),
        CLASSY_TEST((declined<kTransfereeExtern, kTransferorExtern, kTransferTExtern>)).tag("skip"),
    },
};

}

TestSuite _{
    "b2bua::sip-bridge::blind-call-transfer",
    {
        CLASSY_TEST((successful<kTransfereeInternD, kTransferorInternD, kTransferTInternD>)).tag("skip"),
        CLASSY_TEST((successful<kTransfereeInternD, kTransferorInternD, kTransferTExtern>)).tag("skip"),
        CLASSY_TEST((successful<kTransfereeInternD, kTransferorExtern, kTransferTInternD>)).tag("skip"),
        CLASSY_TEST((successful<kTransfereeInternD, kTransferorExtern, kTransferTExtern>)).tag("skip"),
        CLASSY_TEST((successful<kTransfereeExtern, kTransferorInternD, kTransferTInternD>)).tag("skip"),
        CLASSY_TEST((successful<kTransfereeExtern, kTransferorInternD, kTransferTExtern>)).tag("skip"),
        CLASSY_TEST((successful<kTransfereeExtern, kTransferorExtern, kTransferTInternD>)).tag("skip"),
        CLASSY_TEST((successful<kTransfereeExtern, kTransferorExtern, kTransferTExtern>)).tag("skip"),

        CLASSY_TEST((declined<kTransfereeInternD, kTransferorInternD, kTransferTInternD>)).tag("skip"),
        CLASSY_TEST((declined<kTransfereeInternD, kTransferorInternD, kTransferTExtern>)).tag("skip"),
        CLASSY_TEST((declined<kTransfereeInternD, kTransferorExtern, kTransferTInternD>)).tag("skip"),
        CLASSY_TEST((declined<kTransfereeInternD, kTransferorExtern, kTransferTExtern>)).tag("skip"),
        CLASSY_TEST((declined<kTransfereeExtern, kTransferorInternD, kTransferTInternD>)).tag("skip"),
        CLASSY_TEST((declined<kTransfereeExtern, kTransferorInternD, kTransferTExtern>)).tag("skip"),
        CLASSY_TEST((declined<kTransfereeExtern, kTransferorExtern, kTransferTInternD>)).tag("skip"),
        CLASSY_TEST((declined<kTransfereeExtern, kTransferorExtern, kTransferTExtern>)).tag("skip"),
    },
};

} // namespace
} // namespace flexisip::tester