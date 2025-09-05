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

#include <chrono>
#include <memory>
#include <optional>

#include "asserts.hh"
#include "bctoolbox/tester.h"
#include "client-core.hh"
#include "core-assert.hh"
#include "flexisip/module-router.hh"
#include "linphone++/address.hh"
#include "linphone++/call.hh"
#include "linphone++/call_params.hh"
#include "linphone/misc.h"
#include "tester.hh"
#include "utils/call-builder.hh"
#include "utils/chat-room-builder.hh"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"

using namespace std;
using namespace std::chrono;
using namespace linphone;

namespace flexisip::tester {

namespace {

auto assert_data_transmitted(linphone::Call& calleeCall, linphone::Call& callerCall, bool videoOriginallyEnabled) {
	return [&calleeCall, &callerCall, videoOriginallyEnabled] {
		const auto& calleeAudioStats = calleeCall.getAudioStats();
		FAIL_IF(calleeAudioStats == nullptr);
		const auto& callerAudioStats = callerCall.getAudioStats();
		FAIL_IF(callerAudioStats == nullptr);
		// Check both sides for download and upload
		FAIL_IF(calleeAudioStats->getDownloadBandwidth() < 10);
		FAIL_IF(callerAudioStats->getDownloadBandwidth() < 10);

		if (videoOriginallyEnabled) { // Not VideoEnabled() of current call. Callee could have declined
			FAIL_IF(!calleeCall.getCurrentParams()->videoEnabled());
			FAIL_IF(!callerCall.getCurrentParams()->videoEnabled());
			const auto& calleeVideoStats = calleeCall.getVideoStats();
			FAIL_IF(calleeVideoStats == nullptr);
			const auto& callerVideoStats = callerCall.getVideoStats();
			FAIL_IF(callerVideoStats == nullptr);
			FAIL_IF(calleeVideoStats->getDownloadBandwidth() < 10);
			FAIL_IF(callerVideoStats->getDownloadBandwidth() < 10);
		} else {
			FAIL_IF(callerCall.getCurrentParams()->videoEnabled());
			FAIL_IF(calleeCall.getCurrentParams()->videoEnabled());
		}

		return ASSERTION_PASSED();
	};
}

} // namespace

std::shared_ptr<linphone::Core> minimalCore() {
	const auto factory = linphone::Factory::get();
	const auto dataDir = std::string(bc_tester_get_writable_dir_prefix());
	auto linphoneConfig = factory->createConfig("");

	linphoneConfig->setBool("logging", "disable_stdout", true);
	linphoneConfig->setString("storage", "call_logs_db_uri", dataDir + "/null");
	linphoneConfig->setString("storage", "zrtp_secrets_db_uri", dataDir + "/null");
	linphoneConfig->setString("storage", "uri", dataDir + "/null");
	linphoneConfig->setString("lime", "x3dh_db_path", ":memory:");
	auto core = factory->createCoreWithConfig(linphoneConfig, nullptr);
	factory->setDataDir(bcTesterWriteDir() / "");
	auto clientTransport = factory->createTransports();
	clientTransport->setTcpPort(LC_SIP_TRANSPORT_DONTBIND);
	clientTransport->setUdpPort(LC_SIP_TRANSPORT_DONTBIND);
	core->setTransports(clientTransport);
	core->setZrtpSecretsFile(":memory:");
	core->enableLimeX3Dh(false);
	return core;
}

CoreClient::CoreClient(const std::string& me, const std::shared_ptr<Agent>& agent)
    : CoreClient(ClientBuilder(*agent).build(me)) {
}

CoreClient::~CoreClient() {
	if (mAccount != nullptr) {
		mCore->clearAccounts();
		if (mAccount->getState() != linphone::RegistrationState::None) {
			CoreAssert(mCore, mAgent)
			    .wait([&account = mAccount] {
				    FAIL_IF(account->getState() != linphone::RegistrationState::Cleared);
				    return ASSERTION_PASSED();
			    })
			    .assert_passed();
		}
	}
	if (mCore) {
		mCore->stopAsync(); // stopAsync is not really async, we must clear the account first, or it will wait for the
		                    // un-registration on server
		CoreAssert(mCore, mAgent)
		    .wait([&core = mCore] {
			    FAIL_IF(core->getGlobalState() != linphone::GlobalState::Off);
			    return ASSERTION_PASSED();
		    })
		    .assert_passed();
	}
}

std::shared_ptr<linphone::Call> CoreClient::callVideo(const std::shared_ptr<const CoreClient>& callee,
                                                      const std::shared_ptr<linphone::CallParams>& callerCallParams,
                                                      const std::shared_ptr<linphone::CallParams>& calleeCallParams,
                                                      const std::shared_ptr<Agent>& externalProxy) {
	return callVideo(*callee, callerCallParams, calleeCallParams, externalProxy);
}

std::shared_ptr<linphone::Call> CoreClient::callVideo(const CoreClient& callee,
                                                      const std::shared_ptr<linphone::CallParams>& callerCallParams,
                                                      const std::shared_ptr<linphone::CallParams>& calleeCallParams,
                                                      const std::shared_ptr<Agent>& externalProxy) {
	const auto calleeAddress = callee.getAccount()->getParams()->getIdentityAddress();
	auto callParams = callerCallParams;
	if (callParams == nullptr) {
		callParams = mCore->createCallParams(nullptr);
	}
	callParams->enableVideo(true);
	return call(callee, calleeAddress, callParams, calleeCallParams, {}, externalProxy);
}

std::shared_ptr<linphone::Call> CoreClient::call(const CoreClient& callee,
                                                 const std::shared_ptr<const linphone::Address>& calleeAddress,
                                                 const std::shared_ptr<linphone::CallParams>& callerCallParams,
                                                 const std::shared_ptr<linphone::CallParams>& calleeCallParams,
                                                 const std::vector<std::shared_ptr<CoreClient>>& calleeIdleDevices,
                                                 const std::shared_ptr<Agent>& externalProxy) {
	auto callParams = callerCallParams;
	if (callParams == nullptr) {
		callParams = mCore->createCallParams(nullptr);
	}

	auto clonedCalleeAddress = calleeAddress->clone();
	clonedCalleeAddress->removeUriParam("gr");
	auto callerCall = mCore->inviteAddressWithParams(clonedCalleeAddress, callParams);

	if (callerCall == nullptr) {
		BC_FAIL("Invite \"" + clonedCalleeAddress->asString() + "\" failed");
		return nullptr;
	}

	CoreAssert asserter{mCore, mAgent, callee.mCore, callee.mAgent};
	CoreAssert idleAsserter{mCore, mAgent, callee.mCore, callee.mAgent};
	for (const auto& calleeDevice : calleeIdleDevices) {
		idleAsserter.registerSteppable(calleeDevice);
	}
	if (externalProxy) {
		asserter.registerSteppable(externalProxy);
		idleAsserter.registerSteppable(externalProxy);
	}

	// Check call get the incoming call and caller is in OutgoingRinging state.
	if (!callee.hasReceivedCallFrom(*this, asserter).assert_passed()) {
		return nullptr;
	}

	if (!calleeIdleDevices.empty()) {
		// If callee also have idle devices, verify that they are ringing too.
		if (!idleAsserter
		         .wait([&calleeIdleDevices] {
			         FAIL_IF(any_of(calleeIdleDevices.cbegin(), calleeIdleDevices.cend(),
			                        [](const shared_ptr<CoreClient>& idleDevice) {
				                        const auto call = idleDevice->getCurrentCall();
				                        return call == std::nullopt ||
				                               call->getState() != linphone::Call::State::IncomingReceived;
			                        }));
			         return ASSERTION_PASSED();
		         })
		         .assert_passed()) {
			return nullptr;
		}
	}

	const auto calleeCall = callee.mCore->getCurrentCall();
	if (calleeCall == nullptr) {
		BC_FAIL("No call received");
		return nullptr;
	}

	if (!asserter
	         .wait([&callerCall] {
		         FAIL_IF(callerCall->getState() != linphone::Call::State::OutgoingRinging);
		         return ASSERTION_PASSED();
	         })
	         .assert_passed()) {
		return nullptr;
	}

	// Callee answer the call
	if (!BC_ASSERT(calleeCall->acceptWithParams(calleeCallParams) == 0)) {
		return nullptr;
	};

	if (!asserter
	         .waitUntil(5s,
	                    [&calleeCall, &callerCall] {
		                    FAIL_IF(callerCall->getState() != linphone::Call::State::StreamsRunning);
		                    FAIL_IF(calleeCall->getState() != linphone::Call::State::StreamsRunning);
		                    return ASSERTION_PASSED();
	                    })
	         .assert_passed()) {
		BC_ASSERT(callerCall->getState() == linphone::Call::State::StreamsRunning);
		BC_ASSERT(calleeCall->getState() == linphone::Call::State::StreamsRunning);
		return nullptr;
	}
	if (!calleeIdleDevices.empty()) {
		// If callee also have idle devices check that they are not ringing anymore / got cancelled.
		if (!idleAsserter
		         .wait([&calleeIdleDevices] {
			         FAIL_IF(!all_of(calleeIdleDevices.cbegin(), calleeIdleDevices.cend(),
			                         [](const shared_ptr<CoreClient>& idleDevice) {
				                         const auto call = idleDevice->getCurrentCall();
				                         return call == std::nullopt ||
				                                call->getState() == linphone::Call::State::End ||
				                                call->getState() == linphone::Call::State::Released;
			                         }));
			         return ASSERTION_PASSED();
		         })
		         .assert_passed()) {
			return nullptr;
		}
	}

	if (!asserter.waitUntil(12s, assert_data_transmitted(*calleeCall, *callerCall, callParams->videoEnabled()))
	         .assert_passed()) {
		return nullptr;
	}

	return callerCall;
}

std::shared_ptr<linphone::Call> CoreClient::call(const CoreClient& callee,
                                                 const std::shared_ptr<linphone::CallParams>& callerCallParams,
                                                 const std::shared_ptr<linphone::CallParams>& calleeCallParams,
                                                 const std::vector<std::shared_ptr<CoreClient>>& calleeIdleDevices,
                                                 const std::shared_ptr<Agent>& externalProxy) {
	const auto calleeAddress = callee.getAccount()->getParams()->getIdentityAddress();
	return call(callee, calleeAddress, callerCallParams, calleeCallParams, calleeIdleDevices, externalProxy);
}

std::shared_ptr<linphone::Call> CoreClient::call(const std::shared_ptr<CoreClient>& callee,
                                                 const std::shared_ptr<linphone::CallParams>& callerCallParams,
                                                 const std::shared_ptr<linphone::CallParams>& calleeCallParams,
                                                 const std::vector<std::shared_ptr<CoreClient>>& calleeIdleDevices,
                                                 const std::shared_ptr<Agent>& externalProxy) {
	return call(*callee, callerCallParams, calleeCallParams, calleeIdleDevices, externalProxy);
}

std::shared_ptr<linphone::Call> CoreClient::call(const CoreClient& callee, const Server& externalProxy) {
	const auto calleeAddress = callee.getAccount()->getParams()->getIdentityAddress();
	return call(callee, calleeAddress, nullptr, nullptr, {}, externalProxy.getAgent());
}

std::shared_ptr<linphone::Call> CoreClient::callWithEarlyCancel(const CoreClient& callee) {
	auto callParams = mCore->createCallParams(nullptr);

	auto addressWithoutGr = callee.getAccount()->getContactAddress()->clone();
	addressWithoutGr->removeUriParam("gr");
	auto callerCall = mCore->inviteAddressWithParams(addressWithoutGr, callParams);

	if (callerCall == nullptr) {
		BC_FAIL("Invite \"" + addressWithoutGr->asString() + "\" failed");
		return nullptr;
	}

	CoreAssert asserter{mCore, mAgent, callee.mCore, callee.mAgent};

	// Wait for call to be received
	if (!asserter
	         .waitUntil(15s,
	                    [&callerCall, &callee] {
		                    FAIL_IF(callerCall->getState() != linphone::Call::State::OutgoingRinging);
		                    const auto calleeCall = callee.getCurrentCall();
		                    FAIL_IF(!calleeCall);
		                    FAIL_IF(calleeCall->getState() != Call::State::IncomingReceived);
		                    return ASSERTION_PASSED();
	                    })
	         .assert_passed()) {
		return nullptr;
	}

	callerCall->terminate();

	if (!asserter.wait([&] { return LOOP_ASSERTION(callerCall->getState() == linphone::Call::State::Released); })
	         .assert_passed()) {
		return nullptr;
	}

	return callerCall;
}

std::shared_ptr<linphone::Call>
CoreClient::callWithEarlyDecline(const CoreClient& callee,
                                 const std::shared_ptr<linphone::CallParams>& callerCallParams,
                                 const std::shared_ptr<Agent>& externalProxy) {
	auto callParams = callerCallParams;
	if (callParams == nullptr) {
		callParams = mCore->createCallParams(nullptr);
	}

	auto addressWithoutGr = callee.getAccount()->getContactAddress()->clone();
	addressWithoutGr->removeUriParam("gr");
	auto callerCall = mCore->inviteAddressWithParams(addressWithoutGr, callParams);

	if (callerCall == nullptr) {
		BC_FAIL("Invite \"" + addressWithoutGr->asString() + "\" failed");
		return nullptr;
	}

	CoreAssert asserter{mCore, mAgent, callee.mCore, callee.mAgent};
	asserter.registerSteppable(callee);
	if (externalProxy) {
		asserter.registerSteppable(externalProxy);
	}

	// Check call get the incoming call and caller is in OutgoingRinging state.
	if (!asserter
	         .waitUntil(10s,
	                    [&callerCall, &callee] {
		                    FAIL_IF(callerCall->getState() != linphone::Call::State::OutgoingRinging);
		                    const auto calleeCall = callee.getCurrentCall();
		                    FAIL_IF(!calleeCall);
		                    FAIL_IF(calleeCall->getState() != linphone::Call::State::IncomingReceived);
		                    return ASSERTION_PASSED();
	                    })
	         .assert_passed()) {
		return nullptr;
	}

	callee.getCurrentCall()->decline(linphone::Reason::Declined);

	if (!asserter
	         .wait([&callerCall, &callee] {
		         FAIL_IF(callerCall->getState() != linphone::Call::State::Released);
		         const auto calleeCall = callee.getCurrentCall();
		         FAIL_IF(calleeCall && calleeCall->getState() != Call::State::Released);
		         return ASSERTION_PASSED();
	         })
	         .assert_passed()) {
		return nullptr;
	}

	return callerCall;
}

std::shared_ptr<linphone::Call>
CoreClient::callWithEarlyDecline(const std::shared_ptr<CoreClient>& callee,
                                 const std::shared_ptr<linphone::CallParams>& callerCallParams,
                                 const std::shared_ptr<Agent>& externalProxy) {
	return callWithEarlyDecline(*callee, callerCallParams, externalProxy);
}

bool CoreClient::callUpdate(const CoreClient& peer,
                            const std::shared_ptr<linphone::CallParams>& callParams,
                            const std::shared_ptr<Agent>& externalProxy) {
	if (callParams == nullptr) {
		BC_FAIL("Cannot update call without new call params");
	}

	const auto selfCall = mCore->getCurrentCall();
	const auto peerCall = peer.mCore->getCurrentCall();
	if (selfCall == nullptr || peerCall == nullptr) {
		BC_FAIL("Trying to update a call but at least one participant is not currently engaged in one");
		return false;
	}

	CoreAssert asserter{mCore, peer.mCore, mAgent, peer.mAgent};
	if (externalProxy) {
		asserter.registerSteppable(externalProxy);
	}

	// Our peer is set to auto accept the call update so just verify the changes after.
	selfCall->update(callParams);
	BC_ASSERT(selfCall->getState() == linphone::Call::State::Updating);
	BC_ASSERT(peerCall->getState() == linphone::Call::State::StreamsRunning);

	// Wait for the update to be concluded
	if (!asserter
	         .iterateUpTo(10,
	                      [&selfCall = *selfCall] {
		                      FAIL_IF(selfCall.getState() != linphone::Call::State::StreamsRunning);
		                      return ASSERTION_PASSED();
	                      })
	         .assert_passed())
		return false;
	BC_ASSERT(peerCall->getState() == linphone::Call::State::StreamsRunning);

	if (!asserter.waitUntil(12s, assert_data_transmitted(*peerCall, *selfCall, callParams->videoEnabled()))
	         .assert_passed())
		return false;

	return true;
}

bool CoreClient::endCurrentCall(const CoreClient& peer, const std::shared_ptr<Agent>& externalProxy) {
	auto selfCall = mCore->getCurrentCall();
	auto peerCall = peer.mCore->getCurrentCall();
	if (selfCall == nullptr || peerCall == nullptr) {
		BC_FAIL("Trying to end a call, but there is no call currently running");
		return false;
	}

	CoreAssert asserter{mCore, peer.mCore, mAgent, peer.mAgent};
	if (externalProxy) {
		asserter.registerSteppable(externalProxy);
	}

	selfCall->terminate();
	if (!asserter
	         .waitUntil(5s,
	                    [selfCall, peerCall] {
		                    FAIL_IF(selfCall->getState() != linphone::Call::State::Released);
		                    FAIL_IF(peerCall->getState() != linphone::Call::State::Released);
		                    return ASSERTION_PASSED();
	                    })
	         .assert_passed()) {
		BC_ASSERT(selfCall->getState() == linphone::Call::State::Released);
		BC_ASSERT(peerCall->getState() == linphone::Call::State::Released);
		return false;
	}

	return true;
}

bool CoreClient::endCurrentCall(const std::shared_ptr<CoreClient>& peer, const std::shared_ptr<Agent>& externalProxy) {
	return endCurrentCall(*peer, externalProxy);
}

bool CoreClient::endCurrentCall(const flexisip::tester::CoreClient& peer,
                                const flexisip::tester::Server& externalProxy) {
	return endCurrentCall(peer, externalProxy.getAgent());
}

bool CoreClient::endCurrentCall(const std::shared_ptr<CoreClient>& peer,
                                const flexisip::tester::Server& externalProxy) {
	return endCurrentCall(*peer, externalProxy.getAgent());
}

void CoreClient::runFor(std::chrono::milliseconds duration) {
	auto beforePlusDuration = steady_clock::now() + duration;
	while (beforePlusDuration >= steady_clock::now()) {
		mCore->iterate();
	}
}

std::shared_ptr<linphone::Call> CoreClient::invite(const CoreClient& peer) const {
	return mCore->inviteAddress(peer.getAccount()->getContactAddress());
}

std::shared_ptr<linphone::Call> CoreClient::invite(const CoreClient& peer,
                                                   const shared_ptr<const linphone::CallParams>& params) const {
	return mCore->inviteAddressWithParams(peer.getAccount()->getContactAddress(), params);
}

std::shared_ptr<linphone::Call> CoreClient::invite(const string& aor,
                                                   const shared_ptr<const linphone::CallParams>& params) const {
	return params ? mCore->inviteWithParams(aor, params) : mCore->invite(aor);
}

std::optional<ClientCall> CoreClient::getCurrentCall() const {
	return ClientCall::tryFrom(mCore->getCurrentCall());
}

std::shared_ptr<linphone::CallLog> CoreClient::getCallLog() const {
	const auto& current_call = mCore->getCurrentCall();
	if (!current_call) return nullptr;
	return current_call->getCallLog();
}

int CoreClient::getTcpPort() const {
	auto port = mCore->getTransportsUsed()->getTcpPort();
	if (port != LC_SIP_TRANSPORT_DONTBIND) return port;

	// Force-set-up TCP listening port
	auto transports = mCore->getTransports();
	transports->setTcpPort(LC_SIP_TRANSPORT_RANDOM);
	mCore->setTransports(transports);
	return mCore->getTransportsUsed()->getTcpPort();
}

std::list<std::shared_ptr<linphone::ChatMessage>> CoreClient::getChatMessages() const {
	const auto& chatRooms = getCore()->getChatRooms();
	if (chatRooms.empty()) {
		return {};
	}
	return chatRooms.begin()->get()->getHistory(0);
}

void CoreClient::disconnect() const {
	mCore->setNetworkReachable(false);
}
void CoreClient::reconnect() const {
	mCore->setNetworkReachable(true);
}
void CoreClient::refreshRegisters() const {
	mCore->refreshRegisters();
}

ChatRoomBuilder CoreClient::chatroomBuilder() const {
	return ChatRoomBuilder(*this);
}
CallBuilder CoreClient::callBuilder() const {
	return CallBuilder(*this);
}

void CoreClient::setRoute(const std::string& host, const std::string& port) {
	auto accountParams = mAccount->getParams()->clone();
	auto routeAddr = linphone::Factory::get()->createAddress(host);
	routeAddr->setPort(std::stoi(port));
	accountParams->setServerAddress(routeAddr);
	mAccount->setParams(accountParams);
	mCore->setDefaultAccount(mAccount);
}

} // namespace flexisip::tester