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

#include <chrono>
#include <memory>
#include <optional>
#include <stdexcept>

#include <bctoolbox/tester.h>
#include <linphone++/address.hh>
#include <linphone++/call.hh>
#include <linphone++/call_params.hh>

#include "flexisip/module-router.hh"

#include "asserts.hh"
#include "core-assert.hh"

#include "client-core.hh"
#include "linphone/misc.h"
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
	return [&, videoOriginallyEnabled] {
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

std::shared_ptr<linphone::Core> minimalCore(linphone::Factory& factory) {
	auto dataDir = std::string(bc_tester_get_writable_dir_prefix());
	auto linphoneConfig = factory.createConfig("");

	linphoneConfig->setBool("logging", "disable_stdout", true);
	linphoneConfig->setString("storage", "call_logs_db_uri", dataDir + "/null");
	linphoneConfig->setString("storage", "zrtp_secrets_db_uri", dataDir + "/null");
	linphoneConfig->setString("storage", "uri", dataDir + "/null");
	linphoneConfig->setString("lime", "x3dh_db_path", ":memory:");
	auto core = factory.createCoreWithConfig(linphoneConfig, nullptr);
	auto clientTransport = factory.createTransports();
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
		mCore->stopAsync(); // stopAsync is not really async, we must clear the account first or it will wait for the
		                    // unregistration on server
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
                                                      const std::shared_ptr<linphone::CallParams>& calleeCallParams) {
	return callVideo(*callee, callerCallParams, calleeCallParams);
}

std::shared_ptr<linphone::Call> CoreClient::callVideo(const CoreClient& callee,
                                                      const std::shared_ptr<linphone::CallParams>& callerCallParams,
                                                      const std::shared_ptr<linphone::CallParams>& calleeCallParams) {
	std::shared_ptr<linphone::CallParams> callParams = callerCallParams;
	if (callParams == nullptr) {
		callParams = mCore->createCallParams(nullptr);
	}
	callParams->enableVideo(true);
	return call(callee, callParams, calleeCallParams);
}

std::shared_ptr<linphone::Call> CoreClient::call(const CoreClient& callee,
                                                 const std::shared_ptr<const linphone::Address>& calleeAddress,
                                                 const std::shared_ptr<linphone::CallParams>& callerCallParams,
                                                 const std::shared_ptr<linphone::CallParams>& calleeCallParams,
                                                 const std::vector<std::shared_ptr<CoreClient>>& calleeIdleDevices) {
	shared_ptr<CallParams> callParams = callerCallParams;
	if (callParams == nullptr) {
		callParams = mCore->createCallParams(nullptr);
	}

	auto _calleeAddress = calleeAddress->clone();
	_calleeAddress->removeUriParam("gr");
	auto callerCall = mCore->inviteAddressWithParams(_calleeAddress, callParams);

	if (callerCall == nullptr) {
		BC_FAIL("Invite failed");
		return nullptr;
	}

	const auto calleeCore = callee.getCore();
	CoreAssert asserter{mCore, mAgent, calleeCore};
	CoreAssert idleAsserter{mCore, mAgent};
	for (const auto& calleeDevice : calleeIdleDevices) {
		idleAsserter.registerSteppable(calleeDevice);
	}

	// Check call get the incoming call and caller is in OutgoingRinging state
	if (!BC_ASSERT_TRUE(callee.hasReceivedCallFrom(*this))) {
		return nullptr;
	}
	if (!calleeIdleDevices.empty()) {
		// If callee also have idle devices check that they are ringing too
		if (!BC_ASSERT_TRUE(idleAsserter.wait([calleeIdleDevices] {
			    return all_of(
			        calleeIdleDevices.cbegin(), calleeIdleDevices.cend(), [](const shared_ptr<CoreClient>& idleDevice) {
				        return idleDevice->getCurrentCall() != std::nullopt &&
				               idleDevice->getCurrentCall()->getState() == linphone::Call::State::IncomingReceived;
			        });
		    }))) {
			return nullptr;
		}
	}

	auto calleeCall = calleeCore->getCurrentCall();
	if (calleeCall == nullptr) {
		BC_FAIL("No call received");
		return nullptr;
	}

	if (!BC_ASSERT_TRUE(asserter.wait(
	        [callerCall] { return (callerCall->getState() == linphone::Call::State::OutgoingRinging); }))) {
		return nullptr;
	}

	// Callee answer the call
	if (!BC_ASSERT_TRUE(calleeCall->acceptWithParams(calleeCallParams) == 0)) {
		return nullptr;
	};

	if (!BC_ASSERT_TRUE(asserter.waitUntil(std::chrono::seconds(5), [calleeCall, callerCall] {
		    return (callerCall->getState() == linphone::Call::State::StreamsRunning &&
		            calleeCall->getState() == linphone::Call::State::StreamsRunning);
	    }))) {
		BC_ASSERT_TRUE(callerCall->getState() == linphone::Call::State::StreamsRunning);
		BC_ASSERT_TRUE(calleeCall->getState() == linphone::Call::State::StreamsRunning);
		return nullptr;
	}
	if (!calleeIdleDevices.empty()) {
		// If callee also have idle devices check that they are not ringing anymore / got cancelled.
		if (!BC_ASSERT_TRUE(idleAsserter.wait([calleeIdleDevices] {
			    return all_of(calleeIdleDevices.cbegin(), calleeIdleDevices.cend(),
			                  [](const shared_ptr<CoreClient>& idleDevice) {
				                  return idleDevice->getCurrentCall() == std::nullopt ||
				                         idleDevice->getCurrentCall()->getState() == linphone::Call::State::End ||
				                         idleDevice->getCurrentCall()->getState() == linphone::Call::State::Released;
			                  });
		    }))) {
			return nullptr;
		}
	}

	if (!asserter
	         .waitUntil(std::chrono::seconds(12),
	                    assert_data_transmitted(*calleeCall, *callerCall, callParams->videoEnabled()))
	         .assert_passed()) {
		return nullptr;
	}

	return callerCall;
}

std::shared_ptr<linphone::Call> CoreClient::call(const CoreClient& callee,
                                                 const std::shared_ptr<linphone::CallParams>& callerCallParams,
                                                 const std::shared_ptr<linphone::CallParams>& calleeCallParams,
                                                 const std::vector<std::shared_ptr<CoreClient>>& calleeIdleDevices) {
	auto calleeAddress = callee.getAccount()->getParams()->getIdentityAddress();
	return call(callee, calleeAddress, callerCallParams, calleeCallParams, calleeIdleDevices);
}

std::shared_ptr<linphone::Call> CoreClient::call(const std::shared_ptr<CoreClient>& callee,
                                                 const std::shared_ptr<linphone::CallParams>& callerCallParams,
                                                 const std::shared_ptr<linphone::CallParams>& calleeCallParams,
                                                 const std::vector<std::shared_ptr<CoreClient>>& calleeIdleDevices) {
	return call(*callee, callerCallParams, calleeCallParams, calleeIdleDevices);
}

std::shared_ptr<linphone::Call>
CoreClient::callWithEarlyCancel(const std::shared_ptr<CoreClient>& callee,
                                const std::shared_ptr<linphone::CallParams>& callerCallParams,
                                bool isCalleeAway) {
	shared_ptr<linphone::CallParams> callParams = callerCallParams;
	if (callParams == nullptr) {
		callParams = mCore->createCallParams(nullptr);
	}

	auto addressWithoutGr = callee->getAccount()->getContactAddress()->clone();
	addressWithoutGr->removeUriParam("gr");
	auto callerCall = mCore->inviteAddressWithParams(addressWithoutGr, callParams);

	if (callerCall == nullptr) {
		BC_FAIL("Invite failed");
		return nullptr;
	}

	CoreAssert asserter{mCore, mAgent};
	if (isCalleeAway) {
		callee->disconnect();
	} else {
		asserter.registerSteppable(callee);
	}

	// Check call get the incoming call and caller is in OutgoingRinging state
	if (isCalleeAway) {
		if (!BC_ASSERT_TRUE(asserter.waitUntil(seconds(10), [&callerCall, agent = &mAgent] {
			    const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
			    return callerCall->getState() == linphone::Call::State::OutgoingProgress &&
			           moduleRouter->mStats.mCountCallForks->start->read() == 1;
		    }))) {
			return nullptr;
		}
	} else {
		if (!BC_ASSERT_TRUE(asserter.waitUntil(seconds(15), [&callerCall, &callee] {
			    return callerCall->getState() == linphone::Call::State::OutgoingRinging && callee->getCurrentCall() &&
			           callee->getCurrentCall()->getState() == Call::State::IncomingReceived;
		    }))) {
			return nullptr;
		}
	}

	callerCall->terminate();

	if (!BC_ASSERT_TRUE(asserter.wait([&callerCall, isCalleeAway, &callee] {
		    return callerCall->getState() == linphone::Call::State::Released &&
		           (isCalleeAway || !callee->getCurrentCall() ||
		            callee->getCurrentCall()->getState() == Call::State::Released);
	    }))) {
		return nullptr;
	}
	return callerCall;
}

std::shared_ptr<linphone::Call>
CoreClient::callWithEarlyDecline(const std::shared_ptr<CoreClient>& callee,
                                 const std::shared_ptr<linphone::CallParams>& callerCallParams) {
	shared_ptr<linphone::CallParams> callParams = callerCallParams;
	if (callParams == nullptr) {
		callParams = mCore->createCallParams(nullptr);
	}

	auto addressWithoutGr = callee->getAccount()->getContactAddress()->clone();
	addressWithoutGr->removeUriParam("gr");
	auto callerCall = mCore->inviteAddressWithParams(addressWithoutGr, callParams);

	if (callerCall == nullptr) {
		BC_FAIL("Invite failed");
		return nullptr;
	}

	CoreAssert asserter{mCore, mAgent};
	asserter.registerSteppable(callee);

	// Check call get the incoming call and caller is in OutgoingRinging state
	if (!BC_ASSERT_TRUE(asserter.waitUntil(seconds(10), [&callerCall, &callee] {
		    return callerCall->getState() == linphone::Call::State::OutgoingRinging && callee->getCurrentCall() &&
		           callee->getCurrentCall()->getState() == Call::State::IncomingReceived;
	    }))) {
		return nullptr;
	}

	callee->getCurrentCall()->decline(linphone::Reason::Declined);

	if (!BC_ASSERT_TRUE(asserter.wait([&callerCall, &callee] {
		    return callerCall->getState() == linphone::Call::State::Released &&
		           (!callee->getCurrentCall() || callee->getCurrentCall()->getState() == Call::State::Released);
	    }))) {
		return nullptr;
	}
	return callerCall;
}

bool CoreClient::callUpdate(const CoreClient& peer, const std::shared_ptr<linphone::CallParams>& callParams) {
	if (callParams == nullptr) {
		BC_FAIL("Cannot update call without new call params");
	}

	auto peerCore = peer.getCore();
	auto selfCall = mCore->getCurrentCall();
	auto peerCall = peerCore->getCurrentCall();
	if (selfCall == nullptr || peerCall == nullptr) {
		BC_FAIL("Trying to update a call but at least one participant is not currently engaged in one");
		return false;
	}

	// peer is set to auto accept update so just check the changes after
	selfCall->update(callParams);
	using State = linphone::Call::State;
	BC_ASSERT_TRUE(selfCall->getState() == State::Updating);
	BC_ASSERT_TRUE(peerCall->getState() == State::StreamsRunning);

	// Wait for the update to be concluded
	if (!BC_ASSERT_TRUE(CoreAssert(mCore, peerCore, mAgent)
	                        .iterateUpTo(5,
	                                     [&selfCall = *selfCall] {
		                                     FAIL_IF(selfCall.getState() != State::StreamsRunning);
		                                     return ASSERTION_PASSED();
	                                     })
	                        .assert_passed()))
		return false;
	BC_ASSERT_TRUE(peerCall->getState() == State::StreamsRunning);

	if (!CoreAssert(mCore, peerCore, mAgent)
	         .waitUntil(std::chrono::seconds(12),
	                    assert_data_transmitted(*peerCall, *selfCall, callParams->videoEnabled()))
	         .assert_passed())
		return false;

	return true;
}

bool CoreClient::endCurrentCall(const CoreClient& peer) {
	const auto peerCore = peer.getCore();
	auto selfCall = mCore->getCurrentCall();
	auto peerCall = peerCore->getCurrentCall();
	if (selfCall == nullptr || peerCall == nullptr) {
		BC_FAIL("Trying to end call but No current call running");
		return false;
	}
	mCore->getCurrentCall()->terminate();
	if (!BC_ASSERT_TRUE(CoreAssert(mCore, peerCore, mAgent).waitUntil(std::chrono::seconds(5), [selfCall, peerCall] {
		    return (selfCall->getState() == linphone::Call::State::Released &&
		            peerCall->getState() == linphone::Call::State::Released);
	    }))) {
		BC_ASSERT_TRUE(selfCall->getState() == linphone::Call::State::Released);
		BC_ASSERT_TRUE(peerCall->getState() == linphone::Call::State::Released);
		return false;
	}
	return true;
}

bool CoreClient::endCurrentCall(const std::shared_ptr<CoreClient>& peer) {
	return endCurrentCall(*peer);
}

void CoreClient::runFor(std::chrono::milliseconds duration) {
	auto beforePlusDuration = steady_clock::now() + duration;
	while (beforePlusDuration >= steady_clock::now()) {
		mCore->iterate();
	}
}

AssertionResult CoreClient::hasReceivedCallFrom(const CoreClient& peer) const {
	return CoreAssert(mCore, peer.getCore(), mAgent).waitUntil(mCallInviteReceivedDelay, [this] {
		const auto& current_call = mCore->getCurrentCall();
		FAIL_IF(current_call == nullptr);
		FAIL_IF(current_call->getState() != linphone::Call::State::IncomingReceived);
		return ASSERTION_PASSED();
	});
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
	auto maybeCall = mCore->getCurrentCall();
	if (maybeCall == nullptr) return {};
	return maybeCall;
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

std::list<std::shared_ptr<linphone::ChatMessage>> CoreClient::getChatMessages() {
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
