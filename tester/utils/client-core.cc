/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <chrono>
#include <iostream>

#include <bctoolbox/tester.h>

#include <linphone/core.h>

#include <mediastreamer2/mediastream.h>

#include "flexisip/logmanager.hh"
#include "flexisip/module-router.hh"

#include "asserts.hh"
#include "core-assert.hh"

#include "client-core.hh"
#include "tester.hh"

using namespace std;
using namespace std::chrono;
using namespace linphone;

namespace flexisip {
namespace tester {

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

ClientBuilder::ClientBuilder(const std::string& me)
    : mFactory(linphone::Factory::get()), mMe(mFactory->createAddress(me)) {
	auto configLinphone = Factory::get()->createConfig("");
	configLinphone->setBool("logging", "disable_stdout", true);
	mCore = mFactory->createCoreWithConfig(configLinphone, nullptr);
	mCore->setPrimaryContact(me);

	mAccountParams = mCore->createAccountParams();

	{
		auto config = mCore->getConfig();
		config->setString("storage", "backend", "sqlite3");
		config->setString("storage", "uri", ":memory:");
		config->setString("storage", "call_logs_db_uri", "null");
	}
	{
		auto clientTransport = mFactory->createTransports();
		clientTransport->setTcpPort(-2); // -2 for LC_SIP_TRANSPORT_DONTBIND)
		mCore->setTransports(clientTransport);
	}

	mCore->setZrtpSecretsFile("null");
	mCore->setAudioPort(-1);
	mCore->setVideoPort(-1);
	mCore->setUseFiles(true);
	mCore->enableVideoCapture(true);  // We must be able to simulate capture to make video calls
	mCore->enableVideoDisplay(false); // No need to bother displaying the received video
	// final check on call successfully established is based on bandwidth used,
	// so use file as input to make sure there is some traffic
	{
		auto helloPath = bcTesterRes("sounds/hello8000.wav");
		if (bctbx_file_exist(helloPath.c_str()) != 0) {
			BC_FAIL("Unable to find resource sound, did you forget to use --resource-dir option?");
		} else {
			mCore->setPlayFile(helloPath);
		}
	}

	{ // Use Mire as camera for video stream
		auto msFactory = linphone_core_get_ms_factory(mCore->cPtr());
		auto webCamMan = ms_factory_get_web_cam_manager(msFactory);
		auto mire_desc = ms_mire_webcam_desc_get();
		auto mire = ms_web_cam_new(mire_desc);
		ms_web_cam_manager_add_cam(webCamMan, mire);
		mCore->setVideoDevice("Mire: Mire (synthetic moving picture)");
	}
	{
		auto policy = mFactory->createVideoActivationPolicy();
		policy->setAutomaticallyAccept(true);
		policy->setAutomaticallyInitiate(
		    false); // requires explicit settings in the parameters to initiate a video call
		mCore->setVideoActivationPolicy(policy);
	}

	{
		// Clients register to the first of the list of transports read in the proxy configuration
		auto route = mFactory->createAddress(flexisip::GenericManager::get()
		                                         ->getRoot()
		                                         ->get<flexisip::GenericStruct>("global")
		                                         ->get<flexisip::ConfigStringList>("transports")
		                                         ->read()
		                                         .front());

		mAccountParams->setIdentityAddress(mMe);
		mAccountParams->enableRegister(true);
		mAccountParams->setServerAddress(route);
		mAccountParams->setRoutesAddresses({route});
	}
}

ClientBuilder& ClientBuilder::setPassword(const std::string& password) {
	if (!password.empty()) {
		mCore->addAuthInfo(mFactory->createAuthInfo(mMe->getUsername(), "", password, "", "", mMe->getDomain()));
	}
	return *this;
}

ClientBuilder& ClientBuilder::setCustomContact(const std::string& contact) {
	mAccountParams->setCustomContact(mCore->createAddress(contact));
	return *this;
}

ClientBuilder& ClientBuilder::setPushParams(const pushnotification::RFC8599PushParams& params) {
	mAccountParams->setContactUriParameters(params.toUriParams());
	return *this;
}

ClientBuilder& ClientBuilder::setApplePushConfig() {
	const auto pushConfig = mAccountParams->getPushNotificationConfig();
	pushConfig->setProvider("apns");
	pushConfig->setPrid("AAAAAAAAAAAAAAAAAAAA7DF897B431746F49E271E66BBF655C13C2BBD70FFC18:remote&"
	                    "8A499FF20722E0C47A4F52657554B22E2AE6BF45AC91AAAAAAAAAAAAAAAAAAAA:voip");
	pushConfig->setParam("ABCD1234.org.linphone.phone.remote&voip");
	mAccountParams->setPushNotificationAllowed(true);
	mCore->enablePushNotification(true);

	return *this;
}

CoreClient ClientBuilder::registerTo(const shared_ptr<Server>& server) {
	return CoreClient(std::move(*this), server);
}

CoreClient::CoreClient(ClientBuilder&& builder, const shared_ptr<Server>& server)
    : mCore(std::move(builder.mCore)), mAccount(mCore->createAccount(builder.mAccountParams)),
      mMe(std::move(builder.mMe)), mServer(server) {
	mCore->start();
	mCore->addAccount(mAccount);
	CoreAssert({mCore}, server->getAgent())
	    .waitUntil(std::chrono::seconds(3),
	               [&account = mAccount] {
		               FAIL_IF(account->getState() != linphone::RegistrationState::Ok);
		               return ASSERTION_PASSED();
	               })
	    .assert_passed();
}

CoreClient::~CoreClient() {
	if (mAccount != nullptr) {
		mCore->clearAccounts();
		CoreAssert({mCore}, mServer->getAgent())
		    .wait([&account = mAccount] {
			    FAIL_IF(account->getState() != linphone::RegistrationState::Cleared);
			    return ASSERTION_PASSED();
		    })
		    .assert_passed();
	}
	if (mCore) {
		mCore->stopAsync(); // stopAsync is not really async, we must clear the account first or it will wait for the
		                    // unregistration on server
		CoreAssert({mCore}, mServer->getAgent())
		    .wait([&core = mCore] {
			    FAIL_IF(core->getGlobalState() != linphone::GlobalState::Off);
			    return ASSERTION_PASSED();
		    })
		    .assert_passed();
	}
}

std::shared_ptr<linphone::Call> CoreClient::callVideo(const std::shared_ptr<CoreClient>& callee,
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
	vector<shared_ptr<Core>> coreList = {mCore, calleeCore};

	vector<shared_ptr<Core>> idleCoreList = {mCore};
	for (const auto& calleeDevice : calleeIdleDevices) {
		idleCoreList.push_back(calleeDevice->getCore());
	}

	// Check call get the incoming call and caller is in OutgoingRinging state
	if (!BC_ASSERT_TRUE(callee.hasReceivedCallFrom(*this))) {
		return nullptr;
	}
	if (!calleeIdleDevices.empty()) {
		// If callee also have idle devices check that they are ringing too
		if (!BC_ASSERT_TRUE(CoreAssert(idleCoreList, mServer->getAgent()).wait([calleeIdleDevices] {
			    return all_of(calleeIdleDevices.cbegin(), calleeIdleDevices.cend(),
			                  [](const shared_ptr<CoreClient>& idleDevice) {
				                  return idleDevice->getCore()->getCurrentCall() != nullptr &&
				                         idleDevice->getCore()->getCurrentCall()->getState() ==
				                             linphone::Call::State::IncomingReceived;
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

	if (!BC_ASSERT_TRUE(CoreAssert(coreList, mServer->getAgent()).wait([callerCall] {
		    return (callerCall->getState() == linphone::Call::State::OutgoingRinging);
	    }))) {
		return nullptr;
	}

	// Callee answer the call
	if (!BC_ASSERT_TRUE(calleeCall->acceptWithParams(calleeCallParams) == 0)) {
		return nullptr;
	};

	if (!BC_ASSERT_TRUE(
	        CoreAssert(coreList, mServer->getAgent()).waitUntil(std::chrono::seconds(5), [calleeCall, callerCall] {
		        return (callerCall->getState() == linphone::Call::State::StreamsRunning &&
		                calleeCall->getState() == linphone::Call::State::StreamsRunning);
	        }))) {
		BC_ASSERT_TRUE(callerCall->getState() == linphone::Call::State::StreamsRunning);
		BC_ASSERT_TRUE(calleeCall->getState() == linphone::Call::State::StreamsRunning);
		return nullptr;
	}
	if (!calleeIdleDevices.empty()) {
		// If callee also have idle devices check that they are not ringing anymore / got cancelled.
		if (!BC_ASSERT_TRUE(CoreAssert(idleCoreList, mServer->getAgent()).wait([calleeIdleDevices] {
			    return all_of(
			        calleeIdleDevices.cbegin(), calleeIdleDevices.cend(), [](const shared_ptr<CoreClient>& idleDevice) {
				        return idleDevice->getCore()->getCurrentCall() == nullptr ||
				               idleDevice->getCore()->getCurrentCall()->getState() == linphone::Call::State::End ||
				               idleDevice->getCore()->getCurrentCall()->getState() == linphone::Call::State::Released;
			        });
		    }))) {
			return nullptr;
		}
	}

	if (!CoreAssert(coreList, mServer->getAgent())
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

	auto addressWithoutGr = callee->getAccount()->getContactAddress();
	addressWithoutGr->removeUriParam("gr");
	auto callerCall = mCore->inviteAddressWithParams(addressWithoutGr, callParams);

	if (callerCall == nullptr) {
		BC_FAIL("Invite failed");
		return nullptr;
	}

	vector<shared_ptr<linphone::Core>> coreList = {mCore};
	const auto& agent = mServer->getAgent();
	if (isCalleeAway) {
		// Register callee to update the registrar DB
		if (!BC_ASSERT_TRUE(CoreAssert(coreList, agent).wait([callee] {
			    return callee->getAccount()->getState() == linphone::RegistrationState::Ok;
		    }))) {
			return nullptr;
		}

		callee->getCore()->setNetworkReachable(false);

		// But simulate that callee goes offline
		coreList = {mCore};
	} else {
		coreList.push_back(callee->getCore());
	}

	// Check call get the incoming call and caller is in OutgoingRinging state
	if (!BC_ASSERT_TRUE(CoreAssert(coreList, agent)
	                        .waitUntil(seconds(10), [&callerCall, isCalleeAway, &agent, &callee] {
		                        if (isCalleeAway) {
			                        const auto& moduleRouter =
			                            dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
			                        return callerCall->getState() == linphone::Call::State::OutgoingProgress &&
			                               moduleRouter->mStats.mCountCallForks->start->read() == 1;
		                        } else {

			                        return callerCall->getState() == linphone::Call::State::OutgoingRinging &&
			                               callee->getCore()->getCurrentCall() &&
			                               callee->getCore()->getCurrentCall()->getState() ==
			                                   Call::State::IncomingReceived;
		                        }
	                        }))) {
		return nullptr;
	}

	callerCall->terminate();

	if (!BC_ASSERT_TRUE(CoreAssert(coreList, agent).wait([&callerCall, isCalleeAway, &callee] {
		    return callerCall->getState() == linphone::Call::State::Released &&
		           (isCalleeAway || !callee->getCore()->getCurrentCall() ||
		            callee->getCore()->getCurrentCall()->getState() == Call::State::Released);
	    }))) {
		return nullptr;
	}
	return callerCall;
}

bool CoreClient::callUpdate(const std::shared_ptr<CoreClient>& peer,
                            const std::shared_ptr<linphone::CallParams>& callParams) {
	if (callParams == nullptr) {
		BC_FAIL("Cannot update call without new call params");
	}

	auto selfCall = mCore->getCurrentCall();
	auto peerCall = peer->getCore()->getCurrentCall();
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
	if (!BC_ASSERT_TRUE(CoreAssert({mCore, peer->getCore()}, mServer->getAgent())
	                        .iterateUpTo(5,
	                                     [&selfCall = *selfCall] {
		                                     FAIL_IF(selfCall.getState() != State::StreamsRunning);
		                                     return ASSERTION_PASSED();
	                                     })
	                        .assert_passed()))
		return false;
	BC_ASSERT_TRUE(peerCall->getState() == State::StreamsRunning);

	if (!CoreAssert({mCore, peer->getCore()}, mServer->getAgent())
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
	if (!BC_ASSERT_TRUE(
	        CoreAssert({mCore, peerCore}, mServer->getAgent()).waitUntil(std::chrono::seconds(5), [selfCall, peerCall] {
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
	return CoreAssert({mCore, peer.getCore()}, mServer->getAgent()).waitUntil(mCallInviteReceivedDelay, [this] {
		const auto& current_call = mCore->getCurrentCall();
		FAIL_IF(current_call == nullptr);
		FAIL_IF(current_call->getState() != linphone::Call::State::IncomingReceived);
		return ASSERTION_PASSED();
	});
}

std::shared_ptr<linphone::Call> CoreClient::invite(const CoreClient& peer) const {
	return mCore->inviteAddress(peer.getAccount()->getContactAddress());
}

std::shared_ptr<linphone::CallLog> CoreClient::getCallLog() const {
	const auto& current_call = mCore->getCurrentCall();
	if (!current_call) return nullptr;
	return current_call->getCallLog();
}

std::list<std::shared_ptr<linphone::ChatMessage>> CoreClient::getChatMessages() {
	const auto& chatRooms = getCore()->getChatRooms();
	if (chatRooms.empty()) {
		return {};
	}
	return chatRooms.begin()->get()->getHistory(0);
}

} // namespace tester
} // namespace flexisip
