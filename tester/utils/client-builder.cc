/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "client-builder.hh"

#include <stdexcept>

#include <linphone/core.h>

#include "pushnotification/rfc8599-push-params.hh"
#include "tester.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/string-utils.hh"

namespace flexisip {
namespace tester {

ClientBuilder::ClientBuilder(const Server& server)
    : mFactory(linphone::Factory::get()), mCoreTemplate(mFactory->createCore("", "", nullptr)),
      mAccountParams(mCoreTemplate->createAccountParams()), mServer(server), mLimeX3DH(OnOff::On),
      mSendVideo(OnOff::Off), mReceiveVideo(OnOff::Off), mSendRtcp(OnOff::On) {
}

CoreClient ClientBuilder::build(const std::string& baseAddress) const {
	const std::string& me = StringUtils::startsWith(baseAddress, "sip:") ? baseAddress : "sip:" + baseAddress;
	auto myAddress = mFactory->createAddress(me);
	if (!myAddress) {
		std::ostringstream msg{};
		msg << "Invalid contact adress '" << me << "'";
		bc_assert(__FILE__, __LINE__, false, msg.str().c_str());
		throw std::invalid_argument{msg.str()};
	}

	auto core = minimal_core(*mFactory);
	core->setPrimaryContact(me);

	auto accountParams = mAccountParams->clone();
	accountParams->setIdentityAddress(myAddress);
	accountParams->enableRegister(true);
	{
		// Clients register to the first of the list of transports read in the proxy configuration
		auto route = mFactory->createAddress(flexisip::GenericManager::get()
		                                         ->getRoot()
		                                         ->get<flexisip::GenericStruct>("global")
		                                         ->get<flexisip::ConfigStringList>("transports")
		                                         ->read()
		                                         .front());
		// Fix port if auto-bound
		if (route->getPort() == 0) {
			route->setPort(std::atoi(mServer.getFirstPort()));
		}

		accountParams->setServerAddress(route);
		accountParams->setRoutesAddresses({route});
	}
	auto account = core->createAccount(accountParams);
	core->addAccount(account);
	core->enablePushNotification(accountParams->getPushNotificationAllowed());

	if (!mPassword.empty()) {
		core->addAuthInfo(
		    mFactory->createAuthInfo(myAddress->getUsername(), "", mPassword, "", "", myAddress->getDomain()));
	}

	core->enableLimeX3Dh(bool(mLimeX3DH));

	{
		auto config = core->getConfig();
		config->setString("storage", "backend", "sqlite3");
		config->setString("storage", "uri", ":memory:");
		config->setString("storage", "call_logs_db_uri", "null");
		config->setBool("rtp", "rtcp_enabled", bool(mSendRtcp));
	}

	core->setZrtpSecretsFile("null");
	core->setAudioPort(-1);
	core->setVideoPort(-1);
	core->setUseFiles(true);
	// final check on call successfully established is based on bandwidth used,
	// so use file as input to make sure there is some traffic
	{
		auto helloPath = bcTesterRes("sounds/hello8000.wav");
		if (bctbx_file_exist(helloPath.c_str()) != 0) {
			BC_FAIL("Unable to find resource sound, did you forget to use --resource-dir option?");
		} else {
			core->setPlayFile(helloPath);
		}
	}

	{
		auto policy = mFactory->createVideoActivationPolicy();
		policy->setAutomaticallyAccept(true);
		policy->setAutomaticallyInitiate(
		    false); // requires explicit settings in the parameters to initiate a video call
		core->setVideoActivationPolicy(policy);
	}

	if (bool(mSendVideo)) {
		auto msFactory = linphone_core_get_ms_factory(core->cPtr());
		auto webCamMan = ms_factory_get_web_cam_manager(msFactory);
		auto mire_desc = ms_mire_webcam_desc_get();
		auto mire = ms_web_cam_new(mire_desc);
		ms_web_cam_manager_add_cam(webCamMan, mire);
		core->setVideoDevice("Mire: Mire (synthetic moving picture)");
		core->enableVideoCapture(true);
	} else {
		core->enableVideoCapture(false);
	}

	if (bool(mReceiveVideo)) {
		// Enabling display enables video decoding, letting tests setup hooks to get notified of frames decoded.
		core->enableVideoDisplay(true);
		// The MSExtDisplay filter is designed to forward buffers to another layer, but when it is not setup it just
		// does nothing and acts as a void sink.
		core->setVideoDisplayFilter("MSExtDisplay");
	} else {
		core->enableVideoDisplay(false);
	}

	core->start();
	CoreAssert(core, mServer)
	    .iterateUpTo(0x10,
	                 [&account] {
		                 FAIL_IF(account->getState() != linphone::RegistrationState::Ok);
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();
	return CoreClient(std::move(core), std::move(account), std::move(myAddress), mServer);
}

ClientBuilder& ClientBuilder::setConferenceFactoryUri(const std::string& uri) {
	mAccountParams->setConferenceFactoryUri(uri);
	return *this;
}

void ClientBuilder::setLimeX3DH(OnOff state) {
	mLimeX3DH = state;
}

ClientBuilder& ClientBuilder::setVideoReceive(OnOff value) {
	mReceiveVideo = value;
	return *this;
}
ClientBuilder& ClientBuilder::setVideoSend(OnOff value) {
	mSendVideo = value;
	return *this;
}

ClientBuilder& ClientBuilder::setRtcpSend(OnOff value) {
	mSendRtcp = value;
	return *this;
}

ClientBuilder& ClientBuilder::setCustomContact(const std::string& contact) {
	mAccountParams->setCustomContact(mFactory->createAddress(contact));
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

	return *this;
}

ClientBuilder& ClientBuilder::setApplePushConfigRemoteOnly() {
	const auto pushConfig = mAccountParams->getPushNotificationConfig();
	pushConfig->setProvider("apns");
	pushConfig->setPrid("AAAAAAAAAAAAAAAAAAAA7DF897B431746F49E271E66BBF655C13C2BBD70FFC19:remote");
	pushConfig->setParam("ABCD1234.org.linphone.phone.remote");
	mAccountParams->setPushNotificationAllowed(true);

	return *this;
}

ClientBuilder& ClientBuilder::setPassword(const std::string_view& password) {
	mPassword = password;
	return *this;
}

} // namespace tester
} // namespace flexisip
