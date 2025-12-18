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

#include "voicemail-server.hh"

#include "linphone++/linphone.hh"

#include "call-handler.hh"
#include "exceptions/bad-configuration.hh"
#include "flexisip/configmanager.hh"
#include "flexisip/flexisip-version.h"
#include "flexisip/utils/sip-uri.hh"
#include "utils/configuration/media.hh"
#include "utils/configuration/transport.hh"
#include "utils/digest.hh"

using namespace std;

namespace flexisip {

namespace {
string getCallKey(const std::shared_ptr<linphone::Call>& call) {
	return Sha256{}.compute<string>(call->getCallLog()->getCallId() + call->getRemoteAddress()->asString());
}
} // namespace

void VoicemailServer::_init() {
	const auto* config = mConfigManager->getRoot()->get<GenericStruct>("voicemail-server");

	const auto* announcementParam = config->get<ConfigString>("announcement-file-path");
	const auto announcementParamName = announcementParam->getCompleteName();
	mAnnouncementFile = announcementParam->read();
	if (mAnnouncementFile.empty()) throw BadConfigurationEmpty{announcementParam};
	if (!exists(mAnnouncementFile))
		throw BadConfiguration{announcementParamName + " (" + mAnnouncementFile.string() + ") does not exists"};

	const auto factory = linphone::Factory::get();

	const auto transport = factory->createTransports();
	const auto* transportParam = config->get<ConfigString>("transport");
	if (transportParam->read().empty()) throw BadConfigurationEmpty{transportParam};
	configuration_utils::configureTransport(transport, transportParam, {"", "udp", "tcp"});
	mTransport = SipUri{transportParam->read()};

	// Linphone-sdk configuration.
	auto configLinphone = factory->createConfig("");
	// Do not reject INVITE requests that contain an already known Call-ID.
	configLinphone->setBool("sip", "reject_duplicated_calls", false);
	// Disable the possibility for UACs to subscribe to the local conference events.
	configLinphone->setBool("misc", "conference_event_log_enabled", false);
	// Remove call logs and disable db to avoid memory accumulation
	configLinphone->setInt("misc", "history_max_size", 0);
	// Prevent the default log handler from being reset while LinphoneCore construction.
	configLinphone->setBool("logging", "disable_stdout", true);
	// Do not try to change call parameters if a message seems malformed.
	configLinphone->setBool("sip", "account_strict_matching", true);

	mCore = factory->createCoreWithConfig(configLinphone, nullptr);
	// Disable DB storage to avoid memory accumulation
	mCore->enableDatabase(false);
	// Maximum number of calls the server can answer simultaneously.
	const auto* maxCallsParameter = config->get<ConfigInt>("max-calls");
	const auto maxCalls = maxCallsParameter->read();
	if (maxCalls <= 0) {
		throw BadConfigurationValue{maxCallsParameter, "parameter must be strictly positive"};
	}
	mCore->setMaxCalls(maxCalls);
	mCore->setInCallTimeout(300); // 5 minutes
	mCore->setNortpTimeout(10);   // 10 seconds
	// Allow to handle multiple calls at once
	mCore->setMediaResourceMode(linphone::MediaResourceMode::Shared);
	// No sound card shall be used in calls.
	mCore->setUseFiles(true);
	mCore->enableEchoCancellation(false);

	const auto audioPortMin = config->get<ConfigIntRange>("audio-port")->readMin();
	const auto audioPortMax = config->get<ConfigIntRange>("audio-port")->readMax();
	configuration_utils::setMediaPort(audioPortMin, audioPortMax, *mCore, &linphone::Core::setAudioPort,
	                                  &linphone::Core::setAudioPortRange);

	// Create default account for the server.
	const auto accountParams = mCore->createAccountParams();
	const auto localhostAddress = factory->createAddress("sip:flexisip-voicemail");
	const auto address = factory->createAddress("sip:flexisip-voicemail@localhost");
	accountParams->setIdentityAddress(address);
	accountParams->enableRegister(false);
	accountParams->setServerAddress(localhostAddress);
	const auto account = mCore->createAccount(accountParams);
	account->setContactAddress(localhostAddress);
	mCore->addAccount(account);
	mCore->setDefaultAccount(account);
	mCore->setPrimaryContact(address->asString());

	mCore->enableFriendListSubscription(false);
	mCore->enableLimeX3Dh(false);
	// Forward DTMF via out-of-band RTP ...
	mCore->setUseRfc2833ForDtmf(true);
	// ... or via SIP INFO if unsupported by media.
	mCore->setUseInfoForDtmf(true);
	// Do not allow chat
	mCore->disableChat(linphone::Reason::NotImplemented);

	// Voicemail shall never accept or start video calls.
	// Stick to incoming call parameters for that.
	const auto videoActivationPolicy = factory->createVideoActivationPolicy();
	videoActivationPolicy->setAutomaticallyAccept(false);
	videoActivationPolicy->setAutomaticallyInitiate(false);
	mCore->setVideoActivationPolicy(videoActivationPolicy);

	const auto natPolicy = mCore->createNatPolicy();
	natPolicy->enableIce(config->get<ConfigBoolean>("enable-ice")->read());
	mCore->setNatPolicy(natPolicy);

	mCore->setUserAgent("Flexisip-voicemail", FLEXISIP_GIT_VERSION);
	mCore->setTransports(transport);

	mCore->addListener(shared_from_this());

	linphone::Status err = mCore->start();
	if (err < 0) throw ExitFailure{"the Linphone core failed to start (please check the logs)"};
}

void VoicemailServer::_run() {
	mCore->iterate();
}

unique_ptr<AsyncCleanup> VoicemailServer::_stop() {
	for (const auto& [_, callHandler] : mCallHandlers)
		callHandler->terminateCall();
	mCallHandlers.clear();

	if (mCore == nullptr) return nullptr;

	mCore->removeListener(shared_from_this());
	mCore->stop();
	return nullptr;
}

void VoicemailServer::onCallStateChanged(const std::shared_ptr<linphone::Core>&,
                                         const std::shared_ptr<linphone::Call>& call,
                                         linphone::Call::State state,
                                         const std::string&) {
	LOGD << "Call " << call << " state changed to: " << static_cast<int>(state);

	switch (state) {
		case linphone::Call::State::IncomingReceived:
			onCallStateIncomingReceived(call);
			break;
		case linphone::Call::State::PushIncomingReceived:
		case linphone::Call::State::OutgoingInit:
		case linphone::Call::State::OutgoingProgress:
		case linphone::Call::State::OutgoingRinging:
		case linphone::Call::State::OutgoingEarlyMedia:
		case linphone::Call::State::Connected:
			break;
		case linphone::Call::State::StreamsRunning:
			onCallStateStreamsRunning(call);
			break;
		case linphone::Call::State::Pausing:
		case linphone::Call::State::Paused:
		case linphone::Call::State::Resuming:
		case linphone::Call::State::Referred:
			break;
			// When call is in error state we shall do as in linphone::Call::State::End.
		case linphone::Call::State::Error:
		case linphone::Call::State::End:
			onCallStateEnd(call);
			break;
		case linphone::Call::State::PausedByRemote:
		case linphone::Call::State::UpdatedByRemote:
		case linphone::Call::State::IncomingEarlyMedia:
		case linphone::Call::State::Updating:
		case linphone::Call::State::Released:
		case linphone::Call::State::EarlyUpdating:
		case linphone::Call::State::EarlyUpdatedByRemote:
		default:
			break;
	}
}

void VoicemailServer::onCallStateIncomingReceived(const std::shared_ptr<linphone::Call>& call) {
	const auto remoteAddress = call->getRemoteAddress()->asString();
	LOGD << "Incoming call received from " << remoteAddress << " [" << call << "]";

	// Accept the call only if the handler was created and stored
	if (mCallHandlers.emplace(getCallKey(call), make_shared<CallHandler>(call)).second) {
		call->accept();
	} else {
		const auto errorInfo = linphone::Factory::get()->createErrorInfo();
		errorInfo->setReason(linphone::Reason::Busy);
		call->declineWithErrorInfo(errorInfo);
	}
}

void VoicemailServer::onCallStateStreamsRunning(const std::shared_ptr<linphone::Call>& call) {
	LOGD << "Call stream running [" << call << "]";

	if (const auto callHandler = mCallHandlers.find(getCallKey(call)); callHandler != mCallHandlers.end())
		callHandler->second->playAnnounce(mAnnouncementFile);
}

void VoicemailServer::onCallStateEnd(const std::shared_ptr<linphone::Call>& call) {
	LOGD << "Call end [" << call << "]";
	mCallHandlers.erase(getCallKey(call));
}

namespace {

// Statically define default configuration items.
auto& defineConfig = ConfigManager::defaultInit().emplace_back([](GenericStruct& root) {
	ConfigItemDescriptor items[] = {
	    {
	        String,
	        "transport",
	        "Unique SIP URI on which the server is listening.\n"
	        "Supported protocols: UDP and TCP.",
	        "sip:127.0.0.1:6066;transport=tcp",
	    },
	    {
	        IntegerRange,
	        "audio-port",
	        "Audio port to use for RTP and RTCP traffic. You can set a specific port, a range of ports or let the "
	        "server ask the kernel for an available port (special value: 0).\n"
	        "Examples: 'audio-port=0' or 'audio-port=12345' or 'audio-port=1024-65535'",
	        "0",
	    },
	    {
	        Boolean,
	        "enable-ice",
	        "Enable interactive connectivity establishment (ICE).",
	        "true",
	    },
	    {
	        String,
	        "announcement-file-path",
	        "Path to the audio file that will be played right after call establishment.\n"
	        "Supports WAV and MKA/MKV files.",
	        "",
	    },
	    {
	        Integer,
	        "max-calls",
	        "Maximum number of calls the server can answer simultaneously.",
	        "1000",
	    },
	    config_item_end,
	};

	root.addChild(make_unique<GenericStruct>(voicemail::configSection, "Flexisip voicemail server parameters.", 0))
	    ->addChildrenValues(items);
});

} // namespace

} // namespace flexisip