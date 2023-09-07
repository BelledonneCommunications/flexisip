/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022  Belledonne Communications SARL, All rights reserved.

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

#include "b2bua-server.hh"

#include <memory>

#include <mediastreamer2/ms_srtp.h>

#include "flexisip/logmanager.hh"
#include "flexisip/utils/sip-uri.hh"

#include "external-provider-bridge.hh"
#include "trenscrypter.hh"

using namespace std;
using namespace linphone;

namespace flexisip {

// b2bua namespace to declare internal structures
namespace b2bua {
struct callsRefs {
	std::shared_ptr<linphone::Call> legA; /**< legA is the incoming call intercepted by the b2bua */
	std::shared_ptr<linphone::Call> legB; /**< legB is the call initiated by the b2bua to the original recipient */
	std::shared_ptr<linphone::Conference> conf; /**< the conference created to connect legA and legB */
};
} // namespace b2bua

// unamed namespace for local functions
namespace {
/**
 * Given one leg of the tranfered call, it returns the other leg
 *
 * @param[in]	call one of the call in the two call conference created by the b2bua
 *
 * @return	the other call in the conference
 */
std::shared_ptr<linphone::Call> getPeerCall(std::shared_ptr<linphone::Call> call) {
	auto& confData = call->getData<flexisip::b2bua::callsRefs>(B2buaServer::confKey);
	if (call->getDir() == linphone::Call::Dir::Outgoing) {
		return confData.legA;
	} else {
		return confData.legB;
	}
}
} // namespace

B2buaServer::B2buaServer(const std::shared_ptr<sofiasip::SuRoot>& root) : ServiceServer(root), mCli("b2bua") {
}

B2buaServer::~B2buaServer() {
}

void B2buaServer::onCallStateChanged([[maybe_unused]] const std::shared_ptr<linphone::Core>& core,
                                     const std::shared_ptr<linphone::Call>& call,
                                     linphone::Call::State state,
                                     [[maybe_unused]] const std::string& message) {
	SLOGD << "b2bua server onCallStateChanged to " << (int)state << " "
	      << ((call->getDir() == linphone::Call::Dir::Outgoing) ? "legB" : "legA");
	switch (state) {
		case linphone::Call::State::IncomingReceived: {
			SLOGD << "b2bua server onCallStateChanged incomingReceived, to " << call->getToAddress()->asString()
			      << " from " << call->getRemoteAddress()->asString();
			// Create outgoing call using parameters created from the incoming call in order to avoid duplicating the
			// callId
			auto outgoingCallParams = mCore->createCallParams(call);
			// add this custom header so this call will not be intercepted by the b2bua
			outgoingCallParams->addCustomHeader("flexisip-b2bua", "ignore");

			const auto calleeOrReason = mApplication->onCallCreate(*call, *outgoingCallParams);
			const auto& callee = std::get<1>(calleeOrReason);
			if (callee == nullptr) {
				call->decline(std::get<0>(calleeOrReason));
				return;
			}

			// create a conference and attach it
			auto conferenceParams = mCore->createConferenceParams(nullptr);
			conferenceParams->enableVideo(true);
			conferenceParams->enableLocalParticipant(false); // b2bua core is not part of it
			conferenceParams->enableOneParticipantConference(true);
			conferenceParams->setConferenceFactoryAddress(nullptr);

			auto conference = mCore->createConferenceWithParams(conferenceParams);

			// create legB and add it to the conference
			auto legB = mCore->inviteAddressWithParams(callee, outgoingCallParams);
			if (!legB) {
				// E.g. TLS is not supported
				SLOGE << "Could not establish bridge call. Please check your config.";
				call->decline(linphone::Reason::NotImplemented);
				return;
			}
			conference->addParticipant(legB);

			// add legA to the conference, but do not answer now
			conference->addParticipant(call);

			// store shared pointer to the conference and each call
			auto confData = new b2bua::callsRefs();
			confData->conf = conference;
			confData->legA = call;
			confData->legB = legB;

			// store ref on each other call
			call->setData<b2bua::callsRefs>(B2buaServer::confKey, *confData);
			legB->setData<b2bua::callsRefs>(B2buaServer::confKey, *confData);
		} break;
		case linphone::Call::State::PushIncomingReceived:
			break;
		case linphone::Call::State::OutgoingInit:
			break;
		case linphone::Call::State::OutgoingProgress:
			break;
		case linphone::Call::State::OutgoingRinging: {
			// This is legB getting its ring from callee, relay it to the legA call
			auto& confData = call->getData<b2bua::callsRefs>(B2buaServer::confKey);
			confData.legA->notifyRinging();
		} break;
		case linphone::Call::State::OutgoingEarlyMedia: {
			// LegB call sends early media: relay a 180
			auto& confData = call->getData<b2bua::callsRefs>(B2buaServer::confKey);
			confData.legA->notifyRinging();
		} break;
		case linphone::Call::State::Connected: {
		} break;
		case linphone::Call::State::StreamsRunning: {
			auto peerCall = getPeerCall(call);

			// If this is legB and legA is in incoming state, answer it
			// This cannot be done in connected state as currentCallParams are not updated yet
			if (call->getDir() == linphone::Call::Dir::Outgoing &&
			    (peerCall->getState() == linphone::Call::State::IncomingReceived ||
			     peerCall->getState() == linphone::Call::State::IncomingEarlyMedia)) {
				SLOGD << "b2bua server leg B running -> answer legA";
				auto incomingCallParams = mCore->createCallParams(peerCall);
				// add this custom header so this call will not be intercepted by the b2bua
				incomingCallParams->addCustomHeader("flexisip-b2bua", "ignore");
				// enforce same video/audio enable to legA than on legB - manage video rejected by legB
				incomingCallParams->enableAudio(call->getCurrentParams()->audioEnabled());
				incomingCallParams->enableVideo(call->getCurrentParams()->videoEnabled());
				peerCall->acceptWithParams(incomingCallParams);
			}
			// If peer in state updateByRemote, we defered an update, accept it now
			if (peerCall->getState() == linphone::Call::State::UpdatedByRemote) {
				SLOGD << "b2bua server onCallStateChanged: peer call defered update, accept it now";
				// update is defered only on video/audio add remove
				// create call params for peer call and copy video/audio enabling settings from this call
				auto peerCallParams = mCore->createCallParams(peerCall);
				peerCallParams->enableVideo(call->getCurrentParams()->videoEnabled());
				peerCallParams->enableAudio(call->getCurrentParams()->audioEnabled());
				peerCall->acceptUpdate(peerCallParams);
			} else {
				// if we are in StreamsRunning but peer is sendonly or inactive we likely arrived here after resuming
				// from pausedByRemote update peer back to recvsend
				auto peerCallAudioDirection = peerCall->getCurrentParams()->getAudioDirection();
				if (peerCallAudioDirection == linphone::MediaDirection::SendOnly ||
				    peerCallAudioDirection == linphone::MediaDirection::Inactive) {
					SLOGD << "b2bua server onCallStateChanged: peer call is paused, update it to resume";
					auto peerCallParams = peerCall->getCurrentParams()->copy();
					peerCallParams->setAudioDirection(linphone::MediaDirection::SendRecv);
					peerCall->update(peerCallParams);
				}
			}
		} break;
		case linphone::Call::State::Pausing:
			break;
		case linphone::Call::State::Paused:
			break;
		case linphone::Call::State::Resuming:
			break;
		case linphone::Call::State::Referred:
			break;
		case linphone::Call::State::Error:
			// when call in error we shall kill the conf, just do as in End
		case linphone::Call::State::End: {
			mApplication->onCallEnd(*call);
			// If there are some data in that call, it is the first one to end
			if (call->dataExists(B2buaServer::confKey)) {
				auto peerCall = getPeerCall(call);

				SLOGD << "B2bua end call: Terminate conference";
				auto& confData = call->getData<b2bua::callsRefs>(B2buaServer::confKey);
				// unset data everywhere it was stored
				confData.legA->unsetData(B2buaServer::confKey);
				confData.legB->unsetData(B2buaServer::confKey);
				confData.conf->unsetData(B2buaServer::confKey);
				// terminate peer Call, copy error info from this call
				peerCall->terminateWithErrorInfo(call->getErrorInfo());
				// terminate the conf
				confData.conf->terminate();
				// memory cleaning
				delete (&confData);
			} else {
				SLOGD << "B2bua end call: conference already terminated";
			}
		} break;
		case linphone::Call::State::PausedByRemote: {
			// Paused by remote: do not pause peer call as it will kick it out of the conference
			// just switch the media direction to sendOnly (only if it is not already set this way)
			auto peerCall = getPeerCall(call);
			auto peerCallParams = peerCall->getCurrentParams()->copy();
			auto audioDirection = peerCallParams->getAudioDirection();
			// Nothing to do if peer call is already not sending audio
			if (audioDirection != linphone::MediaDirection::Inactive &&
			    audioDirection != linphone::MediaDirection::SendOnly) {
				peerCallParams->setAudioDirection(linphone::MediaDirection::SendOnly);
				peerCall->update(peerCallParams);
			}
		} break;
		case linphone::Call::State::UpdatedByRemote: {
			// Manage add/remove video - ignore for other changes
			auto peerCall = getPeerCall(call);
			auto peerCallParams = mCore->createCallParams(peerCall);
			const auto selfCallParams = call->getCurrentParams();
			const auto selfRemoteCallParams = call->getRemoteParams();
			bool update = false;
			if (selfRemoteCallParams->videoEnabled() != selfCallParams->videoEnabled()) {
				update = true;
				peerCallParams->enableVideo(selfRemoteCallParams->videoEnabled());
			}
			if (selfRemoteCallParams->audioEnabled() != selfCallParams->audioEnabled()) {
				update = true;
				peerCallParams->enableAudio(selfRemoteCallParams->audioEnabled());
			}
			if (update) {
				SLOGD << "update peer call";
				// add this custom header so this call will not be intercepted by the b2bua
				peerCallParams->addCustomHeader("flexisip-b2bua", "ignore");
				peerCall->update(peerCallParams);
				call->deferUpdate();
			} else { // no update on video/audio status, just accept it with requested params
				SLOGD << "accept update without forwarding it to peer call";
				call->acceptUpdate(call->getRemoteParams());
			}
		} break;
		case linphone::Call::State::IncomingEarlyMedia:
			break;
		case linphone::Call::State::Updating:
			break;
		case linphone::Call::State::Released:
			break;
		case linphone::Call::State::EarlyUpdating:
			break;
		case linphone::Call::State::EarlyUpdatedByRemote:
			break;
		default:
			break;
	}
}

void B2buaServer::_init() {
	// Parse configuration for Data Dir
	/* Handle the case where the  directory is not created.
	 * This is for convenience, because our rpm and deb packages create it already. - NO THEY DO NOT DO THAT
	 * However, in other case (like developper environnement) this is painful to create it all the time manually.*/
	const auto configRoot = GenericManager::get()->getRoot();
	auto config = configRoot->get<GenericStruct>(b2bua::configSection);
	auto dataDirPath = config->get<ConfigString>("data-directory")->read();
	if (!bctbx_directory_exists(dataDirPath.c_str())) {
		BCTBX_SLOGI << "Creating b2bua data directory " << dataDirPath;
		// check parent dir exists as default path requires creation of 2 levels
		auto parentDir = dataDirPath.substr(0, dataDirPath.find_last_of('/'));
		if (!bctbx_directory_exists(parentDir.c_str())) {
			if (bctbx_mkdir(parentDir.c_str()) != 0) {
				BCTBX_SLOGE << "Could not create b2bua data parent directory " << parentDir;
			}
		}
		if (bctbx_mkdir(dataDirPath.c_str()) != 0) {
			BCTBX_SLOGE << "Could not create b2bua data directory " << dataDirPath;
		}
	}
	BCTBX_SLOGI << "B2bua data directory set to " << dataDirPath;
	Factory::get()->setDataDir(dataDirPath + "/");

	auto configLinphone = Factory::get()->createConfig("");
	configLinphone->setBool("misc", "conference_server_enabled", 1);
	configLinphone->setInt("misc", "max_calls", 1000);
	configLinphone->setInt("misc", "media_resources_mode", 1); // share media resources
	configLinphone->setBool("sip", "reject_duplicated_calls", false);
	configLinphone->setBool("sip", "defer_update_default",
	                        true); // do not automatically accept update: we might want to update peer call before
	configLinphone->setBool("misc", "conference_event_log_enabled", 0);
	configLinphone->setInt("misc", "conference_layout", static_cast<int>(linphone::ConferenceLayout::ActiveSpeaker));
	mCore = Factory::get()->createCoreWithConfig(configLinphone, nullptr);
	mCore->getConfig()->setString("storage", "backend", "sqlite3");
	mCore->getConfig()->setString("storage", "uri", ":memory:");
	mCore->setUseFiles(true); // No sound card shall be used in calls
	mCore->enableEchoCancellation(false);
	mCore->setPrimaryContact("sip:b2bua@localhost"); // TODO: get the primary contact from config, do we really need
	                                                 // one?
	mCore->enableAutoSendRinging(
	    false); // Do not auto answer a 180 on incoming calls, relay the one from the other part.
	mCore->setZrtpSecretsFile("null");

	// b2bua shall never take the initiative of accepting or starting video calls
	// stick to incoming call parameters for that
	auto policy = linphone::Factory::get()->createVideoActivationPolicy();
	policy->setAutomaticallyAccept(true); // accept incoming video call so the request is forwarded to legB, acceptance
	                                      // from legB is checked before accepting legA
	policy->setAutomaticallyInitiate(false);
	mCore->setVideoActivationPolicy(policy);

	// random port for UDP audio and video stream
	mCore->setAudioPort(-1);
	mCore->setVideoPort(-1);

	shared_ptr<Transports> b2buaTransport = Factory::get()->createTransports();
	// Get transport from flexisip configuration
	std::string mTransport = config->get<ConfigString>("transport")->read();
	if (mTransport.length() > 0) {
		sofiasip::Home mHome;
		url_t* urlTransport = url_make(mHome.home(), mTransport.c_str());
		if (urlTransport == nullptr || mTransport.at(0) == '<') {
			LOGF("B2bua server: Your configured conference transport(\"%s\") is not an URI.\n"
			     "If you have \"<>\" in your transport, remove them.",
			     mTransport.c_str());
		}
		b2buaTransport->setTcpPort(stoi(urlTransport->url_port));
	}

	mCore->setTransports(b2buaTransport);
	mCore->addListener(shared_from_this());

	auto applicationType = config->get<ConfigString>("application")->read();
	SLOGD << "B2BUA server starting with '" << applicationType << "' application";
	if (applicationType == "trenscrypter") {
		mApplication = std::make_unique<b2bua::trenscrypter::Trenscrypter>();
	} else if (applicationType == "sip-bridge") {
		auto bridge = std::make_unique<b2bua::bridge::AccountManager>();
		mCli.registerHandler(*bridge);
		mApplication = std::move(bridge);
	} else {
		LOGF("Unknown B2BUA application type: %s", applicationType.c_str());
	}
	mApplication->init(mCore, *configRoot);

	mCore->start();
	mCli.start();
}

void B2buaServer::_run() {
	mCore->iterate();
}

void B2buaServer::_stop() {
	mCore->removeListener(shared_from_this());
	mCli.stop();
}

namespace {
// Statically define default configuration items
auto defineConfig = [] {
	ConfigItemDescriptor items[] = {
	    {String, "application",
	     "The type of application that will handle calls bridged through the B2BUA. Possible values:\n"
	     "- `trenscrypter` Bridge different encryption types on both ends transparently.\n"
	     "- `sip-bridge` Bridge calls through an external SIP provider. (e.g. for PSTN gateways)",
	     "trenscrypter"},
	    {String, "transport", "SIP uri on which the back-to-back user agent server is listening on.",
	     "sip:127.0.0.1:6067;transport=tcp"},
	    {String, "data-directory",
	     "Directory where to store b2bua core local files\n"
	     "Default",
	     DEFAULT_B2BUA_DATA_DIR},
	    {String, "outbound-proxy",
	     "The Flexisip proxy URI to which the B2bua server should send all its outgoing SIP requests.",
	     "sip:127.0.0.1:5060;transport=tcp"},
	    config_item_end};

	GenericManager::get()
	    ->getRoot()
	    ->addChild(std::make_unique<GenericStruct>(b2bua::configSection,
	                                               "Flexisip back-to-back user agent server parameters.", 0))
	    ->addChildrenValues(items);

	return nullptr;
}();
} // namespace

} // namespace flexisip
