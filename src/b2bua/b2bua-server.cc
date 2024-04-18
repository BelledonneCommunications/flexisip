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

#include <memory>

#include "linphone/misc.h"
#include <mediastreamer2/ms_srtp.h>

#include "flexisip/flexisip-version.h"
#include "flexisip/logmanager.hh"
#include "flexisip/utils/sip-uri.hh"

#include "b2bua-server.hh"
#include "b2bua/async-stop-core.hh"
#include "sip-bridge/sip-bridge.hh"
#include "trenscrypter.hh"
#include "utils/variant-utils.hh"

using namespace std;
using namespace linphone;

namespace flexisip {

// b2bua namespace to declare internal structures
namespace b2bua {
struct callsRefs {
	shared_ptr<linphone::Call> legA;       /**< legA is the incoming call intercepted by the b2bua */
	shared_ptr<linphone::Call> legB;       /**< legB is the call initiated by the b2bua to the original recipient */
	shared_ptr<linphone::Conference> conf; /**< the conference created to connect legA and legB */
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
shared_ptr<linphone::Call> getPeerCall(shared_ptr<linphone::Call> call) {
	auto& confData = call->getData<flexisip::b2bua::callsRefs>(B2buaServer::kConfKey);
	if (call->getDir() == linphone::Call::Dir::Outgoing) {
		return confData.legA;
	} else {
		return confData.legB;
	}
}
} // namespace

B2buaServer::B2buaServer(const shared_ptr<sofiasip::SuRoot>& root, const std::shared_ptr<ConfigManager>& cfg)
    : ServiceServer(root), mConfigManager(cfg), mCli("b2bua", cfg) {
}

B2buaServer::~B2buaServer() {
}

void B2buaServer::onCallStateChanged(const shared_ptr<linphone::Core>&,
                                     const shared_ptr<linphone::Call>& call,
                                     linphone::Call::State state,
                                     const string&) {
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
			// TODO(jabiru) rename to x-flexisip-b2bua to be RFC compliant OR get rid of it entirely
			outgoingCallParams->addCustomHeader(kCustomHeader, "ignore");

			const auto callee = Match(mApplication->onCallCreate(*call, *outgoingCallParams))
			                        .against([](shared_ptr<const linphone::Address> callee) { return callee; },
			                                 [&call](linphone::Reason&& reason) {
				                                 call->decline(reason);
				                                 return shared_ptr<const linphone::Address>{};
			                                 });
			if (callee == nullptr) return;

			// create a conference and attach it
			auto conferenceParams = mCore->createConferenceParams(nullptr);
			conferenceParams->setHidden(true); // Hide conference to prevent the contact address from being updated
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
			call->setData<b2bua::callsRefs>(B2buaServer::kConfKey, *confData);
			legB->setData<b2bua::callsRefs>(B2buaServer::kConfKey, *confData);
		} break;
		case linphone::Call::State::PushIncomingReceived:
			break;
		case linphone::Call::State::OutgoingInit:
			break;
		case linphone::Call::State::OutgoingProgress:
			break;
		case linphone::Call::State::OutgoingRinging: {
			// This is legB getting its ring from callee, relay it to the legA call
			auto& confData = call->getData<b2bua::callsRefs>(B2buaServer::kConfKey);
			confData.legA->notifyRinging();
		} break;
		case linphone::Call::State::OutgoingEarlyMedia: {
			// LegB call sends early media: relay a 180
			auto& confData = call->getData<b2bua::callsRefs>(B2buaServer::kConfKey);
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
				incomingCallParams->addCustomHeader(kCustomHeader, "ignore");
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
			} else if (peerCall->getState() != linphone::Call::State::PausedByRemote) {
				// Resuming from PausedByRemote. Update peer back to sendrecv.
				auto peerCallAudioDirection = peerCall->getCurrentParams()->getAudioDirection();
				if (peerCallAudioDirection == linphone::MediaDirection::SendOnly ||
				    peerCallAudioDirection == linphone::MediaDirection::Inactive) {
					SLOGD << "b2bua server onCallStateChanged: peer call is paused, update it to resume";
					auto peerCallParams = mCore->createCallParams(peerCall);
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
			if (call->dataExists(B2buaServer::kConfKey)) {
				auto peerCall = getPeerCall(call);

				SLOGD << "B2bua end call: Terminate conference";
				auto& confData = call->getData<b2bua::callsRefs>(B2buaServer::kConfKey);
				// unset data everywhere it was stored
				confData.legA->unsetData(B2buaServer::kConfKey);
				confData.legB->unsetData(B2buaServer::kConfKey);
				confData.conf->unsetData(B2buaServer::kConfKey);
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
			auto peerCallParams = mCore->createCallParams(peerCall);
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
			bool updatePeerCall = false;
			if (selfRemoteCallParams->videoEnabled() != selfCallParams->videoEnabled()) {
				updatePeerCall = true;
				peerCallParams->enableVideo(selfRemoteCallParams->videoEnabled());
			}
			if (selfRemoteCallParams->audioEnabled() != selfCallParams->audioEnabled()) {
				updatePeerCall = true;
				peerCallParams->enableAudio(selfRemoteCallParams->audioEnabled());
			}
			if (updatePeerCall) {
				SLOGD << "update peer call";
				// add this custom header so this call will not be intercepted by the b2bua
				peerCallParams->addCustomHeader(kCustomHeader, "ignore");
				peerCall->update(peerCallParams);
				call->deferUpdate();
			} else { // no update on video/audio status, just accept it with requested params
				SLOGD << "accept update without forwarding it to peer call";
				// Accept all minor changes.
				// acceptUpdate()'s documentation isn't very clear on its behaviour
				// See https://linphone.atlassian.net/browse/SDK-120
				call->acceptUpdate(nullptr);
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

void B2buaServer::onDtmfReceived([[maybe_unused]] const shared_ptr<linphone::Core>& _core,
                                 const shared_ptr<linphone::Call>& call,
                                 int dtmf) {
	auto otherLeg = getPeerCall(call);
	SLOGD << "Forwarding DTMF " << dtmf << " from " << call->getCallLog()->getCallId() << " to "
	      << otherLeg->getCallLog()->getCallId();
	otherLeg->sendDtmf(dtmf);
};

void B2buaServer::_init() {
	// Parse configuration for Data Dir
	/* Handle the case where the directory is not created.
	 * This is for convenience, because our rpm and deb packages create it already. - NO THEY DO NOT DO THAT
	 * However, in other cases (like development environment) it is painful to create it all the time manually.*/
	const auto* config = mConfigManager->getRoot()->get<GenericStruct>(b2bua::configSection);
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
	configLinphone->setBool("sip", "use_rfc2833", true); // Forward DTMF via out-of-band RTP...
	configLinphone->setBool("sip", "use_info", true);    // ...or via SIP INFO if unsupported by media
	configLinphone->setBool("sip", "defer_update_default",
	                        true); // do not automatically accept update: we might want to update peer call before
	configLinphone->setBool("misc", "conference_event_log_enabled", 0);
	configLinphone->setInt("misc", "conference_layout", static_cast<int>(linphone::Conference::Layout::ActiveSpeaker));
	// Prevent the default log handler from being reset while LinphoneCore construction.
	configLinphone->setBool("logging", "disable_stdout", true);
	// we may want to use unsupported codecs (h264) in the conference
	configLinphone->setBool("video", "dont_check_codecs", true);
	// make sure the videostream can be started when using unsupported codec
	configLinphone->setBool("video", "fallback_to_dummy_codec", true);
	mCore = Factory::get()->createCoreWithConfig(configLinphone, nullptr);
	mCore->setLabel("Flexisip B2BUA");
	mCore->getConfig()->setString("storage", "backend", "sqlite3");
	mCore->getConfig()->setString("storage", "uri", ":memory:");
	mCore->setUseFiles(true); // No sound card shall be used in calls
	mCore->enableEchoCancellation(false);
	mCore->setPrimaryContact("sip:b2bua@localhost"); // TODO: get primary contact from config, do we really need one?
	mCore->enableAutoSendRinging(false); // Do not auto answer 180 on incoming calls, relay the one from the other part.
	mCore->setZrtpSecretsFile(dataDirPath + "/null");
	// Give enough time to the outgoing call (legB) to establish while we leave the incoming one (legA) ringing
	// See RFC 3261 §16.6 step 11 for the duration
	mCore->setIncTimeout(4 * 60);

	// Read user-agent parameter.
	smatch res{};
	const auto value = config->get<ConfigString>("user-agent")->read();
	if (regex_match(value, res, regex(R"(^([a-zA-Z0-9-.!%*_+`'~]+)(?:\/([a-zA-Z0-9-.!%*_+`'~]+|\{version\}))?$)"))) {
		mCore->setUserAgent(res[1], res[2] == "{version}" ? FLEXISIP_GIT_VERSION : res[2].str());
	} else {
		throw runtime_error("user-agent parameter is ill-formed, use the following syntax: <name>[/<version>]");
	}

	// b2bua shall never take the initiative of accepting or starting video calls
	// stick to incoming call parameters for that
	auto policy = linphone::Factory::get()->createVideoActivationPolicy();
	policy->setAutomaticallyAccept(true); // accept incoming video call so the request is forwarded to legB, acceptance
	                                      // from legB is checked before accepting legA
	policy->setAutomaticallyInitiate(false);
	mCore->setVideoActivationPolicy(policy);

	// if a video codec is set in config enable only that one
	string cVideoCodec = config->get<ConfigString>("video-codec")->read();
	if (cVideoCodec.length() > 0) {
		// disable all video codecs
		for (const auto& pt : mCore->getVideoPayloadTypes()) {
			BCTBX_SLOGI << "Disable " << pt->getMimeType() << " codec as only " << cVideoCodec << " should be used";
			pt->enable(false);
		}
		// enable the given one
		auto enabledCodec = mCore->getPayloadType(cVideoCodec, -1, -1);
		if (enabledCodec) {
			enabledCodec->enable(true);
		} else {
			BCTBX_SLOGW << "B2bua core failed to enable " << cVideoCodec << " video codec";
		}
	}

	// random port for UDP audio and video stream
	mCore->setAudioPort(-1);
	mCore->setVideoPort(-1);

	// set no-RTP timeout
	const auto noRTPTimeout = config->get<ConfigInt>("no-rtp-timeout")->read();
	if (noRTPTimeout <= 0) {
		LOGF("'%s' must be higher than 0", config->getCompleteName().c_str());
	}
	mCore->setNortpTimeout(noRTPTimeout);

	mCore->setInCallTimeout(config->get<ConfigInt>("max-call-duration")->read());

	// Get transport from flexisip configuration
	shared_ptr<Transports> b2buaTransport = Factory::get()->createTransports();
	string mTransport = config->get<ConfigString>("transport")->read();
	if (mTransport.length() > 0) {
		try {
			const auto urlTransport = SipUri{mTransport};
			const auto scheme = urlTransport.getScheme();
			const auto transportParam = urlTransport.getParam("transport");
			auto listeningPort = stoi(urlTransport.getPort(true));
			if (listeningPort == 0) {
				listeningPort = LC_SIP_TRANSPORT_RANDOM;
			}
			if (scheme == "sip") {
				if (transportParam.empty() || transportParam == "udp") {
					b2buaTransport->setUdpPort(listeningPort);
				} else if (transportParam == "tcp") {
					b2buaTransport->setTcpPort(listeningPort);
				} else if (transportParam == "tls") {
					b2buaTransport->setTlsPort(listeningPort);
				} else {
					throw sofiasip::InvalidUrlError{
					    mTransport, "invalid transport parameter value for 'sip' scheme: "s + transportParam};
				}
			} else if (scheme == "sips") {
				if (transportParam == "udp") {
					b2buaTransport->setDtlsPort(listeningPort);
				} else if (transportParam.empty() || transportParam == "tcp") {
					b2buaTransport->setTlsPort(listeningPort);
				} else {
					throw sofiasip::InvalidUrlError{
					    mTransport, "invalid transport parameter value for 'sips' scheme: "s + transportParam};
				}
			}
		} catch (const sofiasip::InvalidUrlError& e) {
			LOGF("B2bua server: Your configured b2bua transport(\"%s\") is not an URI.\n"
			     "%s",
			     mTransport.c_str(), e.what());
		};
	}

	mCore->setTransports(b2buaTransport);
	mCore->addListener(shared_from_this());

	auto applicationType = config->get<ConfigString>("application")->read();
	SLOGD << "B2BUA server starting with '" << applicationType << "' application";
	if (applicationType == "trenscrypter") {
		mApplication = make_unique<b2bua::trenscrypter::Trenscrypter>();
	} else if (applicationType == "sip-bridge") {
		auto bridge = make_unique<b2bua::bridge::SipBridge>(mRoot, mCore);
		mCli.registerHandler(*bridge);
		mApplication = std::move(bridge);
	} else {
		LOGF("Unknown B2BUA application type: %s", applicationType.c_str());
	}
	mApplication->init(mCore, *mConfigManager);

	mCore->start();
	mCli.start();
}

void B2buaServer::_run() {
	mCore->iterate();
}

std::unique_ptr<AsyncCleanup> B2buaServer::_stop() {
	mCore->removeListener(shared_from_this());
	mCli.stop();
	return std::make_unique<b2bua::AsyncStopCore>(mCore);
}

namespace {
// Statically define default configuration items
auto& defineConfig = ConfigManager::defaultInit().emplace_back([](GenericStruct& root) {
	ConfigItemDescriptor items[] = {
	    {String, "application",
	     "The type of application that will handle calls bridged through the B2BUA. Possible values:\n"
	     "- `trenscrypter` Bridge different encryption types on both ends transparently.\n"
	     "- `sip-bridge` Bridge calls through an external SIP provider. (e.g. for PSTN gateways)",
	     "trenscrypter"},
	    {String, "transport", "SIP uri on which the back-to-back user agent server is listening on.",
	     "sip:127.0.0.1:6067;transport=tcp"},
	    {String, "user-agent",
	     "Value of User-Agent header. Use the following syntax: <name>[/<version>] where <version> can bet set to "
	     "'{version}' that is a placeholder for the Flexisip version.",
	     "Flexisip-B2BUA/{version}"},
	    {String, "data-directory",
	     "Directory where to store b2bua core local files\n"
	     "Default",
	     DEFAULT_B2BUA_DATA_DIR},
	    {String, "outbound-proxy",
	     "The Flexisip proxy URI to which the B2bua server should send all its outgoing SIP requests.",
	     "sip:127.0.0.1:5060;transport=tcp"},
	    {Integer, "no-rtp-timeout",
	     "Duration after which the B2BUA will terminate a call if no RTP packet is received from the other call "
	     "participant. Unit: seconds.",
	     "30"},
	    {Integer, "max-call-duration",
	     "Any call bridged through the B2BUA that has been running for longer than this amount of seconds will be "
	     "terminated. 0 to disable and let calls run unbounded.",
	     "0"},
	    {String, "video-codec",
	     "When not null, force outgoing video call to use the specified codec.\n"
	     "Warning: all outgoing calls will list only this codec, which means incoming calls must use it too.",
	     ""},
	    config_item_end};

	root.addChild(
	        make_unique<GenericStruct>(b2bua::configSection, "Flexisip back-to-back user agent server parameters.", 0))
	    ->addChildrenValues(items);
});
} // namespace

} // namespace flexisip
