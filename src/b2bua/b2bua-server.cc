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
#include "mediastreamer2/msconference.h"
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

struct EventsRefs {
	shared_ptr<linphone::Event> legA; /**< legA is the incoming subscribe intercepted by the b2bua */
	shared_ptr<linphone::Event> legB; /**< legB is the subscribe initiated by the b2bua to the original recipient */
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
	const string_view legName = call->getDir() == linphone::Call::Dir::Outgoing ? "legB" : "legA";
	SLOGD << "b2bua server onCallStateChanged to " << (int)state << legName;
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
			if (call->dataExists(B2buaServer::kConfKey)) {
				auto peerCall = getPeerCall(call);
				// terminate peer Call, copy error info from this call
				peerCall->terminateWithErrorInfo(call->getErrorInfo());
			}
		} break;
		case linphone::Call::State::PausedByRemote: {
			// Paused by remote: do not pause peer call as it will kick it out of the conference
			// just switch the media direction to sendOnly (only if it is not already set this way)
			const auto peerCall = getPeerCall(call);
			if (peerCall->getState() == linphone::Call::State::PausedByRemote) {
				const string_view peerLegName = legName == "legA" ? "legB" : "legA";
				SLOGE << "Both calls are in state LinphoneCallPausedByRemote, lost track of who initiated the pause"
				      << " [" << legName << ": " << call << ", " << peerLegName << ": " << peerCall << "]";
				call->terminate();
				peerCall->terminate();
				return;
			}

			const auto peerCallAudioDirection = mCore->createCallParams(peerCall)->getAudioDirection();
			// Nothing to do if peer call is already not sending audio
			if (peerCallAudioDirection != linphone::MediaDirection::Inactive &&
			    peerCallAudioDirection != linphone::MediaDirection::SendOnly) {
				const auto peerCallParams = mCore->createCallParams(peerCall);
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
			// If there are some data in that call, it is the first one to end
			if (call->dataExists(B2buaServer::kConfKey)) {
				auto& confData = call->getData<b2bua::callsRefs>(B2buaServer::kConfKey);
				SLOGD << "B2bua release call: Terminate conference " << confData.conf;
				// unset data everywhere it was stored
				confData.legA->unsetData(B2buaServer::kConfKey);
				confData.legB->unsetData(B2buaServer::kConfKey);
				confData.conf->unsetData(B2buaServer::kConfKey);
				// terminate the conf
				confData.conf->terminate();
				// memory cleaning
				delete (&confData);
			} else {
				SLOGD << "B2bua end call: conference already terminated";
			}
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
}

void B2buaServer::onSubscribeReceived(const std::shared_ptr<linphone::Core>& core,
                                      const std::shared_ptr<linphone::Event>& legAEvent,
                                      const std::string& subscribeEvent,
                                      const std::shared_ptr<const linphone::Content>& body) {
	int expires = 0;
	try {
		expires = stoi(legAEvent->getCustomHeader("Expires"));
	} catch (std::exception const& ex) {
		SLOGE << "Invalid expires in received SUBSCRIBE, denying subscription";
		legAEvent->denySubscription(linphone::Reason::NotAcceptable);
		return;
	}

	const auto subscriber = Match(mApplication->onSubscribe(*legAEvent, subscribeEvent))
	                            .against([](shared_ptr<const linphone::Address> subscriber) { return subscriber; },
	                                     [&legAEvent](linphone::Reason&& reason) {
		                                     legAEvent->denySubscription(reason);
		                                     return shared_ptr<const linphone::Address>{};
	                                     });
	if (subscriber == nullptr) return;

	// Create the outgoing SUBSCRIBE and copy the request address and Accept header
	// from the incoming one.
	auto resource = subscriber->clone();
	auto legBEvent = core->createSubscribe(resource, subscribeEvent, expires);
	legBEvent->setRequestAddress(legAEvent->getRequestAddress()->clone());
	auto acceptHeader = legAEvent->getCustomHeader("Accept");
	if (!acceptHeader.empty()) legBEvent->addCustomHeader("Accept", acceptHeader);
	legBEvent->addListener(shared_from_this());

	if (legBEvent->sendSubscribe(body) < 0) {
		legAEvent->denySubscription(linphone::Reason::NotAcceptable);
		return;
	}

	// Store a shared pointer to each event
	auto eventsData = new b2bua::EventsRefs();
	eventsData->legA = legAEvent;
	eventsData->legB = legBEvent;
	legAEvent->setData<b2bua::EventsRefs>(B2buaServer::kEventKey, *eventsData);
	legBEvent->setData<b2bua::EventsRefs>(B2buaServer::kEventKey, *eventsData);
	legAEvent->addListener(shared_from_this());
}

void B2buaServer::onSubscribeStateChanged(const std::shared_ptr<linphone::Event>& event,
                                          linphone::SubscriptionState state) {
	try {
		b2bua::EventsRefs& eventsData = event->getData<b2bua::EventsRefs>(B2buaServer::kEventKey);
		if (event == eventsData.legB) {
			if (state == linphone::SubscriptionState::Active) {
				// Forward the subscription acceptation
				eventsData.legA->acceptSubscription();
			} else if (state == linphone::SubscriptionState::Error) {
				// Forward the subcription error
				eventsData.legA->denySubscription(event->getReason());
			}
		} else if (event == eventsData.legA) {
			if (state == linphone::SubscriptionState::Terminated) {
				// Un-SUBSCRIBE from the subscriber
				eventsData.legB->terminate();
				eventsData.legA->unsetData(B2buaServer::kEventKey);
				eventsData.legB->unsetData(B2buaServer::kEventKey);
				delete &eventsData;
			}
		}
	} catch (std::out_of_range&) {
		// The event does not contain eventsData
	}
}

// NOTIFY listener on a subscribe event.
// This is called when a SUBSCRIBE is forwarded by the B2BUA and then a NOTIFY is received for this
// subscription.
void B2buaServer::onNotifyReceived(const std::shared_ptr<linphone::Event>& event,
                                   const std::shared_ptr<const linphone::Content>& content) {
	try {
		b2bua::EventsRefs& eventsData = event->getData<b2bua::EventsRefs>(B2buaServer::kEventKey);
		// Forward NOTIFY
		eventsData.legA->notify(content);
	} catch (std::out_of_range&) {
		SLOGE << "No data associated to the event, can't forward the NOTIFY";
	}
}

// MWI listener on the core.
// This is called when a MWI NOTIFY is received out-of-dialog.
void B2buaServer::onMessageWaitingIndicationChanged(
    const std::shared_ptr<linphone::Core>& core,
    const std::shared_ptr<linphone::Event>& legBEvent,
    const std::shared_ptr<const linphone::MessageWaitingIndication>& mwi) {

	// Try to create a temporary account configured with the correct outbound proxy to be able to bridge the received
	// NOTIFY.
	const auto destination = mApplication->onNotifyToBeSent(*legBEvent);
	if (!destination) return;
	const auto& [subscriber, accountUsedToSendNotify] = *destination;

	// Modify the MWI content so that its Message-Account is mapped according to the account mapping of the sip
	// provider.
	auto newMwi = mwi->clone();
	newMwi->setAccountAddress(core->createAddress(subscriber.str()));
	auto content = newMwi->toContent();
	auto resource = core->createAddress(subscriber.str());
	auto legAEvent = core->createNotify(resource, "message-summary");
	legAEvent->notify(content);
}

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

	const auto& forceCodec = [&config, &core = *mCore, &configLinphone](const auto& flexisipConfigName,
	                                                                    const auto& linphoneConfigName,
	                                                                    const auto& codecList) {
		const auto* configField = config->get<ConfigString>(flexisipConfigName);
		const auto& payloadDesc = configField->read();
		if (payloadDesc.empty()) return;
		const auto& parts = StringUtils::split(string_view(payloadDesc), "/");
		if (parts.size() < 2) {
			throw runtime_error(configField->getCompleteName() +
			                    " misconfigured. Expected something like <codec>/<sample rate>, e.g. 'speex/8000'");
		}
		const auto codec = parts[0];
		const auto rate = parts[1];

		for (const auto& payloadType : (core.*codecList)()) {
			if (payloadType->getMimeType() == codec && to_string(payloadType->getClockRate()) == rate) {
				payloadType->enable(true);
			} else { // disable all other codecs
				payloadType->enable(false);
				SLOGD << "Disabling " << payloadType->getDescription() << " to force " << codec << "/" << rate;
			}
		}

		// We know for certain that the codec used in both legs will be the same (the one we just forced), so we can
		// enable media bridging (payload forwarding without decoding)
		configLinphone->setInt(linphoneConfigName, "conference_mode", MSConferenceModeRouterPayload);
	};

	// if an audio codec is set in config enable only that one
	forceCodec("audio-codec", "sound", &linphone::Core::getAudioPayloadTypes);
	// if a video codec is set in config enable only that one
	forceCodec("video-codec", "video", &linphone::Core::getVideoPayloadTypes);

	const int audioPortMin = config->get<ConfigIntRange>("audio-port")->readMin();
	const int audioPortMax = config->get<ConfigIntRange>("audio-port")->readMax();
	mCore->setAudioPort(audioPortMin == audioPortMax ? audioPortMin : -1);
	mCore->setAudioPortRange(audioPortMin, audioPortMax);

	const int videoPortMin = config->get<ConfigIntRange>("video-port")->readMin();
	const int videoPortMax = config->get<ConfigIntRange>("video-port")->readMax();
	mCore->setVideoPort(videoPortMin == videoPortMax ? videoPortMin : -1);
	mCore->setVideoPortRange(videoPortMin, videoPortMax);

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
	    {
	        String,
	        "application",
	        "The type of application that will handle calls bridged through the B2BUA. Possible values:\n"
	        "- `trenscrypter` Bridge different encryption types on both ends transparently.\n"
	        "- `sip-bridge` Bridge calls through an external SIP provider. (e.g. for PSTN gateways)",
	        "trenscrypter",
	    },
	    {
	        String,
	        "transport",
	        "SIP uri on which the back-to-back user agent server is listening on.",
	        "sip:127.0.0.1:6067;transport=tcp",
	    },
	    {
	        IntegerRange,
	        "audio-port",
	        "Audio port to use for RTP and RTCP traffic. You can set a specific port or a range of ports.\n"
	        "Examples: 'audio-port=12345' or 'audio-port=1024-65535'",
	        "1024-65535",
	    },
	    {
	        IntegerRange,
	        "video-port",
	        "Video port to use for RTP and RTCP traffic. You can set a specific port or a range of ports.\n"
	        "Examples: 'video-port=12345' or 'video-port=1024-65535'",
	        "1024-65535",
	    },
	    {
	        String,
	        "user-agent",
	        "Value of User-Agent header. Use the following syntax: <name>[/<version>] where <version> can bet set to "
	        "'{version}' that is a placeholder for the Flexisip version.",
	        "Flexisip-B2BUA/{version}",
	    },
	    {
	        String,
	        "data-directory",
	        "Directory where to store b2bua core local files\n"
	        "Default",
	        DEFAULT_B2BUA_DATA_DIR,
	    },
	    {
	        String,
	        "outbound-proxy",
	        "The Flexisip proxy URI to which the B2bua server should send all its outgoing SIP requests.",
	        "sip:127.0.0.1:5060;transport=tcp",
	    },
	    {
	        Integer,
	        "no-rtp-timeout",
	        "Duration after which the B2BUA will terminate a call if no RTP packet is received from the other call "
	        "participant. Unit: seconds.",
	        "30",
	    },
	    {
	        Integer,
	        "max-call-duration",
	        "Any call bridged through the B2BUA that has been running for longer than this amount of seconds will be "
	        "terminated. 0 to disable and let calls run unbounded.",
	        "0",
	    },
	    {
	        String,
	        "audio-codec",
	        "Turn off all audio codecs except this one. This will effectively force this codec on both ends of all "
	        "bridged calls. (If either end does not support the codec set here, the call will fail to establish.) "
	        "Setting this option will also turn on the media payload forwarding optimisation which improves the "
	        "performance of the B2BUA.",
	        "",
	    },
	    {
	        String,
	        "video-codec",
	        "Same as 'audio-codec' but for video.",
	        "",
	    },
	    config_item_end};

	root.addChild(
	        make_unique<GenericStruct>(b2bua::configSection, "Flexisip back-to-back user agent server parameters.", 0))
	    ->addChildrenValues(items);
});
} // namespace

} // namespace flexisip
