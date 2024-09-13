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

#include "b2bua-server.hh"

#include <memory>

#include <mediastreamer2/ms_srtp.h>

#include "flexisip/logmanager.hh"

#include "b2bua/async-stop-core.hh"
#include "sip-bridge/sip-bridge.hh"
#include "trenscrypter.hh"
#include "utils/variant-utils.hh"

#define FUNC_LOG_PREFIX(prefix) prefix << " " << __func__ << "()"

using namespace std;
using namespace linphone;

namespace flexisip {

shared_ptr<linphone::Call> B2buaServer::getPeerCall(const shared_ptr<linphone::Call>& call) const {
	const auto peerCallEntry = mPeerCalls.find(call);
	if (peerCallEntry == mPeerCalls.cend()) {
		SLOGW << mLogPrefix << ": failed to find peer call of current call {ptr = " << call
		      << ", call-id = " << call->getCallLog()->getCallId() << "}";
		return nullptr;
	}

	return peerCallEntry->second.lock();
}

B2buaServer::B2buaServer(const shared_ptr<sofiasip::SuRoot>& root, const std::shared_ptr<ConfigManager>& cfg)
    : ServiceServer(root), mConfigManager(cfg), mCli("b2bua", cfg, root) {
}

B2buaServer::~B2buaServer() {
}

void B2buaServer::onCallStateChanged(const shared_ptr<linphone::Core>&,
                                     const shared_ptr<linphone::Call>& call,
                                     linphone::Call::State state,
                                     const string&) {
	const auto legName = call->getDir() == linphone::Call::Dir::Outgoing ? "legB"sv : "legA"sv;
	SLOGD << FUNC_LOG_PREFIX(mLogPrefix) << ": call " << call << " (" << legName << ") state changed to " << (int)state;
	switch (state) {
		case linphone::Call::State::IncomingReceived: {
			SLOGD << FUNC_LOG_PREFIX(mLogPrefix) << ": incoming call received from "
			      << call->getRemoteAddress()->asString() << " to " << call->getToAddress()->asString();
			// Create outgoing call using parameters from the incoming call in order to avoid duplicating the callId.
			auto outgoingCallParams = mCore->createCallParams(call);
			// Add this custom header so this call will not be intercepted by the B2BUA.
			outgoingCallParams->addCustomHeader(kCustomHeader, "ignore");

			const auto callee = Match(mApplication->onCallCreate(*call, *outgoingCallParams))
			                        .against([](shared_ptr<const linphone::Address> callee) { return callee; },
			                                 [&call](linphone::Reason&& reason) {
				                                 call->decline(reason);
				                                 return shared_ptr<const linphone::Address>{};
			                                 });
			if (callee == nullptr) return;

			// Create a conference and attach it.
			auto conferenceParams = mCore->createConferenceParams(nullptr);
			conferenceParams->setHidden(true); // Hide conference to prevent the contact address from being updated.
			conferenceParams->enableVideo(true);
			conferenceParams->enableLocalParticipant(false); // B2BUA core is not part of it.
			conferenceParams->enableOneParticipantConference(true);
			conferenceParams->setConferenceFactoryAddress(nullptr);

			auto conference = mCore->createConferenceWithParams(conferenceParams);

			// Create legB and add it to the conference.
			auto legB = mCore->inviteAddressWithParams(callee, outgoingCallParams);
			if (!legB) {
				// E.g. TLS is not supported
				SLOGE << FUNC_LOG_PREFIX(mLogPrefix)
				      << ": could not establish bridge call, please verify your configuration";
				call->decline(linphone::Reason::NotImplemented);
				return;
			}
			conference->addParticipant(legB);

			// Add legA to the conference, but do not answer now.
			conference->addParticipant(call);

			// Store each call.
			mPeerCalls[call] = legB;
			mPeerCalls[legB] = call;
		} break;
		case linphone::Call::State::PushIncomingReceived:
			break;
		case linphone::Call::State::OutgoingInit:
			break;
		case linphone::Call::State::OutgoingProgress:
			break;
		case linphone::Call::State::OutgoingRinging: {
			// This is legB getting its ring from callee, relay it to the legA call.
			const auto& legA = getPeerCall(call);
			if (legA) legA->notifyRinging();
		} break;
		case linphone::Call::State::OutgoingEarlyMedia: {
			// LegB call sends early media: relay a 180
			const auto& legA = getPeerCall(call);
			if (legA) legA->notifyRinging();
		} break;
		case linphone::Call::State::Connected: {
		} break;
		case linphone::Call::State::StreamsRunning: {
			auto peerCall = getPeerCall(call);
			if (!peerCall) return;

			// If this is legB and that legA is in incoming state, answer it.
			// This cannot be done in connected state as currentCallParams are not updated yet.
			if (call->getDir() == linphone::Call::Dir::Outgoing &&
			    (peerCall->getState() == linphone::Call::State::IncomingReceived ||
			     peerCall->getState() == linphone::Call::State::IncomingEarlyMedia)) {
				SLOGD << FUNC_LOG_PREFIX(mLogPrefix) << ": legB is now running -> answer legA";
				auto incomingCallParams = mCore->createCallParams(peerCall);
				// Add this custom header so this call will not be intercepted by the B2BUA.
				incomingCallParams->addCustomHeader(kCustomHeader, "ignore");
				// Enforce same video/audio enable to legA than on legB - manage video rejected by legB.
				incomingCallParams->enableAudio(call->getCurrentParams()->audioEnabled());
				incomingCallParams->enableVideo(call->getCurrentParams()->videoEnabled());
				peerCall->acceptWithParams(incomingCallParams);
			}
			// If peer is in state UpdatedByRemote, we deferred an update, so accept it now.
			if (peerCall->getState() == linphone::Call::State::UpdatedByRemote) {
				SLOGD << FUNC_LOG_PREFIX(mLogPrefix) << ": peer call deferred update, accept it now";
				// Update is deferred only on video/audio add remove.
				// Create call params for peer call and copy video/audio enabling settings from this call.
				auto peerCallParams = mCore->createCallParams(peerCall);
				peerCallParams->enableVideo(call->getCurrentParams()->videoEnabled());
				peerCallParams->enableAudio(call->getCurrentParams()->audioEnabled());
				peerCall->acceptUpdate(peerCallParams);
			} else if (peerCall->getState() != linphone::Call::State::PausedByRemote) {
				// Resuming from PausedByRemote, update peer back to "sendrecv".
				auto peerCallAudioDirection = peerCall->getCurrentParams()->getAudioDirection();
				if (peerCallAudioDirection == linphone::MediaDirection::SendOnly ||
				    peerCallAudioDirection == linphone::MediaDirection::Inactive) {
					SLOGD << FUNC_LOG_PREFIX(mLogPrefix) << ": peer call is paused, update it to resume";
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
			// When call is in error state we shall kill the conference: just do as in End state.
		case linphone::Call::State::End: {
			mApplication->onCallEnd(*call);
			// Terminate peer Call, copy error information from this call.
			const auto& peerCall = getPeerCall(call);
			if (peerCall) peerCall->terminateWithErrorInfo(call->getErrorInfo());
		} break;
		case linphone::Call::State::PausedByRemote: {
			// Paused by remote: do not pause peer call as it will kick it out of the conference.
			// Just switch the media direction to sendOnly (only if it is not already set this way).
			const auto& peerCall = getPeerCall(call);
			if (!peerCall) return;
			if (peerCall->getState() == linphone::Call::State::PausedByRemote) {
				const auto peerLegName = legName == "legA" ? "legB"sv : "legA"sv;
				SLOGE << FUNC_LOG_PREFIX(mLogPrefix)
				      << ": both calls are in state LinphoneCallPausedByRemote, lost track of who initiated the pause"
				      << " [" << legName << ": " << call << ", " << peerLegName << ": " << peerCall << "]";
				call->terminate();
				peerCall->terminate();
				return;
			}

			const auto peerCallAudioDirection = mCore->createCallParams(peerCall)->getAudioDirection();
			// Nothing to do if peer call is already not sending audio.
			if (peerCallAudioDirection != linphone::MediaDirection::Inactive &&
			    peerCallAudioDirection != linphone::MediaDirection::SendOnly) {
				const auto peerCallParams = mCore->createCallParams(peerCall);
				peerCallParams->setAudioDirection(linphone::MediaDirection::SendOnly);
				peerCall->update(peerCallParams);
			}
		} break;
		case linphone::Call::State::UpdatedByRemote: {
			// Manage add/remove video - ignore for other changes.
			const auto& peerCall = getPeerCall(call);
			if (!peerCall) return;
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
				SLOGD << FUNC_LOG_PREFIX(mLogPrefix) << ": update peer call";
				// Add this custom header so this call will not be intercepted by the B2BUA.
				peerCallParams->addCustomHeader(kCustomHeader, "ignore");
				peerCall->update(peerCallParams);
				call->deferUpdate();
			} else { // No update on video/audio status, just accept it with requested params.
				SLOGD << FUNC_LOG_PREFIX(mLogPrefix) << ": accept update without forwarding it to peer call";
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
		case linphone::Call::State::Released: {
			// If there are some data in that call, it is the first one to end.
			const auto callId = call->getCallLog()->getCallId();
			const auto peerCallEntry = mPeerCalls.find(call);
			if (peerCallEntry != mPeerCalls.cend()) {
				SLOGD << FUNC_LOG_PREFIX(mLogPrefix) << ": release peer call {ptr = " << peerCallEntry->second.lock()
				      << ", call-id = " << callId << "}";
				mPeerCalls.erase(peerCallEntry);
			} else {
				SLOGD << FUNC_LOG_PREFIX(mLogPrefix) << ": call {ptr = " << call << ", call-id = " << callId
				      << "} is in end state but it is already terminated";
			}
		} break;
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
	const auto& otherLeg = getPeerCall(call);
	if (!otherLeg) return;

	SLOGD << FUNC_LOG_PREFIX(mLogPrefix) << ": forwarding DTMF " << dtmf << " from " << call->getCallLog()->getCallId()
	      << " to " << otherLeg->getCallLog()->getCallId();
	otherLeg->sendDtmf(dtmf);
}

void B2buaServer::onSubscribeReceived(const std::shared_ptr<linphone::Core>& core,
                                      const std::shared_ptr<linphone::Event>& legAEvent,
                                      const std::string& subscribeEvent,
                                      const std::shared_ptr<const linphone::Content>& body) {
	SLOGD << FUNC_LOG_PREFIX(mLogPrefix) << ": received subscribe event " << legAEvent;
	int expires = 0;
	try {
		expires = stoi(legAEvent->getCustomHeader("Expires"));
	} catch (std::exception const& ex) {
		SLOGE << FUNC_LOG_PREFIX(mLogPrefix) << ": invalid expires in received SUBSCRIBE, deny subscription";
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

	// Create the outgoing SUBSCRIBE and copy the request address and Accept header from the incoming one.
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
	mPeerEvents[legAEvent] = {.peerEvent = legBEvent, .isLegA = true};
	mPeerEvents[legBEvent] = {.peerEvent = legAEvent, .isLegA = false};
	legAEvent->addListener(shared_from_this());
}

void B2buaServer::onSubscribeStateChanged(const std::shared_ptr<linphone::Event>& event,
                                          linphone::SubscriptionState state) {
	SLOGD << FUNC_LOG_PREFIX(mLogPrefix) << ": event " << event << " state change to " << (int)state;
	const auto eventEntry = mPeerEvents.find(event);
	if (eventEntry == mPeerEvents.cend()) return;

	const auto& eventInfo = eventEntry->second;
	if (eventInfo.isLegA) {
		if (state == linphone::SubscriptionState::Terminated) {
			// Un-SUBSCRIBE from the subscriber.
			const auto peerEvent = eventInfo.peerEvent.lock();
			if (peerEvent == nullptr) {
				SLOGE << FUNC_LOG_PREFIX(mLogPrefix) << ": peer event pointer is null for event " << event;
				return;
			}
			peerEvent->terminate();
			const auto peerEventEntry = mPeerEvents.find(peerEvent);
			if (peerEventEntry != mPeerEvents.cend()) mPeerEvents.erase(peerEventEntry);
			mPeerEvents.erase(eventEntry);
		}
	} else {
		if (state == linphone::SubscriptionState::Active) {
			// Forward the subscription acceptation.
			const auto peerEvent = eventInfo.peerEvent.lock();
			if (peerEvent == nullptr) {
				SLOGE << FUNC_LOG_PREFIX(mLogPrefix) << ": peer event pointer is null for event " << event;
				return;
			}
			peerEvent->acceptSubscription();
		} else if (state == linphone::SubscriptionState::Error) {
			// Forward the subscription error.
			const auto peerEvent = eventInfo.peerEvent.lock();
			if (peerEvent == nullptr) {
				SLOGE << FUNC_LOG_PREFIX(mLogPrefix) << ": peer event pointer is null for event " << event;
				return;
			}
			peerEvent->denySubscription(event->getReason());
		}
	}
}

// NOTIFY listener on a subscribe event.
// This is called when a SUBSCRIBE is forwarded by the B2BUA and then a NOTIFY is received for this
// subscription.
void B2buaServer::onNotifyReceived(const std::shared_ptr<linphone::Event>& event,
                                   const std::shared_ptr<const linphone::Content>& content) {
	SLOGD << FUNC_LOG_PREFIX(mLogPrefix) << ": received notify event " << event;
	const auto eventEntry = mPeerEvents.find(event);
	if (eventEntry == mPeerEvents.cend()) {
		SLOGE << FUNC_LOG_PREFIX(mLogPrefix) << ": no data associated with the event " << event
		      << ", cannot forward the NOTIFY";
		return;
	}

	// Forward NOTIFY
	const auto peerEvent = eventEntry->second.peerEvent.lock();
	if (peerEvent == nullptr) {
		SLOGE << FUNC_LOG_PREFIX(mLogPrefix) << ": peer event pointer is null for event " << event;
		return;
	}

	peerEvent->notify(content);
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
	const auto& factory = Factory::get();
	factory->setDataDir(dataDirPath + "/");

	mCore = b2bua::B2buaCore::create(*factory, *config);

	mCore->addListener(shared_from_this());

	auto applicationType = config->get<ConfigString>("application")->read();
	SLOGD << mLogPrefix << ": starting with '" << applicationType << "' application";
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
	if (mCore == nullptr) return nullptr;

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
	        "performance of the B2BUA.\n"
	        "Format: <codec>/<sample-rate>. Example: speex/8000",
	        "",
	    },
	    {
	        String,
	        "video-codec",
	        "Same as 'audio-codec' but for video.\n"
	        "Format: <codec>. Example: H264",
	        "",
	    },
	    {
	        Boolean,
	        "one-connection-per-account",
	        "Make the B2BUA use a separate connection (port) for each (external) account it manages. This can be used "
	        "to work around DoS protection and rate-limiting systems on external proxies.",
	        "false",
	    },
	    config_item_end};

	root.addChild(
	        make_unique<GenericStruct>(b2bua::configSection, "Flexisip back-to-back user agent server parameters.", 0))
	    ->addChildrenValues(items);
});

} // namespace
} // namespace flexisip