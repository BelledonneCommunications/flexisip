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

#include "mediarelay.hh"

#include <vector>

#include "callcontext-mediarelay.hh"
#include "fork-context/fork-context.hh"
#include "module-toolbox.hh"
#include "sdp-modifier.hh"
#include "transaction/incoming-transaction.hh"
#include "transaction/outgoing-transaction.hh"

using namespace std;
using namespace ::std::placeholders;
using namespace flexisip;

namespace {

bool isEarlyMedia(sip_t* sip) {
	if (sip->sip_status->st_status == 180 || sip->sip_status->st_status == 183) {
		sip_payload_t* payload = sip->sip_payload;
		// TODO: should check if it is application/sdp
		return payload != nullptr;
	}
	return false;
}

bool isInviteOrUpdate(sip_method_t method) {
	return method == sip_method_invite || method == sip_method_update;
}

} // namespace

ModuleInfo<MediaRelay> MediaRelay::sInfo(
    "MediaRelay",
    "The MediaRelay module masquerades SDP message so that all RTP and RTCP streams go through the proxy. "
    "When the client has set ICE candidates in the SDP offer, then the MediaRelay module will automatically add ICE "
    "relay candidates. "
    "The RTP and RTCP streams are then routed so that each client receives the stream of the other. "
    "MediaRelay makes sure that RTP is ALWAYS established, even with uncooperative firewalls.",
    {"LoadBalancer"},
    ModuleInfoBase::ModuleOid::MediaRelay,

    [](GenericStruct& moduleConfig) {
	    ConfigItemDescriptor items[] = {
	        {
	            String,
	            "nortpproxy",
	            "The name of the SDP attribute to set by the first proxy to forbid subsequent proxies to provide "
	            "relay. "
	            "Use 'disable' to disable.",
	            "nortpproxy",
	        },
	        {
	            Integer,
	            "sdp-port-range-min",
	            "The minimal value of SDP port range",
	            "1024",
	        },
	        {
	            Integer,
	            "sdp-port-range-max",
	            "The maximal value of SDP port range",
	            "65535",
	        },
	        {
	            Boolean,
	            "bye-orphan-dialogs",
	            "Sends a ACK and BYE to 200Ok for INVITEs not belonging to any established call. This is to solve the "
	            "race "
	            "condition that happens when two callees answer the same call at the same time. According to RFC3261, "
	            "the "
	            "caller is expected to send an ACK followed by a BYE to the loser callee. This is not the case in "
	            "RFC2543, "
	            "where the proxy was supposed to do this. When set to true, the MediaRelay module will implement the "
	            "RFC2543 behavior. Note that it may sound inappropriate to bundle this property with the media relay "
	            "feature. However the MediaRelay module is the only one in Flexisip that has the visibility of SIP "
	            "dialogs, "
	            "which is necessary to implement this feature.",
	            "false",
	        },
	        {
	            Integer,
	            "max-calls",
	            "Maximum concurrent calls processed by the media-relay. Calls arriving when the limit is exceed will "
	            "be "
	            "rejected. A value of 0 means no limit.",
	            "0",
	        },
	        {
	            Boolean,
	            "force-relay-for-non-ice-targets",
	            "When true, the 'c=' line and port number are set to the relay ip/port even if ICE candidates are "
	            "present "
	            "in the request, while the standard behavior is to leave the c= line and port number as they are in "
	            "the "
	            "original offer sent by the client. This variation allows callees that do not support ICE at all to "
	            "benefit from the media relay service.",
	            "true",
	        },
	        {
	            Boolean,
	            "prevent-loops",
	            "Prevent media-relay ports to loop between them, which can cause 100% cpu on the media relay thread. "
	            "You "
	            "need to set this property to false if you are running test calls from clients running on the same IP "
	            "address as the flexisip server",
	            "true",
	        },
	        {
	            Boolean,
	            "early-media-relay-single",
	            "In case multiples '183 Early media' responses are received for a call, only the first one will have "
	            "RTP "
	            "streams forwarded back to caller. This feature prevents the caller to receive 'mixed' streams, but it "
	            "breaks scenarios where multiple servers play early media announcement in sequence.",
	            "true",
	        },
	        {
	            Integer,
	            "max-early-media-per-call",
	            "Maximum number of relayed early media streams per call. This is useful to limit the cpu usage due to "
	            "early media relaying on embedded systems. A value of 0 stands for unlimited.",
	            "0",
	        },
	        {
	            DurationS,
	            "inactivity-period",
	            "Period of time after which a relayed call without any activity is considered as no longer "
	            "running. Activity counts RTP/RTCP packets exchanged through the relay and SIP messages.",
	            "3600",
	        },
	        {
	            Boolean,
	            "force-public-ip-for-sdp-masquerading",
	            "Force the media relay to use the public address of Flexisip to relay calls. It not enabled, Flexisip "
	            "will deduce a suitable IP address by basing on data from SIP messages, which could fail in tricky "
	            "situations e.g. when Flexisip is behind a TCP proxy.",
	            "false",
	        },
#ifdef MEDIARELAY_SPECIFIC_FEATURES_ENABLED
	        /*very specific features, useless for most people*/
	        {
	            Integer,
	            "h264-filtering-bandwidth",
	            "Enable I-frame only filtering for video H264 for clients annoucing a total bandwith below this value "
	            "expressed in kbit/s. Use 0 to disable the feature",
	            "0",
	        },
	        {Integer, "h264-iframe-decim", "When above option is activated, keep one I-frame over this number.", "1"},
	        {
	            Boolean,
	            "h264-decim-only-last-proxy",
	            "Decimate only if this server is the last proxy in the routes.",
	            "true",
	        },
	        {
	            Boolean,
	            "drop-telephone-event",
	            "Drop out telephone-events packet from incoming RTP stream for sips calls.",
	            "false",
	        },
#endif
	        config_item_end,
	    };
	    moduleConfig.addChildrenValues(items);
	    moduleConfig.createStatPair("count-calls", "Number of relayed calls.");
    });

MediaRelay::MediaRelay(Agent* ag, const ModuleInfoBase* moduleInfo) : Module(ag, moduleInfo), mCalls(NULL) {
	auto p = mModuleConfig->getStatPair("count-calls");
	mCountCalls = p.first;
	mCountCallsFinished = p.second;
}

MediaRelay::~MediaRelay() {
	if (mCalls) delete mCalls;
	mServers.clear();
}

void MediaRelay::createServers() {
	int cpuCount = ModuleToolbox::getCpuCount();
	int i;
	for (i = 0; i < cpuCount; ++i) {
		mServers.push_back(make_shared<MediaRelayServer>(this));
	}
	mCurServer = 0;
}

void MediaRelay::onLoad(const GenericStruct* modconf) {
	mCalls = new CallStore();
	mCalls->setCallStatCounters(mCountCalls, mCountCallsFinished);

	mSdpMangledParam = modconf->get<ConfigString>("nortpproxy")->read();
	if (mSdpMangledParam == "disable") mSdpMangledParam.clear();
	mByeOrphanDialogs = modconf->get<ConfigBoolean>("bye-orphan-dialogs")->read();
	mEarlyMediaRelaySingle = modconf->get<ConfigBoolean>("early-media-relay-single")->read();
#ifdef MEDIARELAY_SPECIFIC_FEATURES_ENABLED
	mH264FilteringBandwidth = modconf->get<ConfigInt>("h264-filtering-bandwidth")->read();
	mH264Decim = modconf->get<ConfigInt>("h264-iframe-decim")->read();
	mDropTelephoneEvent = modconf->get<ConfigBoolean>("drop-telephone-event")->read();
	mH264DecimOnlyIfLastProxy = modconf->get<ConfigBoolean>("h264-decim-only-last-proxy")->read();
#else
	mH264FilteringBandwidth = 0;
	mH264Decim = 0;
	mDropTelephoneEvent = false;
	mH264DecimOnlyIfLastProxy = true;
#endif
	mMinPort = modconf->get<ConfigInt>("sdp-port-range-min")->read();
	mMaxPort = modconf->get<ConfigInt>("sdp-port-range-max")->read();
	mPreventLoop = modconf->get<ConfigBoolean>("prevent-loops")->read();
	mMaxCalls = modconf->get<ConfigInt>("max-calls")->read();
	mMaxRelayedEarlyMedia = modconf->get<ConfigInt>("max-early-media-per-call")->read();
	mForceRelayForNonIceTargets = modconf->get<ConfigBoolean>("force-relay-for-non-ice-targets")->read();
	mUsePublicIpForSdpMasquerading = modconf->get<ConfigBoolean>("force-public-ip-for-sdp-masquerading")->read();
	mInactivityPeriod = chrono::duration_cast<chrono::seconds>(
	                        modconf->get<ConfigDuration<chrono::seconds>>("inactivity-period")->read())
	                        .count();
	createServers();
}

void MediaRelay::onUnload() {
	if (mCalls) {
		delete mCalls;
		mCalls = NULL;
	}
	mServers.clear();
}

bool MediaRelay::processNewInvite(const shared_ptr<RelayedCall>& c,
                                  const shared_ptr<OutgoingTransaction>& transaction,
                                  RequestSipEvent& ev) {
	sip_t* sip = ev.getMsgSip()->getSip();
	msg_t* msg = ev.getMsgSip()->getMsg();

	if (sip->sip_from == NULL || sip->sip_from->a_tag == NULL) {
		LOGW << "No tag in 'From' header";
		return false;
	}
	c->updateActivity();
	shared_ptr<SdpModifier> m = SdpModifier::createFromSipMsg(ev.getMsgSip()->getHome(), sip, mSdpMangledParam);
	if (m == NULL) {
		LOGD << "Invalid SDP";
		return false;
	}

	string from_tag = sip->sip_from->a_tag;
	string from_host;
	sip_via_t* last_via =
	    ModuleToolbox::getLastVia(sip); /*the last via of the message is the originator of the message.*/
	if (last_via->v_received) from_host = ModuleToolbox::getHost(last_via->v_received);
	else from_host = ModuleToolbox::getHost(last_via->v_host);

	string to_tag;
	if (sip->sip_to->a_tag != NULL) to_tag = sip->sip_to->a_tag;
	string dest_host;

	/*get the next hop of the message to make the best guess about the local network interface to use for media relay*/
	sip_route_t* route = sip->sip_route;
	while (route != NULL && mAgent->isUs(route->r_url)) {
		route = route->r_next;
	}
	if (route) {
		dest_host = ModuleToolbox::urlGetHost(route->r_url);
	} else if (sip->sip_request != NULL && sip->sip_request->rq_url->url_host != NULL) {
		dest_host = ModuleToolbox::urlGetHost(sip->sip_request->rq_url);
	}

	if (m->hasAttribute(mSdpMangledParam.c_str())) {
		LOGD << "Invite is already relayed";
		return false;
	}

	// create channels if not already existing
	c->initChannels(m, from_tag, transaction->getBranchId(), from_host, dest_host);

	if (!c->checkMediaValid()) {
		LOGE << "Relay media are invalid (no RTP/RTCP port remaining?)";
		if (auto forkContext = ForkContext::getFork(transaction)) {
			forkContext->processInternalError(500, "RTP port pool exhausted");
			ev.terminateProcessing();
		} else {
			ev.reply(500, "RTP port pool exhausted", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		}
		return false;
	}

	// assign destination address of offerer
	const auto& transactionId = transaction->getBranchId();
	m->iterateInOffer([c, m, &from_tag, &transactionId](int sessionId, const string& ip, int rtpPort, int rtcpPort) {
		c->setChannelDestinations(m, sessionId, ip, rtpPort, rtcpPort, from_tag, transactionId, false);
	});

	// Masquerade using ICE
	const auto& getChannelSources = [c, &to_tag, &transactionId](int sessionId) {
		return c->getChannelSources(sessionId, to_tag, transactionId);
	};
	m->addIceCandidateInOffer(
	    getChannelSources,
	    [c, &from_tag, &transactionId](int sessionId) {
		    return c->getChannelDestinations(sessionId, from_tag, transactionId);
	    },
	    [c, &from_tag, &to_tag, &transactionId](int sessionId) {
		    return c->getMasqueradeContexts(sessionId, from_tag, to_tag, transactionId);
	    },
	    mForceRelayForNonIceTargets);

	// Modify sdp message to set relay address and ports for streams not handled by ICE
	m->masqueradeInOffer(getChannelSources);

	if (!mSdpMangledParam.empty()) m->addAttribute(mSdpMangledParam.c_str(), "yes");
	if (m->update(msg, sip) == -1) {
		LOGE << "Cannot update SDP in message";
		ev.reply(500, "Media relay SDP processing internal error", SIPTAG_SERVER_STR(getAgent()->getServerString()),
		         TAG_END());
		return false;
	}
	c->getServer()->update();
	return true;
}

void MediaRelay::configureContext([[maybe_unused]] shared_ptr<RelayedCall>& c) {
#ifdef MEDIARELAY_SPECIFIC_FEATURES_ENABLED
	if (mH264FilteringBandwidth)
		c->enableH264IFrameFiltering(mH264FilteringBandwidth, mH264Decim, mH264DecimOnlyIfLastProxy);
	if (mDropTelephoneEvent) c->enableTelephoneEventDrooping(true);
#endif
}

unique_ptr<RequestSipEvent> MediaRelay::onRequest(unique_ptr<RequestSipEvent>&& ev) {
	auto* sip = ev->getSip();
	auto method = sip->sip_request->rq_method;
	if (method == sip_method_bye) {
		if (const auto relayedCall =
		        dynamic_pointer_cast<RelayedCall>(mCalls->findEstablishedDialog(getAgent(), sip))) {
			mCalls->remove(relayedCall);
		}
		return std::move(ev);
	}

	auto incomingTransaction = ev->getIncomingTransaction();
	auto relayedCall = incomingTransaction ? incomingTransaction->getProperty<RelayedCall>(getModuleName()) : nullptr;
	if (method == sip_method_cancel) {
		if (relayedCall) {
			LOGD << "Relayed call terminated by incoming cancel";
			mCalls->remove(relayedCall);
		}
		return std::move(ev);
	}

	if (!isInviteOrUpdate(method)) return std::move(ev);

	if (!incomingTransaction && ForkContext::getFork(ev->getOutgoingTransaction())) {
		// The request has been reinjected. If there's no incoming transaction, then there is nothing to relay.
		// (Most likely an INVITE/CANCEL scenario. Creating an incoming transaction now would only leak it, as no-one is
		// going to send it a terminating answer.)
		LOGD << "Skipping re-injected INVITE.";
		return std::move(ev);
	}

	// Force stateful mode to store the RelayedCall context.
	incomingTransaction = ev->createIncomingTransaction();
	auto outgoingTransaction = ev->createOutgoingTransaction();

	auto newContext = false;
	// If the transaction has no RelayedCall associated, then look for an established dialog (case of reINVITE)
	if (relayedCall == nullptr) relayedCall = dynamic_pointer_cast<RelayedCall>(mCalls->find(getAgent(), sip, false));
	if (relayedCall == nullptr) {
		if (mMaxCalls > 0 && mCalls->size() >= mMaxCalls) {
			LOGW << "Maximum number of relayed calls reached (" << mMaxCalls << "), call is rejected";
			ev->reply(503, "Maximum number of calls reached", SIPTAG_SERVER_STR(getAgent()->getServerString()),
			          TAG_END());
			return {};
		}

		relayedCall = make_shared<RelayedCall>(mServers[mCurServer], sip);
		relayedCall->forcePublicAddress(mUsePublicIpForSdpMasquerading);
		mCurServer = (mCurServer + 1) % mServers.size();
		newContext = true;
		incomingTransaction->setProperty(getModuleName(), weak_ptr<RelayedCall>{relayedCall});
		configureContext(relayedCall);
	}
	if (processNewInvite(relayedCall, outgoingTransaction, *ev)) {
		// Be in the record-route
		ModuleToolbox::addRecordRouteIncoming(getAgent(), *ev);
		if (newContext) mCalls->store(relayedCall);
		outgoingTransaction->setProperty(getModuleName(), weak_ptr<RelayedCall>{relayedCall});
		// Let this transaction survive till it reaches the Forward module.
		// Otherwise a new `OutgoingTransaction` will be created to send the request, but it won't have the
		// `RelayedCall` back-pointer
		relayedCall->mCurrentOutgoingTransaction = std::move(outgoingTransaction);
	}

	return std::move(ev);
}

void MediaRelay::processResponseWithSDP(const shared_ptr<RelayedCall>& c,
                                        const shared_ptr<OutgoingTransaction>& transaction,
                                        const shared_ptr<MsgSip>& msgSip) {
	sip_t* sip = msgSip->getSip();
	msg_t* msg = msgSip->getMsg();
	bool isEarlyMedia = false;

	LOGD << "Processing 200 Ok or early media";

	if (sip->sip_to == NULL || sip->sip_to->a_tag == NULL) {
		LOGD << "No tag in answer";
		return;
	}

	if (sip->sip_status->st_status == 200) {
		if (!c->isDialogEstablished()) c->establishDialogWith200Ok(getAgent(), sip);
		c->setEstablished(transaction->getBranchId());
	} else isEarlyMedia = true;

	shared_ptr<SdpModifier> m = SdpModifier::createFromSipMsg(msgSip->getHome(), sip, mSdpMangledParam);
	if (m == NULL) {
		LOGD << "Invalid SDP";
		return;
	}

	if (m->hasAttribute(mSdpMangledParam.c_str())) {
		LOGD << "200 OK is already relayed";
		return;
	}

	string to_tag;
	if (sip->sip_to != NULL && sip->sip_to->a_tag != NULL) to_tag = sip->sip_to->a_tag;

	const auto& from_tag = string(sip->sip_from->a_tag);
	const auto getMasqueradeContexts = [&c = *c, &from_tag, &to_tag,
	                                    &branchId = transaction->getBranchId()](int lineNo) {
		return c.getMasqueradeContexts(lineNo, from_tag, to_tag, branchId);
	};

	// Sanitize before further processing
	m->cleanUpIceCandidatesInAnswer(getMasqueradeContexts);

	// acquire destination ip/ports from answerer
	const auto& transactionId = transaction->getBranchId();
	m->iterateInAnswer(
	    [c, m, &to_tag, &transactionId, isEarlyMedia](int sessionId, const string& ip, int rtpPort, int rtcpPort) {
		    c->setChannelDestinations(m, sessionId, ip, rtpPort, rtcpPort, to_tag, transactionId, isEarlyMedia);
	    });

	// push ICE relay candidates if necessary, and update the ICE states.
	const auto& getChannelSources = [c, &from_tag, &transactionId](int sessionId) {
		return c->getChannelSources(sessionId, from_tag, transactionId);
	};
	m->addIceCandidateInAnswer(
	    getChannelSources,
	    [c, &to_tag, &transactionId](int sessionId) {
		    return c->getChannelDestinations(sessionId, to_tag, transactionId);
	    },
	    getMasqueradeContexts, mForceRelayForNonIceTargets);

	// masquerade c lines and ports for streams not handled by ICE.
	m->masqueradeInAnswer(getChannelSources);
	m->update(msg, sip);
}

unique_ptr<ResponseSipEvent> MediaRelay::onResponse(unique_ptr<ResponseSipEvent>&& ev) {
	shared_ptr<MsgSip> ms = ev->getMsgSip();
	sip_t* sip = ms->getSip();
	msg_t* msg = ms->getMsg();
	shared_ptr<RelayedCall> c;

	// Handle SipEvent associated with a Stateful transaction
	shared_ptr<OutgoingTransaction> ot = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
	shared_ptr<IncomingTransaction> it = dynamic_pointer_cast<IncomingTransaction>(ev->getIncomingAgent());

	if (ot != nullptr) {
		c = ot->getProperty<RelayedCall>(getModuleName());
		if (c && sip->sip_cseq && isInviteOrUpdate(sip->sip_cseq->cs_method)) {
			ModuleToolbox::fixAuthChallengeForSDP(ms->getHome(), msg, sip);
			if (sip->sip_status->st_status == 200 || isEarlyMedia(sip)) {
				processResponseWithSDP(c, ot, ev->getMsgSip());
			} else if (sip->sip_status->st_status >= 300) {
				c->removeBranch(ot->getBranchId());
				const auto hasActiveBranches =
				    std::any_of(c->getSessions().begin(), c->getSessions().end(),
				                [](const auto& session) { return session && (0 < session->getActiveBranchesCount()); });
				if (!hasActiveBranches) {
					LOGD << "RelayedCall[" << c << "] terminated: Last branch removed.";
					mCalls->remove(c);
				}
			}
		}
	}

	if (it && (c = it->getProperty<RelayedCall>(getModuleName())) != NULL) {
		// This is a response sent to the incoming transaction.
		LOGD << "Call context " << c.get();
		if (sip->sip_cseq && isInviteOrUpdate(sip->sip_cseq->cs_method)) {
			// Check for failure code, in which case the call context can be destroyed immediately.
			if (sip->sip_status->st_status >= 300) {
				if (!c->isDialogEstablished()) {
					LOGD << "RelayedCall is terminated by final error response";
					mCalls->remove(c);
				}
			} else if (sip->sip_status->st_status < 200) {
				// ensure that a single early media response is forwarded, otherwise it will be conflicting with the
				// early-media forking feature of the MediaRelay module.
				auto last_response = it->getLastResponse();
				if (last_response && isEarlyMedia(last_response->getSip())) ev->terminateProcessing();
			}
		}
	}

	if (ot == NULL && it == NULL && sip->sip_cseq && isInviteOrUpdate(sip->sip_cseq->cs_method) &&
	    sip->sip_status->st_status == 200) {
		// Out of transaction 200Ok for invite.
		// Check if it matches an established dialog whose to-tag is different, then it is a 200Ok sent by the client
		// before receiving the Cancel.

		shared_ptr<CallContextBase> ccb = mCalls->findEstablishedDialog(getAgent(), sip);
		if (ccb) {
			/*to-tag do match, this looks like a retransmission of 200Ok. We should re-send the last 200Ok instead of
			 * letting it pass with unconsistent data in SDP. It is then better to discard it. Retransmission should be
			 * needed for UDP only.
			 */
			ev->terminateProcessing();
		} else if (mByeOrphanDialogs && mCalls->find(getAgent(), sip, true) != NULL) {
			/* There a dialog with this call-id, but this 200Ok does not belong to it.
			 * This is the case if two callers accept a forked call at the same time*/
			LOGD << "Receiving out of transaction and dialog 200Ok for invite, rejecting it";
			nta_msg_ackbye(getAgent()->getSofiaAgent(), msg_dup(msg));
			ev->terminateProcessing();
		}
	}
	return std::move(ev);
}

void MediaRelay::onIdle() {
	mCalls->dump();
	mCalls->removeAndDeleteInactives(mInactivityPeriod);
	if (mCalls->size() > 0) LOGI << "There are " << mCalls->size() << " calls active in the MediaRelay call list";
}