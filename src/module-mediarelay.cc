/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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

#include "mediarelay.hh"
#include "sdp-modifier.hh"
#include "transaction.hh"
#include "h264iframefilter.hh"
#include "callcontext-mediarelay.hh"

#include <vector>
#include <algorithm>


using namespace std;
using namespace ::std::placeholders;


static bool isEarlyMedia(sip_t *sip) {
	if (sip->sip_status->st_status == 180 || sip->sip_status->st_status == 183) {
		sip_payload_t *payload = sip->sip_payload;
		//TODO: should check if it is application/sdp
		return payload != NULL;
	}
	return false;
}

ModuleInfo<MediaRelay> MediaRelay::sInfo("MediaRelay", "The MediaRelay module masquerades SDP message so that all RTP and RTCP streams go through the proxy. "
		"The RTP and RTCP streams are then routed so that each client receives the stream of the other. "
		"MediaRelay makes sure that RTP is ALWAYS established, even with uncooperative firewalls.",
		ModuleInfoBase::ModuleOid::MediaRelay);

MediaRelay::MediaRelay(Agent * ag) :
		Module(ag), mCalls(NULL) {
}

MediaRelay::~MediaRelay() {
	if (mCalls)
		delete mCalls;
	mServers.clear();
}

void MediaRelay::onDeclare(GenericStruct * mc) {
	ConfigItemDescriptor items[] = {
			{ String, "nortpproxy", "SDP attribute set by the first proxy to forbid subsequent proxies to provide relay. Use 'disable' to disable.", "nortpproxy" },
			{ Integer, "sdp-port-range-min", "The minimal value of SDP port range", "1024" },
			{ Integer, "sdp-port-range-max", "The maximal value of SDP port range", "65535" },
			{ Boolean, "bye-orphan-dialogs", "Sends a ACK and BYE to 200Ok for INVITEs not belonging to any established call.", "false"},
			{ Integer, "max-calls", "Maximum concurrent calls processed by the media-relay. Calls arriving when the limit is exceed will be rejected. "
						"A value of 0 means no limit.", "0" },
			{ Boolean, "force-relay-for-non-ice-targets", "When true, the 'c=' line and port number"
				" are set to the relay ip/port even if ICE candidates are present in the request."
				" This is allow non-ice clients to have their streams relayed.", "true"},
			{ Boolean, "prevent-loops", "Prevent media-relay ports to loop between them, which can cause 100% cpu on the media relay thread."
						"You need to set this property to false if you are running test calls from clients running on the same "
						"IP address as the flexisip server" , "true"},
			{ Boolean, "early-media-relay-single", "In case multiples 183 Early media responses are received for a call, only the first one will have RTP streams forwarded back to caller. This feature prevents the caller to receive 'mixed' streams, but it breaks scenarios where multiple servers play early media announcement in sequence.", "true"},
			{ Integer, "max-early-media-per-call", "Maximum number of relayed early media streams per call. This is useful to limit the cpu usage due to early media relaying on"
				" embedded systems. A value of 0 stands for unlimited.", "0"},
#ifdef MEDIARELAY_SPECIFIC_FEATURES_ENABLED
			/*very specific features, useless for most people*/
			{ Integer, "h264-filtering-bandwidth", "Enable I-frame only filtering for video H264 for clients annoucing a total bandwith below this value expressed in kbit/s. Use 0 to disable the feature", "0" },
			{ Integer, "h264-iframe-decim", "When above option is activated, keep one I frame over this number.", "1" },
			{ Boolean, "h264-decim-only-last-proxy", "Decimate only if this server is the last proxy in the routes", "true" },
			{ Boolean, "drop-telephone-event", "Drop out telephone-events packet from incoming RTP stream for sips calls.", "false" },
#endif
			config_item_end };
	mc->addChildrenValues(items);

	auto p=mc->createStatPair("count-calls", "Number of relayed calls.");
	mCountCalls=p.first;
	mCountCallsFinished=p.second;
}

void MediaRelay::createServers(){
	int cpuCount = ModuleToolbox::getCpuCount();
	int i;
	for(i = 0; i<cpuCount; ++i){
		mServers.push_back(make_shared<MediaRelayServer>(this));
	}
	mCurServer = 0;
}

void MediaRelay::onLoad(const GenericStruct * modconf) {
	mCalls = new CallStore();
	mCalls->setCallStatCounters(mCountCalls, mCountCallsFinished);

	mSdpMangledParam = modconf->get<ConfigString>("nortpproxy")->read();
	if (mSdpMangledParam == "disable") mSdpMangledParam.clear();
	mByeOrphanDialogs = modconf->get<ConfigBoolean>("bye-orphan-dialogs")->read();
	mEarlyMediaRelaySingle = modconf->get<ConfigBoolean>("early-media-relay-single")->read();
#ifdef MEDIARELAY_SPECIFIC_FEATURES_ENABLED
	mH264FilteringBandwidth=modconf->get<ConfigInt>("h264-filtering-bandwidth")->read();
	mH264Decim=modconf->get<ConfigInt>("h264-iframe-decim")->read();
	mDropTelephoneEvent=modconf->get<ConfigBoolean>("drop-telephone-event")->read();
	mH264DecimOnlyIfLastProxy=modconf->get<ConfigBoolean>("h264-decim-only-last-proxy")->read();
#else
	mH264FilteringBandwidth=0;
	mH264Decim=0;
	mDropTelephoneEvent=false;
	mH264DecimOnlyIfLastProxy=true;
#endif
	mMinPort = modconf->get<ConfigInt>("sdp-port-range-min")->read();
	mMaxPort = modconf->get<ConfigInt>("sdp-port-range-max")->read();
	mPreventLoop = modconf->get<ConfigBoolean>("prevent-loops")->read();
	mMaxCalls=modconf->get<ConfigInt>("max-calls")->read();
	mMaxRelayedEarlyMedia = modconf->get<ConfigInt>("max-early-media-per-call")->read();
	mForceRelayForNonIceTargets = modconf->get<ConfigBoolean>("force-relay-for-non-ice-targets")->read();
	createServers();
}

void MediaRelay::onUnload() {
	if (mCalls) {
		delete mCalls;
		mCalls=NULL;
	}
	mServers.clear();
}


bool MediaRelay::processNewInvite(const shared_ptr<RelayedCall> &c, const shared_ptr<OutgoingTransaction>& transaction, const shared_ptr<RequestSipEvent> &ev) {
	sip_t *sip = ev->getMsgSip()->getSip();
	msg_t *msg = ev->getMsgSip()->getMsg();

	if (sip->sip_from == NULL || sip->sip_from->a_tag == NULL) {
		LOGW("No tag in from !");
		return false;
	}
	shared_ptr<SdpModifier> m = SdpModifier::createFromSipMsg(ev->getMsgSip()->getHome(), sip, mSdpMangledParam);
	if (m == NULL) {
		LOGW("Invalid SDP");
		return false;
	}

	string from_tag = sip->sip_from->a_tag;
	string from_host;
	if (sip->sip_via->v_received)
		from_host=getHost(sip->sip_via->v_received);
	else
		from_host=getHost(sip->sip_via->v_host);


	string to_tag;
	if (sip->sip_to->a_tag != NULL)
		to_tag = sip->sip_to->a_tag;
	string dest_host;
	if (sip->sip_request != NULL && sip->sip_request->rq_url->url_host != NULL)
		dest_host = urlGetHost(sip->sip_request->rq_url);

	if (m->hasAttribute(mSdpMangledParam.c_str())) {
		LOGD("Invite is already relayed");
		return false;
	}

	// create channels if not already existing
	c->initChannels(m, from_tag, transaction->getBranchId(), mAgent->getPreferredIp(from_host), mAgent->getPreferredIp(dest_host));

	if (!c->checkMediaValid()) {
		LOGE("The relay media are invalid, no RTP/RTCP port remaining?");
		ev->reply(500, "RTP port pool exhausted", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return false;
	}

	// assign destination address of offerer
	m->iterateInOffer(bind(&RelayedCall::setChannelDestinations, c, m, _1, _2, _3, from_tag, transaction->getBranchId(),false));

	// Masquerade using ICE
	m->addIceCandidateInOffer(bind(&RelayedCall::getChannelSources, c, _1, to_tag, transaction->getBranchId()),
			   bind(&RelayedCall::getChannelDestinations, c, _1, from_tag, transaction->getBranchId()),
			   bind(&RelayedCall::getMasqueradeContexts, c, _1, from_tag, to_tag, transaction->getBranchId()), mForceRelayForNonIceTargets);

	// Modify sdp message to set relay address and ports for streams not handled by ICE
	m->masqueradeInOffer(bind(&RelayedCall::getChannelSources, c, _1, to_tag, transaction->getBranchId()));

	if (!mSdpMangledParam.empty()) m->addAttribute(mSdpMangledParam.c_str(), "yes");
	if (m->update(msg, sip)==-1){
		LOGE("Cannot update SDP in message.");
		ev->reply(500, "Media relay SDP processing internal error", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return false;
	}
	c->getServer()->update();
	return true;
}


void MediaRelay::configureContext(shared_ptr<RelayedCall> &c){
#ifdef MEDIARELAY_SPECIFIC_FEATURES_ENABLED
	if (mH264FilteringBandwidth)
		c->enableH264IFrameFiltering(mH264FilteringBandwidth,mH264Decim,mH264DecimOnlyIfLastProxy);
	if (mDropTelephoneEvent)
		c->enableTelephoneEventDrooping(true);
#endif
}


void MediaRelay::onRequest(shared_ptr<RequestSipEvent> &ev) throw(FlexisipException) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();

	shared_ptr<RelayedCall> c;

	if (sip->sip_request->rq_method == sip_method_invite) {
		shared_ptr<IncomingTransaction> it = ev->createIncomingTransaction();
		shared_ptr<OutgoingTransaction> ot = ev->createOutgoingTransaction();
		bool newContext=false;

		c=it->getProperty<RelayedCall>(getModuleName());
		/*if the transaction has no RelayedCall associated, then look for an established dialog (case of reINVITE) */
		if (c==NULL) c=dynamic_pointer_cast<RelayedCall>(mCalls->find(getAgent(), sip, false));
		if (c==NULL) {
			if (mMaxCalls>0 && mCalls->size()>=mMaxCalls){
				LOGW("Maximum number of relayed calls reached (%i), call is rejected",mMaxCalls);
				ev->reply(503, "Maximum number of calls reached", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
				return;
			}

			c = make_shared<RelayedCall>(mServers[mCurServer], sip);
			mCurServer = (mCurServer + 1) % mServers.size();
			newContext=true;
			it->setProperty<RelayedCall>(getModuleName(), c);
			configureContext(c);
		}
		if (processNewInvite(c, ot, ev)) {
			//be in the record-route
			addRecordRouteIncoming(ev->getMsgSip()->getHome(), getAgent(),ev);
			if (newContext) mCalls->store(c);
			ot->setProperty(getModuleName(), c);
		}
	}else if (sip->sip_request->rq_method == sip_method_bye) {
		if ((c = dynamic_pointer_cast<RelayedCall>(mCalls->findEstablishedDialog(getAgent(), sip))) != NULL) {
			mCalls->remove(c);
		}
	}else if (sip->sip_request->rq_method == sip_method_cancel) {
		shared_ptr<IncomingTransaction> it=dynamic_pointer_cast<IncomingTransaction>(ev->getIncomingAgent());
		/* need to match cancel from incoming transaction, because in this case the entire call context can be dropped immediately*/
		if (it && (c = it->getProperty<RelayedCall>(getModuleName())) != NULL){
			LOGD("Relayed call terminated by incoming cancel.");
			mCalls->remove(c);
		}
	}
}

void MediaRelay::processResponseWithSDP(const shared_ptr<RelayedCall> &c, const shared_ptr<OutgoingTransaction>& transaction, const shared_ptr<MsgSip> &msgSip) {
	sip_t *sip = msgSip->getSip();
	msg_t *msg = msgSip->getMsg();
	bool isEarlyMedia=false;

	LOGD("Processing 200 Ok or early media");

	if (sip->sip_to == NULL || sip->sip_to->a_tag == NULL) {
		LOGW("No tag in answer");
		return;
	}

	if (sip->sip_status->st_status==200){
		if (!c->isDialogEstablished()) c->establishDialogWith200Ok(getAgent(),sip);
		c->setEstablished(transaction->getBranchId());
	}else isEarlyMedia=true;

	shared_ptr<SdpModifier> m = SdpModifier::createFromSipMsg(msgSip->getHome(), sip, mSdpMangledParam);
	if (m == NULL) {
		LOGW("Invalid SDP");
		return;
	}

	string to_tag;
	if (sip->sip_to != NULL && sip->sip_to->a_tag != NULL)
		to_tag = sip->sip_to->a_tag;


	if (m->hasAttribute(mSdpMangledParam.c_str())) {
		LOGD("200 OK is already relayed");
		return;
	}
	//acquire destination ip/ports from answerer
	m->iterateInAnswer(bind(&RelayedCall::setChannelDestinations, c, m, _1, _2, _3, to_tag, transaction->getBranchId(),isEarlyMedia));

	//push ICE relay candidates if necessary, and update the ICE states.
	m->addIceCandidateInAnswer(bind(&RelayedCall::getChannelSources, c, _1, sip->sip_from->a_tag, transaction->getBranchId()),
		bind(&RelayedCall::getChannelDestinations, c, _1, to_tag, transaction->getBranchId()),
		bind(&RelayedCall::getMasqueradeContexts, c, _1, sip->sip_from->a_tag, to_tag, transaction->getBranchId()), mForceRelayForNonIceTargets);

	// masquerade c lines and ports for streams not handled by ICE.
	m->masqueradeInAnswer(bind(&RelayedCall::getChannelSources, c, _1, sip->sip_from->a_tag, transaction->getBranchId()));
	m->update(msg, sip);
}

void MediaRelay::onResponse(shared_ptr<ResponseSipEvent> &ev) throw (FlexisipException) {
	shared_ptr<MsgSip> ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
	msg_t *msg = ms->getMsg();
	shared_ptr<RelayedCall> c;

	// Handle SipEvent associated with a Stateful transaction
	shared_ptr<OutgoingTransaction> ot=dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
	shared_ptr<IncomingTransaction> it=dynamic_pointer_cast<IncomingTransaction>(ev->getIncomingAgent());

	if (ot != NULL) {
		c = ot->getProperty<RelayedCall>(getModuleName());
		if (c) {
			if (sip->sip_cseq && sip->sip_cseq->cs_method == sip_method_invite) {
				fixAuthChallengeForSDP(ms->getHome(), msg, sip);
				if (sip->sip_status->st_status == 200 || isEarlyMedia(sip)) {
					processResponseWithSDP(c, ot, ev->getMsgSip());
				} else if (sip->sip_status->st_status >= 300) {
					c->removeBranch(ot->getBranchId());
				}
			}
		}
	}

	if (it && (c = it->getProperty<RelayedCall>(getModuleName()))!=NULL){
		//This is a response sent to the incoming transaction.
		LOGD("call context %p",c.get());
		if (sip->sip_cseq && sip->sip_cseq->cs_method == sip_method_invite){
			//Check for failure code, in which case the call context can be destroyed immediately.
			if ( sip->sip_status->st_status >= 300){
				if (!c->isDialogEstablished()){
					LOGD("RelayedCall is terminated by final error response");
					mCalls->remove(c);
				}
			}else if (sip->sip_status->st_status < 200){
				//ensure that a single early media response is forwarded, otherwise it will be conflicting with the early-media forking
				//feature of the MediaRelay module.
				auto last_response = it->getLastResponse();
				if (last_response && isEarlyMedia(last_response->getSip()))
					ev->terminateProcessing();
			}
		}
	}

	if (ot==NULL && it==NULL && sip->sip_cseq && sip->sip_cseq->cs_method == sip_method_invite && sip->sip_status->st_status == 200) {
		//Out of transaction 200Ok for invite.
		//Check if it matches an established dialog whose to-tag is different, then it is a 200Ok sent by the client
		//before receiving the Cancel.

		shared_ptr<CallContextBase> ccb=mCalls->findEstablishedDialog(getAgent(),sip);
		if (ccb){
			/*to-tag do match, this looks like a retransmission of 200Ok. We should re-send the last 200Ok instead of letting it pass
			* with unconsistent data in SDP.
			* It is then better to discard it.
			* Retransmission should be needed for UDP only.
			*/
			ev->terminateProcessing();
		}else if (mByeOrphanDialogs && mCalls->find(getAgent(),sip,true)!=NULL){
			/* There a dialog with this call-id, but this 200Ok does not belong to it.
			 * This is the case if two callers accept a forked call at the same time*/
			LOGD("Receiving out of transaction and dialog 200Ok for invite, rejecting it.");
			nta_msg_ackbye(getAgent()->getSofiaAgent(),msg_dup(msg));
			ev->terminateProcessing();
		}
	}
}

void MediaRelay::onIdle() {
	mCalls->dump();
	mCalls->removeAndDeleteInactives();
	if (mCalls->size() > 0)
		LOGD("There are %i calls active in the MediaRelay call list.",mCalls->size());
}
