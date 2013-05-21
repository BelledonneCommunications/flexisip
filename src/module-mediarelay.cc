/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2010  Belledonne Communications SARL.

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

#include "module.hh"
#include "agent.hh"
#include "mediarelay.hh"
#include "callstore.hh"
#include "sdp-modifier.hh"
#include "transaction.hh"
#include "h264iframefilter.hh"
#include "callcontext-mediarelay.hh"

#include <vector>
#include <algorithm>


using namespace ::std;
using namespace ::std::placeholders;

class MediaRelay: public Module, protected ModuleToolbox {
	StatCounter64 *mCountCalls;
	StatCounter64 *mCountCallsFinished;
public:
	MediaRelay(Agent *ag);
	~MediaRelay();
	virtual void onLoad(const GenericStruct * modconf);
	virtual void onUnload();
	virtual void onRequest(shared_ptr<RequestSipEvent> &ev);
	virtual void onResponse(shared_ptr<ResponseSipEvent> &ev);
	virtual void onTransactionEvent(shared_ptr<TransactionEvent> ev);
	virtual void onIdle();
protected:
	virtual void onDeclare(GenericStruct * mc) {
		ConfigItemDescriptor items[] = {
				{ String, "nortpproxy", "SDP attribute set by the first proxy to forbid subsequent proxies to provide relay.", "nortpproxy" },
				{ String, "early-media-rtp-dir", "Set the RTP direction during early media state (duplex, forward)", "duplex" },
				{ Integer, "sdp-port-range-min", "The minimal value of SDP port range", "1024" },
				{ Integer, "sdp-port-range-max", "The maximal value of SDP port range", "65535" },
				{ Boolean, "bye-orphan-dialogs", "Sends a ACK and BYE to 200Ok for INVITEs not belonging to any established call.", "false"},
				{ Integer, "max-calls", "Maximum concurrent calls processed by the media-relay. Calls arriving when the limit is exceed will be rejected. "
							"A value of 0 means no limit.", "0" },
#ifdef MEDIARELAY_SPECIFIC_FEATURES_ENABLED
				/*very specific features, useless for most people*/
				{ Integer, "h264-filtering-bandwidth", "Enable I-frame only filtering for video H264 for clients annoucing a total bandwith below this value expressed in kbit/s. Use 0 to disable the feature", "0" },
				{ Integer, "h264-iframe-decim", "When above option is activated, keep one I frame over this number.", "1" },
				{ Boolean, "drop-telephone-event", "Drop out telephone-events packet from incoming RTP stream for sips calls.", "false" },
#endif
				config_item_end };
		mc->addChildrenValues(items);

		auto p=mc->createStatPair("count-calls", "Number of relayed calls.");
		mCountCalls=p.first;
		mCountCallsFinished=p.second;
	}
private:
	bool processNewInvite(const shared_ptr<RelayedCall> &c, const shared_ptr<OutgoingTransaction>& transaction, const shared_ptr<RequestSipEvent> &ev);
	void process200OkforInvite(const shared_ptr<RelayedCall> &c, const shared_ptr<OutgoingTransaction>& transaction, const shared_ptr<MsgSip> &msgSip);
	void processFailureForInvite(const shared_ptr<RelayedCall> &c, const shared_ptr<OutgoingTransaction>& transaction, const shared_ptr<MsgSip> &msgSip);
	void configureContext(shared_ptr<RelayedCall> &c); 
	CallStore *mCalls;
	MediaRelayServer *mServer;
	string mSdpMangledParam;
	RelayedCall::RTPDir mEarlymediaRTPDir;
	int mH264FilteringBandwidth;
	int mH264Decim;
	int mMaxCalls;
	bool mDropTelephoneEvent;
	bool mByeOrphanDialogs;
	static ModuleInfo<MediaRelay> sInfo;
};


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
		Module(ag), mCalls(NULL), mServer(NULL) {
}

MediaRelay::~MediaRelay() {
	if (mCalls)
		delete mCalls;
	if (mServer)
		delete mServer;
}

void MediaRelay::onLoad(const GenericStruct * modconf) {
	mCalls = new CallStore();
	mCalls->setCallStatCounters(mCountCalls, mCountCallsFinished);
	mServer = new MediaRelayServer(mAgent);
	mSdpMangledParam = modconf->get<ConfigString>("nortpproxy")->read();
	string rtpdir = modconf->get<ConfigString>("early-media-rtp-dir")->read();
	mByeOrphanDialogs = modconf->get<ConfigBoolean>("bye-orphan-dialogs")->read();
#ifdef MEDIARELAY_SPECIFIC_FEATURES_ENABLED
	mH264FilteringBandwidth=modconf->get<ConfigInt>("h264-filtering-bandwidth")->read();
	mH264Decim=modconf->get<ConfigInt>("h264-iframe-decim")->read();
	mDropTelephoneEvent=modconf->get<ConfigBoolean>("drop-telephone-event")->read();
#else
	mH264FilteringBandwidth=0;
	mH264Decim=0;
	mDropTelephoneEvent=false;
#endif
	mMaxCalls=modconf->get<ConfigInt>("max-calls")->read();
	mEarlymediaRTPDir = RelayedCall::RelayedCall::DUPLEX;
	if (rtpdir == "duplex") {
		mEarlymediaRTPDir = RelayedCall::DUPLEX;
	} else if (rtpdir == "forward") {
		mEarlymediaRTPDir = RelayedCall::FORWARD;
	} else {
		LOGW("Wrong value %s for early-media-rtp-dir entry; switch to RelayedCall::DUPLEX.", rtpdir.c_str());
	}
}

void MediaRelay::onUnload() {
	if (mCalls) {
		delete mCalls;
		mCalls=NULL;
	}
	if (mServer) {
		delete mServer;
		mServer=NULL;
	}
}


bool MediaRelay::processNewInvite(const shared_ptr<RelayedCall> &c, const shared_ptr<OutgoingTransaction>& transaction, const shared_ptr<RequestSipEvent> &ev) {
	sip_t *sip = ev->getMsgSip()->getSip();
	msg_t *msg = ev->getMsgSip()->getMsg();

	if (sip->sip_from == NULL || sip->sip_from->a_tag == NULL) {
		LOGW("No tag in from !");
		return false;
	}
	SdpModifier *m = SdpModifier::createFromSipMsg(c->getHome(), sip);
	if (m == NULL) {
		LOGW("Invalid SDP");
		return false;
	}

	string from_tag;
	if (sip->sip_from != NULL && sip->sip_from->a_tag != NULL)
		from_tag = sip->sip_from->a_tag;
	string from_host;
	if (sip->sip_from != NULL && sip->sip_from->a_url != NULL && sip->sip_from->a_url->url_host != NULL)
		from_host = sip->sip_contact->m_url->url_host;
	string to_tag;
	if (sip->sip_to != NULL && sip->sip_to->a_tag != NULL)
		to_tag = sip->sip_to->a_tag;
	string invite_host;
	if (sip->sip_request != NULL && sip->sip_request->rq_url != NULL && sip->sip_request->rq_url->url_host != NULL)
		invite_host = sip->sip_request->rq_url->url_host;

	if (m->hasAttribute(mSdpMangledParam.c_str())) {
		LOGD("Invite is already relayed");
		delete m;
		return false;
	}

	// Create Media
	if (c->getCallerTag() == from_tag){
		c->initChannels(m, to_tag, transaction, mAgent->getPreferredIp(from_host), mAgent->getPreferredIp(invite_host));
	}else{
		c->initChannels(m, from_tag, transaction, mAgent->getPreferredIp(invite_host), mAgent->getPreferredIp(from_host));
	}

	if (!c->checkMediaValid()) {
		LOGE("The relay media are invalid, no RTP/RTCP port remaining?");
		delete m;
		ev->reply(500, "RTP port pool exhausted", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return false;
	}

	// Set
	if (c->getCallerTag() == from_tag)
		m->iterate(bind(&RelayedCall::assignFrontChannel, c, m, _1, _2, _3));
	else
		m->iterate(bind(&RelayedCall::assignBackChannel, c, m, _1, _2, _3, from_tag, ref(transaction)));

	// Translate
	if (c->getCallerTag() == from_tag)
		m->masquerade(bind(&RelayedCall::masqueradeForBack, c, _1, _2, _3, to_tag, ref(transaction)));
	else
		m->masquerade(bind(&RelayedCall::masqueradeForFront, c, _1, _2, _3));

	// Masquerade using ICE
	if (c->getCallerTag() == from_tag)
		m->addIceCandidate(bind(&RelayedCall::masqueradeForBack, c, _1, _2, _3, to_tag, ref(transaction)),
			bind(&RelayedCall::masqueradeIceForFront, c, _1, _2, _3));
	else
		m->addIceCandidate(bind(&RelayedCall::masqueradeForFront, c, _1, _2, _3),
			bind(&RelayedCall::masqueradeIceForBack, c, _1, _2, _3, from_tag, ref(transaction)));
		
	m->addAttribute(mSdpMangledParam.c_str(), "yes");
	m->update(msg, sip);

	mServer->update();

	delete m;
	return true;
}


void MediaRelay::configureContext(shared_ptr<RelayedCall> &c){
#ifdef MEDIARELAY_SPECIFIC_FEATURES_ENABLED
	if (mH264FilteringBandwidth)
		c->enableH264IFrameFiltering(mH264FilteringBandwidth,mH264Decim);
	if (mDropTelephoneEvent)
		c->enableTelephoneEventDrooping(true);
#endif
}


void MediaRelay::onRequest(shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();

	shared_ptr<RelayedCall> c;

	if (sip->sip_request->rq_method == sip_method_invite) {
		ev->createIncomingTransaction();
		shared_ptr<OutgoingTransaction> ot = ev->createOutgoingTransaction();
		if ((c = dynamic_pointer_cast<RelayedCall>(mCalls->find(getAgent(), sip, true))) == NULL) {
			if (mMaxCalls>0 && mCalls->size()>=mMaxCalls){
				LOGW("Maximum number of relayed calls reached (%i), call is rejected",mMaxCalls);
				ev->reply(503, "Maximum number of calls reached", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
				return;
			}
			
			c = make_shared<RelayedCall>(mServer, sip, mEarlymediaRTPDir);
			
			configureContext(c);
			if (processNewInvite(c, ot, ev)) {
				//be in the record-route
				addRecordRouteIncoming(c->getHome(), getAgent(),ev);
				mCalls->store(c);
				ot->setProperty<RelayedCall>(getModuleName(), c);
			}
		} else {
			if (processNewInvite(c, ot, ev)) {
				//be in the record-route
				addRecordRouteIncoming(c->getHome(), getAgent(),ev);
				ot->setProperty(getModuleName(), c);
			}
		}
	} else if (sip->sip_request->rq_method == sip_method_bye) {
		if ((c = dynamic_pointer_cast<RelayedCall>(mCalls->findEstablishedDialog(getAgent(), sip))) != NULL) {
			mCalls->remove(c);
		}
	}
	//no need to match cancel requests. They will terminate the outgoing transaction which will eventually (see onTransactionEvent() below)
	//drop the call.
}
void MediaRelay::processFailureForInvite(const shared_ptr<RelayedCall> &c, const shared_ptr<OutgoingTransaction>& transaction, const shared_ptr<MsgSip> &msgSip) {
	sip_t *sip = msgSip->getSip();
	LOGD("Processing Other");
	if (sip->sip_to == NULL || sip->sip_to->a_tag == NULL) {
		LOGW("No tag in answer");
		return;
	}

	string from_tag;
	if (sip->sip_from != NULL && sip->sip_from->a_tag != NULL)
		from_tag = sip->sip_from->a_tag;
	string to_tag;
	if (sip->sip_to != NULL && sip->sip_to->a_tag != NULL)
		to_tag = sip->sip_to->a_tag;

	// Remove back
	if (c->getCallerTag() == from_tag) {
		if (c->removeBack(to_tag)) {
			mCalls->remove(c);
		}
	}
}
void MediaRelay::process200OkforInvite(const shared_ptr<RelayedCall> &c, const shared_ptr<OutgoingTransaction>& transaction, const shared_ptr<MsgSip> &msgSip) {
	sip_t *sip = msgSip->getSip();
	msg_t *msg = msgSip->getMsg();
	LOGD("Processing 200 Ok or early media");

	if (sip->sip_to == NULL || sip->sip_to->a_tag == NULL) {
		LOGW("No tag in answer");
		return;
	}
	
	if (sip->sip_status->st_status==200){
		c->establishDialogWith200Ok(getAgent(),sip);
	}

	SdpModifier *m = SdpModifier::createFromSipMsg(c->getHome(), sip);
	if (m == NULL) {
		LOGW("Invalid SDP");
		return;
	}

	string from_tag;
	if (sip->sip_from != NULL && sip->sip_from->a_tag != NULL)
		from_tag = sip->sip_from->a_tag;
	string to_tag;
	if (sip->sip_to != NULL && sip->sip_to->a_tag != NULL)
		to_tag = sip->sip_to->a_tag;

	// Valid transaction: now we can use tag as RelayChannel identifier
	if (c->getCallerTag() == from_tag)
		c->validateTransaction(to_tag, transaction);

	if (m->hasAttribute(mSdpMangledParam.c_str())) {
		LOGD("200 OK is already relayed");
		delete m;
		return;
	}

	// Set
	if (c->getCallerTag() == from_tag)
		m->iterate(bind(&RelayedCall::assignBackChannel, c, m, _1, _2, _3, to_tag, ref(transaction)));
	else
		m->iterate(bind(&RelayedCall::assignFrontChannel, c, m, _1, _2, _3));

	if (c->getCallerTag() == from_tag && sip->sip_status->st_status == 200)
		c->setUniqueBack(sip->sip_to->a_tag);

	c->update();

	// Translate
	if (c->getCallerTag() == from_tag)
		m->masquerade(bind(&RelayedCall::masqueradeForFront, c, _1, _2, _3));
	else
		m->masquerade(bind(&RelayedCall::masqueradeForBack, c, _1, _2, _3, from_tag, ref(transaction)));

	if (c->getCallerTag() == from_tag)
		m->addIceCandidate(bind(&RelayedCall::masqueradeForFront, c, _1, _2, _3),
			bind(&RelayedCall::masqueradeIceForBack, c, _1, _2, _3, to_tag, ref(transaction)));
	else
		m->addIceCandidate(bind(&RelayedCall::masqueradeForBack, c, _1, _2, _3, from_tag, ref(transaction)),
			bind(&RelayedCall::masqueradeIceForFront, c, _1, _2, _3));
	m->update(msg, sip);

	delete m;
}

void MediaRelay::onResponse(shared_ptr<ResponseSipEvent> &ev) {
	shared_ptr<MsgSip> ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
	msg_t *msg = ms->getMsg();

	// Handle SipEvent associated with a Stateful transaction
	shared_ptr<OutgoingTransaction> transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
	if (transaction != NULL) {
		shared_ptr<RelayedCall> c = transaction->getProperty<RelayedCall>(getModuleName());
		if (c != NULL) {
			if (sip->sip_cseq && sip->sip_cseq->cs_method == sip_method_invite) {
				fixAuthChallengeForSDP(ms->getHome(), msg, sip);
				if (sip->sip_status->st_status == 200 || isEarlyMedia(sip)) {
					process200OkforInvite(c, transaction, ev->getMsgSip());
				} else if (sip->sip_status->st_status >= 300) {
					processFailureForInvite(c, transaction, ev->getMsgSip());
				}
			}
			return;
		}
	}else{
		if (mByeOrphanDialogs && sip->sip_cseq && sip->sip_cseq->cs_method == sip_method_invite && sip->sip_status->st_status == 200) {
			//Out of transaction 200Ok for invite.
			//Check if it matches an established dialog whose to-tag is different, then it is a 200Ok sent by the client
			//before receiving the Cancel.
			shared_ptr<CallContextBase> c=mCalls->findEstablishedDialog(getAgent(),sip);
			if (c==NULL || (c && (sip->sip_to->a_tag==NULL || c->getCalleeTag()!=sip->sip_to->a_tag))){
				LOGD("Receiving out of transaction and dialog 200Ok for invite, rejecting it.");
				nta_msg_ackbye(getAgent()->getSofiaAgent(),msg_dup(msg));
				ev->terminateProcessing();
			}
		}
	}
}

void MediaRelay::onTransactionEvent(shared_ptr<TransactionEvent> ev) {
	shared_ptr<RelayedCall> c = ev->transaction->getProperty<RelayedCall>(getModuleName());
	if (c != NULL) {
		shared_ptr<OutgoingTransaction> ot = dynamic_pointer_cast<OutgoingTransaction>(ev->transaction);
		if (ot != NULL) {
			switch (ev->kind) {
				case TransactionEvent::Type::Destroy:
				if (c->removeTransaction(ev->transaction)) {
					mCalls->remove(c);
				}
				break;

			default:
				break;
			}
		}
	}
}

void MediaRelay::onIdle() {
	mCalls->dump();
	mCalls->removeAndDeleteInactives();
}
