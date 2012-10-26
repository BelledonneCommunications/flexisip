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
	virtual void onTransactionEvent(const shared_ptr<Transaction> &transaction, Transaction::Event event);
	virtual void onIdle();
protected:
	virtual void onDeclare(GenericStruct * mc) {
		ConfigItemDescriptor items[] = {
				{ String, "nortpproxy", "SDP attribute set by the first proxy to forbid subsequent proxies to provide relay.", "nortpproxy" },
				{ String, "early-media-rtp-dir", "Set the RTP direction during early media state (duplex, forward)", "duplex" },
				{ Integer, "sdp-port-range-min", "The minimal value of SDP port range", "1024" },
				{ Integer, "sdp-port-range-max", "The maximal value of SDP port range", "65535" },
				{ Boolean, "bye-orphan-dialogs", "Sends a ACK and BYE to 200Ok for INVITEs not belonging to any established call.", "false"},
#ifdef H264_FILTERING_ENABLED
				{ Integer, "h264-filtering-bandwidth", "Enable I-frame only filtering for video H264 for clients annoucing a total bandwith below this value expressed in kbit/s. Use 0 to disable the feature", "0" },
				{ Integer, "h264-iframe-decim", "When above option is activated, keep one I frame over this number.", "1" },
#endif
				config_item_end };
		mc->addChildrenValues(items);

		auto p=mc->createStatPair("count-calls", "Number of relayed calls.");
		mCountCalls=p.first;
		mCountCallsFinished=p.second;
	}
private:
	bool processNewInvite(const shared_ptr<RelayedCall> &c, const shared_ptr<OutgoingTransaction>& transaction, const shared_ptr<MsgSip> &msgSip);
	void process200OkforInvite(const shared_ptr<RelayedCall> &c, const shared_ptr<OutgoingTransaction>& transaction, const shared_ptr<MsgSip> &msgSip);
	void processOtherforInvite(const shared_ptr<RelayedCall> &c, const shared_ptr<OutgoingTransaction>& transaction, const shared_ptr<MsgSip> &msgSip);
	CallStore *mCalls;
	MediaRelayServer *mServer;
	string mSdpMangledParam;
	RelayedCall::RTPDir mEarlymediaRTPDir;
	int mH264FilteringBandwidth;
	int mH264Decim;
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
#ifdef H264_FILTERING_ENABLED
	mH264FilteringBandwidth=modconf->get<ConfigInt>("h264-filtering-bandwidth")->read();
	mH264Decim=modconf->get<ConfigInt>("h264-iframe-decim")->read();
#else
	mH264FilteringBandwidth=0;
	mH264Decim=0;
#endif
	
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

bool MediaRelay::processNewInvite(const shared_ptr<RelayedCall> &c, const shared_ptr<OutgoingTransaction>& transaction, const shared_ptr<MsgSip> &msgSip) {
	sip_t *sip = msgSip->getSip();
	msg_t *msg = msgSip->getMsg();

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
		from_host = sip->sip_from->a_url->url_host;
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
	if (c->getCallerTag() == from_tag)
		c->setMedia(m, to_tag, transaction, from_host, invite_host);
	else
		c->setMedia(m, from_tag, transaction, invite_host, from_host);

	// Set
	if (c->getCallerTag() == from_tag)
		m->iterate(bind(&RelayedCall::setFront, c, m, placeholders::_1, placeholders::_2, placeholders::_3));
	else
		m->iterate(bind(&RelayedCall::setBack, c, m, placeholders::_1, placeholders::_2, placeholders::_3, from_tag, ref(transaction)));

	// Translate
	if (c->getCallerTag() == from_tag)
		m->translate(bind(&RelayedCall::forwardTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3, to_tag, ref(transaction)));
	else
		m->translate(bind(&RelayedCall::backwardTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3));

	if (c->getCallerTag() == from_tag)
		m->addIceCandidate(bind(&RelayedCall::forwardTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3, to_tag, ref(transaction)),
			bind(&RelayedCall::backwardIceTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3));
	else
		m->addIceCandidate(bind(&RelayedCall::backwardTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3),
			bind(&RelayedCall::forwardIceTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3, from_tag, ref(transaction)));
	m->addAttribute(mSdpMangledParam.c_str(), "yes");
	m->update(msg, sip);

	mServer->update();

	delete m;
	return true;
}

void MediaRelay::onRequest(shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();

	shared_ptr<RelayedCall> c;

	if (sip->sip_request->rq_method == sip_method_invite) {
		ev->createIncomingTransaction();
		shared_ptr<OutgoingTransaction> ot = ev->createOutgoingTransaction();
		if ((c = dynamic_pointer_cast<RelayedCall>(mCalls->find(getAgent(), sip, true))) == NULL) {
			c = make_shared<RelayedCall>(mServer, sip, mEarlymediaRTPDir);
			if (mH264FilteringBandwidth)
				c->enableH264IFrameFiltering(mH264FilteringBandwidth,mH264Decim);
			if (processNewInvite(c, ot, ev->getMsgSip())) {
				//be in the record-route
				addRecordRouteIncoming(c->getHome(), getAgent(),ev);
				mCalls->store(c);
				ot->setProperty<RelayedCall>(getModuleName(), c);
			}
		} else {
			if (processNewInvite(c, ot, ev->getMsgSip())) {
				//be in the record-route
				addRecordRouteIncoming(c->getHome(), getAgent(),ev);
				ot->setProperty(getModuleName(), c);
			}
		}
	} else if (sip->sip_request->rq_method == sip_method_bye) {
		if ((c = dynamic_pointer_cast<RelayedCall>(mCalls->findEstablishedDialog(getAgent(), sip))) != NULL) {
			mCalls->remove(c);
		}
	} else if (sip->sip_request->rq_method == sip_method_cancel) {
		if ((c = dynamic_pointer_cast<RelayedCall>(mCalls->find(getAgent(), sip, true))) != NULL) {
			mCalls->remove(c);
		}
	}
}
void MediaRelay::processOtherforInvite(const shared_ptr<RelayedCall> &c, const shared_ptr<OutgoingTransaction>& transaction, const shared_ptr<MsgSip> &msgSip) {
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

	// Valid transaction: now we can use tag as MediaSource identifier
	if (c->getCallerTag() == from_tag)
		c->validTransaction(to_tag, transaction);

	if (m->hasAttribute(mSdpMangledParam.c_str())) {
		LOGD("200 OK is already relayed");
		delete m;
		return;
	}

	// Set
	if (c->getCallerTag() == from_tag)
		m->iterate(bind(&RelayedCall::setBack, c, m, placeholders::_1, placeholders::_2, placeholders::_3, to_tag, ref(transaction)));
	else
		m->iterate(bind(&RelayedCall::setFront, c, m, placeholders::_1, placeholders::_2, placeholders::_3));

	if (c->getCallerTag() == from_tag && sip->sip_status->st_status == 200)
		c->validBack(sip->sip_to->a_tag);

	c->update();

	// Translate
	if (c->getCallerTag() == from_tag)
		m->translate(bind(&RelayedCall::backwardTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3));
	else
		m->translate(bind(&RelayedCall::forwardTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3, from_tag, ref(transaction)));

	if (c->getCallerTag() == from_tag)
		m->addIceCandidate(bind(&RelayedCall::backwardTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3),
			bind(&RelayedCall::forwardIceTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3, to_tag, ref(transaction)));
	else
		m->addIceCandidate(bind(&RelayedCall::forwardTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3, from_tag, ref(transaction)),
			bind(&RelayedCall::backwardIceTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3));
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
				} else if (sip->sip_status->st_status > 200) {
					processOtherforInvite(c, transaction, ev->getMsgSip());
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

void MediaRelay::onTransactionEvent(const shared_ptr<Transaction> &transaction, Transaction::Event event) {
	shared_ptr<RelayedCall> c = transaction->getProperty<RelayedCall>(getModuleName());
	if (c != NULL) {
		shared_ptr<OutgoingTransaction> ot = dynamic_pointer_cast<OutgoingTransaction>(transaction);
		if (ot != NULL) {
			switch (event) {
			case Transaction::Destroy:
				if (c->removeTransaction(transaction)) {
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
