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

#include <vector>
#include <algorithm>


using namespace ::std;

class RelayedCall;

class MediaRelay: public Module, protected ModuleToolbox {
	StatCounter64 *mCountCalls;
	StatCounter64 *mCountCallsFinished;
public:
	typedef enum {
		DUPLEX, FORWARD
	} RTPDir;
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
	RTPDir mEarlymediaRTPDir;
	int mH264FilteringBandwidth;
	int mH264Decim;
	static ModuleInfo<MediaRelay> sInfo;
};

class RelayedCall: public CallContextBase {
	class RelaySessionTransaction {
	public:
		RelaySessionTransaction() :
				mRelaySession(NULL) {

		}

		RelaySession *mRelaySession;
		map<shared_ptr<Transaction>, shared_ptr<MediaSource>> mTransactions;
		map<string, shared_ptr<MediaSource>> mMediaSources;
		bool toDelete;
	};
	typedef enum {
		Idle, Initialized, Running
	} State;
public:
	static const int sMaxSessions = 4;
	RelayedCall(MediaRelayServer *server, sip_t *sip, MediaRelay::RTPDir dir) :
			CallContextBase(sip), mServer(server), mState(Idle), mEarlymediaRTPDir(dir), mBandwidthThres(0) {
		LOGD("New RelayedCall %p", this);
	}
	/*Enable filtering of H264 Iframes for low bandwidth.*/
	void enableH264IFrameFiltering(int bandwidth_threshold, int decim){
		mBandwidthThres=bandwidth_threshold;
		mDecim=decim;
	}
	/*this function is called to masquerade the SDP, for each mline*/
	void setMedia(SdpModifier *m, const string &tag, const shared_ptr<Transaction> &transaction, const string &frontIp, const string&backIp) {
		sdp_media_t *mline = m->mSession->sdp_media;
		int i = 0;
		for (i = 0; mline != NULL && i < sMaxSessions; mline = mline->m_next, ++i) {
			if (mline->m_port == 0) {
				//case of declined mline.
				continue;
			}
			if (i >= sMaxSessions) {
				LOGE("Max sessions per relayed call is reached.");
				return;
			}
			RelaySession *s = mSessions[i].mRelaySession;
			if (s == NULL) {
				s = mServer->createSession();
				mSessions[i].mRelaySession = s;
				configureMediaSource(s->addFront(frontIp),m->mSession,mline);
			}
			if (!tag.empty()) {
				if (mSessions[i].mMediaSources.find(tag) == mSessions[i].mMediaSources.end()) {
					shared_ptr<MediaSource> ms = s->addBack(backIp);
					configureMediaSource(ms,m->mSession,mline);
					ms->setBehaviour(MediaSource::Receive);
					mSessions[i].mMediaSources.insert(pair<string, shared_ptr<MediaSource>>(tag, ms));
				}
			} else {
				if (mSessions[i].mTransactions.find(transaction) == mSessions[i].mTransactions.end()) {
					shared_ptr<MediaSource> ms = s->addBack(backIp);
					configureMediaSource(ms,m->mSession,mline);
					ms->setBehaviour(MediaSource::Receive);
					mSessions[i].mTransactions.insert(pair<shared_ptr<Transaction>, shared_ptr<MediaSource>>(transaction, ms));
				}
			}
		}
		while (i < sMaxSessions) {
			if (mSessions[i].mRelaySession) {
				for (auto it = mSessions[i].mRelaySession->getFronts().begin(); it != mSessions[i].mRelaySession->getFronts().end(); ++it) {
					(*it)->setBehaviour(MediaSource::None);
				}
				for (auto it = mSessions[i].mRelaySession->getBacks().begin(); it != mSessions[i].mRelaySession->getBacks().end(); ++it) {
					(*it)->setBehaviour(MediaSource::None);
				}
				mSessions[i].mRelaySession->unuse();
				mSessions[i].mRelaySession = NULL;
				mSessions[i].mMediaSources.clear();
				mSessions[i].mTransactions.clear();
			}
			++i;
		}
	}

	void backwardTranslate(int mline, string *ip, int *port) {
		if (*port == 0) {
			//case of declined mline.
			return;
		}
		if (mline >= sMaxSessions) {
			return;
		}
		RelaySession *s = mSessions[mline].mRelaySession;
		if (s != NULL) {
			*port = s->getFronts().front()->getRelayPort();
			*ip = s->getFronts().front()->getPublicIp();
		}
	}

	void backwardIceTranslate(int mline, string *ip, int *port) {
		if (*port == 0) {
			//case of declined mline.
			return;
		}
		if (mline >= sMaxSessions) {
			return;
		}
		RelaySession *s = mSessions[mline].mRelaySession;
		if (s != NULL) {
			*port = s->getFronts().front()->getPort();
			*ip = s->getFronts().front()->getIp();
		}
	}

	shared_ptr<MediaSource> getMS(int mline, string tag, const shared_ptr<Transaction> &transaction) {
		if (tag.empty()) {
			auto it = mSessions[mline].mTransactions.find(transaction);
			if (it != mSessions[mline].mTransactions.end()) {
				return it->second;
			}
		} else {
			auto it = mSessions[mline].mMediaSources.find(tag);
			if (it != mSessions[mline].mMediaSources.end()) {
				return it->second;
			}
		}
		return shared_ptr<MediaSource>();
	}

	void forwardTranslate(int mline, string *ip, int *port, const string &tag, const shared_ptr<Transaction> &transaction) {
		if (mline >= sMaxSessions) {
			return;
		}
		RelaySession *s = mSessions[mline].mRelaySession;
		if (s != NULL) {
			auto ms = getMS(mline, tag, transaction);
			if (ms != NULL) {
				*port = ms->getRelayPort();
				*ip = ms->getPublicIp();
			} else {
				*port = -1;
				*ip = mServer->getAgent()->getPublicIp();
			}

		}
	}

	void forwardIceTranslate(int mline, string *ip, int *port, const string &tag, const shared_ptr<Transaction> &transaction) {
		if (mline >= sMaxSessions) {
			return;
		}
		RelaySession *s = mSessions[mline].mRelaySession;
		if (s != NULL) {
			auto ms = getMS(mline, tag, transaction);
			if (ms != NULL) {
				*port = ms->getPort();
				*ip = ms->getIp();
			} else {
				*port = -1;
				*ip = mServer->getAgent()->getPublicIp();
			}

		}
	}

	void setFront(int mline, const string &ip, int port) {
		if (mline >= sMaxSessions) {
			return;
		}
		RelaySession *s = mSessions[mline].mRelaySession;
		if (s != NULL) {
			shared_ptr<MediaSource> ms = s->getFronts().front();
			if(ms->getPort() == -1) {
				ms->set(ip, port);
			}
			ms->setBehaviour(MediaSource::All);
		}
	}

	void setBack(int mline, const string &ip, int port, const string &tag, const shared_ptr<Transaction> &transaction) {
		if (mline >= sMaxSessions) {
			return;
		}
		RelaySession *s = mSessions[mline].mRelaySession;
		if (s != NULL) {
			auto ms = getMS(mline, tag, transaction);
			if (ms != NULL && ms->getPort() == -1) {
				ms->set(ip, port);
			}
		}
	}

	// Set only one sender to the caller
	void update(const shared_ptr<Transaction> &transaction = shared_ptr<Transaction>()) {
		if (mState == Idle)
			mState = Initialized;

		if (mEarlymediaRTPDir != MediaRelay::DUPLEX)
			return;

		// Only one feed from back to front
		string feeder;
		for (int mline = 0; mline < sMaxSessions; ++mline) {
			RelaySession *s = mSessions[mline].mRelaySession;
			if (s != NULL) {
				for (auto it = mSessions[mline].mMediaSources.begin(); it != mSessions[mline].mMediaSources.end(); ++it) {
					shared_ptr<MediaSource> &ms = it->second;
					if (ms->getBehaviour() & MediaSource::Send) {
						feeder = it->first;
					}
				}
				break;
			}
		}

		// Update feeder
		for (int mline = 0; mline < sMaxSessions; ++mline) {
			RelaySession *s = mSessions[mline].mRelaySession;
			if (s != NULL) {
				map<string, shared_ptr<MediaSource>>::iterator it;
				if (feeder.empty())
					it = mSessions[mline].mMediaSources.begin();
				else
					it = mSessions[mline].mMediaSources.find(feeder);
				if (it != mSessions[mline].mMediaSources.end()) {
					shared_ptr<MediaSource> &ms = it->second;
					ms->setBehaviour(MediaSource::All);
				}
			}
		}
	}

	void validTransaction(const string &tag, const shared_ptr<Transaction> &transaction) {
		for (int mline = 0; mline < sMaxSessions; ++mline) {
			RelaySession *s = mSessions[mline].mRelaySession;
			if (s != NULL) {
				auto it = mSessions[mline].mTransactions.find(transaction);
				if (it != mSessions[mline].mTransactions.end()) {
					mSessions[mline].mMediaSources.insert(pair<string, shared_ptr<MediaSource>>(tag, it->second));
					mSessions[mline].mTransactions.erase(it);
				}
			}
		}
	}

	bool removeTransaction(const shared_ptr<Transaction> &transaction) {
		bool remove = (mState != Running);
		for (int mline = 0; mline < sMaxSessions; ++mline) {
			RelaySession *s = mSessions[mline].mRelaySession;
			if (s != NULL) {
				auto it = mSessions[mline].mTransactions.find(transaction);
				if (it != mSessions[mline].mTransactions.end()) {
					shared_ptr<MediaSource> &ms = it->second;
					s->removeBack(ms);
					mSessions[mline].mTransactions.erase(it);
				}
				if (!mSessions[mline].mTransactions.empty() || !mSessions[mline].mMediaSources.empty())
					remove = false;
			}
		}
		update();
		return remove;
	}

	bool removeBack(const string &tag) {
		bool remove = (mState != Running);
		for (int mline = 0; mline < sMaxSessions; ++mline) {
			RelaySession *s = mSessions[mline].mRelaySession;
			if (s != NULL) {
				auto it = mSessions[mline].mMediaSources.find(tag);
				if (it != mSessions[mline].mMediaSources.end()) {
					shared_ptr<MediaSource> &ms = it->second;
					s->removeBack(ms);
					mSessions[mline].mMediaSources.erase(it);
				}
				if (!mSessions[mline].mTransactions.empty() || !mSessions[mline].mMediaSources.empty())
					remove = false;
			}
		}
		update();
		return remove;
	}

	void validBack(const string &tag) {
		if (mState == Initialized) {
			for (int mline = 0; mline < sMaxSessions; ++mline) {
				RelaySession *s = mSessions[mline].mRelaySession;
				if (s != NULL) {
					auto it = mSessions[mline].mMediaSources.begin();
					while (it != mSessions[mline].mMediaSources.end()) {
						shared_ptr<MediaSource> &ms = it->second;
						if (it->first == tag) {
							ms->setBehaviour(MediaSource::BehaviourType::All);
						} else {
							s->removeBack(ms);
							mSessions[mline].mMediaSources.erase(it);
						}
						++it;
					}
					mSessions[mline].mTransactions.clear();
				}
			}
		}
		mState = Running;
	}

	bool isInactive(time_t cur) {
		time_t maxtime = 0;
		RelaySession *r;
		for (int i = 0; i < sMaxSessions; ++i) {
			time_t tmp;
			r = mSessions[i].mRelaySession;
			if (r && ((tmp = r->getLastActivityTime()) > maxtime))
				maxtime = tmp;
		}
		if (cur - maxtime > 30)
			return true;
		return false;
	}

	~RelayedCall() {
		LOGD("Destroy RelayedCall %p", this);
		int i;
		for (i = 0; i < sMaxSessions; ++i) {
			RelaySession *s = mSessions[i].mRelaySession;
			if (s) {
				s->unuse();
			}
		}
	}
	void configureMediaSource(shared_ptr<MediaSource> ms, sdp_session_t *session, sdp_media_t *mline){
		if (mBandwidthThres>0){
			if (mline->m_type==sdp_media_video){
				if (mline->m_rtpmaps && strcmp(mline->m_rtpmaps->rm_encoding,"H264")==0){
					sdp_bandwidth_t *b=session->sdp_bandwidths;
					if (b && b->b_modifier==sdp_bw_as && ((int)b->b_value) <= (int)mBandwidthThres){
						LOGI("Enabling H264 filtering");
						ms->setFilter(make_shared<H264IFrameFilter>(mDecim));
					}
				}
			}
		}
	}

private:
	RelaySessionTransaction mSessions[sMaxSessions];
	MediaRelayServer *mServer;
	State mState;
	MediaRelay::RTPDir mEarlymediaRTPDir;
	int mBandwidthThres;
	int mDecim;
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
#ifdef H264_FILTERING_ENABLED
	mH264FilteringBandwidth=modconf->get<ConfigInt>("h264-filtering-bandwidth")->read();
#else
	mH264FilteringBandwidth=0;
#endif
	
	mEarlymediaRTPDir = DUPLEX;
	if (rtpdir == "duplex") {
		mEarlymediaRTPDir = DUPLEX;
	} else if (rtpdir == "forward") {
		mEarlymediaRTPDir = FORWARD;
	} else {
		LOGW("Wrong value %s for early-media-rtp-dir entry; switch to duplex.", rtpdir.c_str());
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
		m->iterate(bind(&RelayedCall::setFront, c, placeholders::_1, placeholders::_2, placeholders::_3));
	else
		m->iterate(bind(&RelayedCall::setBack, c, placeholders::_1, placeholders::_2, placeholders::_3, from_tag, ref(transaction)));

	// Translate
	if (c->getCallerTag() == from_tag)
		m->translate(bind(&RelayedCall::forwardTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3, to_tag, ref(transaction)));
	else
		m->translate(bind(&RelayedCall::backwardTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3));

	if (c->getCallerTag() == from_tag)
		m->addIceCandidate(bind(&RelayedCall::forwardTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3, to_tag, ref(transaction)),
			bind(&RelayedCall::backwardIceTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3));
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
		if ((c = dynamic_pointer_cast<RelayedCall>(mCalls->find(getAgent(), sip, true))) != NULL) {
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
	LOGD("Processing 200 Ok");

	if (sip->sip_to == NULL || sip->sip_to->a_tag == NULL) {
		LOGW("No tag in answer");
		return;
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
		m->iterate(bind(&RelayedCall::setBack, c, placeholders::_1, placeholders::_2, placeholders::_3, to_tag, ref(transaction)));
	else
		m->iterate(bind(&RelayedCall::setFront, c, placeholders::_1, placeholders::_2, placeholders::_3));

	if (c->getCallerTag() == from_tag && sip->sip_status->st_status == 200)
		c->validBack(sip->sip_to->a_tag);

	c->update(transaction);

	// Translate
	if (c->getCallerTag() == from_tag)
		m->translate(bind(&RelayedCall::backwardTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3));
	else
		m->translate(bind(&RelayedCall::forwardTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3, from_tag, ref(transaction)));

	if (c->getCallerTag() == from_tag)
		m->addIceCandidate(bind(&RelayedCall::backwardTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3),
			bind(&RelayedCall::forwardIceTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3, to_tag, ref(transaction)));
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
