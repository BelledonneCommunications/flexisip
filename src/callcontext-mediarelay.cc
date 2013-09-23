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


#include "callcontext-mediarelay.hh"
#include <memory>
#include <string>
#include "mediarelay.hh"
#include "h264iframefilter.hh"
#include "telephone-event-filter.hh"

using namespace std;


RelayedCall::RelayedCall(MediaRelayServer *server, sip_t *sip, RTPDir dir) :
					CallContextBase(sip), mServer(server), mState(Idle), mEarlymediaRTPDir(dir), mBandwidthThres(0) {
	LOGD("New RelayedCall %p", this);
	mDropTelephoneEvents=false;
}

/*Enable filtering of H264 Iframes for low bandwidth.*/
void RelayedCall::enableH264IFrameFiltering(int bandwidth_threshold, int decim){
	mBandwidthThres=bandwidth_threshold;
	mDecim=decim;
}

void RelayedCall::enableTelephoneEventDrooping(bool value){
	mDropTelephoneEvents=value;
}


/*this function is called to masquerade the SDP, for each mline*/
void RelayedCall::initChannels(SdpModifier *m, const string &tag, const shared_ptr<Transaction> &transaction, const std::pair<std::string,std::string> &frontRelayIps, const std::pair<std::string,std::string> &backRelayIps) {
	sdp_media_t *mline = m->mSession->sdp_media;
	int i = 0;
	for (i = 0; mline != NULL && i < sMaxSessions; mline = mline->m_next, ++i) {
		if (mline->m_port == 0) {
			//case of declined mline.
			continue;
		}
		if (i >= sMaxSessions) {
			LOGE("Max sessions per relayed call is reached.");
			return ;
		}
		shared_ptr<RelaySession> s = mSessions[i].mRelaySession;
		if (s == NULL) {
			s = mServer->createSession();
			mSessions[i].mRelaySession = s;
			s->setFront(frontRelayIps);
		}
		if (!tag.empty()) {
			if (mSessions[i].mRelayChannels.find(tag) == mSessions[i].mRelayChannels.end()) {
				shared_ptr<RelayChannel> ms = s->addBack(backRelayIps);
				ms->setBehaviour(RelayChannel::Receive);
				mSessions[i].mRelayChannels.insert(make_pair(tag, ms));
			}
		} else {
			if (mSessions[i].mTransactions.find(transaction) == mSessions[i].mTransactions.end()) {
				shared_ptr<RelayChannel> ms = s->addBack(backRelayIps);
				ms->setBehaviour(RelayChannel::None);
				mSessions[i].mTransactions.insert(make_pair(transaction, ms));
			}
		}
	}
	while (i < sMaxSessions) {
		if (mSessions[i].mRelaySession) {
			
			mSessions[i].mRelaySession->getFront()->setBehaviour(RelayChannel::None);
			for (auto it = mSessions[i].mRelaySession->getBacks().begin(); it != mSessions[i].mRelaySession->getBacks().end(); ++it) {
				(*it)->setBehaviour(RelayChannel::None);
			}
			mSessions[i].mRelaySession->unuse();
			mSessions[i].mRelaySession = shared_ptr<RelaySession>(); // null
			mSessions[i].mRelayChannels.clear();
			mSessions[i].mTransactions.clear();
		}
		++i;
	}
}

bool RelayedCall::checkMediaValid() {
	for (int i=0; i < sMaxSessions; ++i) {
		shared_ptr<RelaySession> s=mSessions[i].mRelaySession;
		if (s && !s->checkMediaSources()) return false;
	}
	return true;
}

void RelayedCall::masqueradeForFront(int mline, string *ip, int *port) {
	if (*port == 0) {
		//case of declined mline.
		return;
	}
	if (mline >= sMaxSessions) {
		return;
	}
	shared_ptr<RelaySession> s = mSessions[mline].mRelaySession;
	if (s != NULL) {
		*port = s->getFront()->getRelayPort();
		*ip = s->getFront()->getPublicIp();
	}
}

void RelayedCall::masqueradeIceForFront(int mline, string *ip, int *port) {
	if (*port == 0) {
		//case of declined mline.
		return;
	}
	if (mline >= sMaxSessions) {
		return;
	}
	shared_ptr<RelaySession> s = mSessions[mline].mRelaySession;
	if (s != NULL) {
		*port = s->getFront()->getPort();
		*ip = s->getFront()->getIp();
	}
}

shared_ptr<RelayChannel> RelayedCall::getMS(int mline, string tag, const shared_ptr<Transaction> &transaction) {
	if (tag.empty()) {
		auto it = mSessions[mline].mTransactions.find(transaction);
		if (it != mSessions[mline].mTransactions.end()) {
			return it->second;
		}
	} else {
		auto it = mSessions[mline].mRelayChannels.find(tag);
		if (it != mSessions[mline].mRelayChannels.end()) {
			return it->second;
		}
	}
	return shared_ptr<RelayChannel>();
}

void RelayedCall::masqueradeForBack(int mline, string *ip, int *port, const string &tag, const shared_ptr<Transaction> &transaction) {
	if (*port == 0) {
		//case of media stream removal
		return;
	}
	if (mline >= sMaxSessions) {
		return;
	}
	shared_ptr<RelaySession> s = mSessions[mline].mRelaySession;
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

void RelayedCall::masqueradeIceForBack(int mline, string *ip, int *port, const string &tag, const shared_ptr<Transaction> &transaction) {
	if (*port == 0) {
		//case of media stream removal
		return;
	}
	if (mline >= sMaxSessions) {
		return;
	}
	shared_ptr<RelaySession> s = mSessions[mline].mRelaySession;
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

void RelayedCall::assignFrontChannel(SdpModifier *m, int mline, const string &ip, int port) {
	if (mline >= sMaxSessions) {
		return;
	}
	shared_ptr<RelaySession> s = mSessions[mline].mRelaySession;
	if (s != NULL) {
		shared_ptr<RelayChannel> ms = s->getFront();
		if(ms->getPort() == -1) {
			configureRelayChannel(ms,m->mSip,m->mSession,mline);
			ms->set(ip, port);
		}
		ms->setBehaviour(RelayChannel::All);
	}
}

void RelayedCall::assignBackChannel(SdpModifier *m, int mline, const string &ip, int port, const string &tag, const shared_ptr<Transaction> &transaction) {
	if (mline >= sMaxSessions) {
		return;
	}
	shared_ptr<RelaySession> s = mSessions[mline].mRelaySession;
	if (s != NULL) {
		auto ms = getMS(mline, tag, transaction);
		if (ms != NULL && ms->getPort() == -1) {
			configureRelayChannel(ms,m->mSip,m->mSession,mline);
			ms->set(ip, port);
		}
	}
}

// Set only one sender to the caller
void RelayedCall::update() {
	if (mState == Idle)
		mState = Initialized;

	if (mEarlymediaRTPDir != DUPLEX)
		return;

	// Only one feed from back to front: find current one
	string feeder;
	for (int mline = 0; mline < sMaxSessions; ++mline) {
		shared_ptr<RelaySession> s = mSessions[mline].mRelaySession;
		if (s != NULL) {
			for (auto it = mSessions[mline].mRelayChannels.begin(); it != mSessions[mline].mRelayChannels.end(); ++it) {
				shared_ptr<RelayChannel> &ms = it->second;
				if (ms->getBehaviour() & RelayChannel::Send) {
					feeder = it->first;
				}
			}
			break;
		}
	}

	// Update current feeder
	for (int mline = 0; mline < sMaxSessions; ++mline) {
		shared_ptr<RelaySession> s = mSessions[mline].mRelaySession;
		if (s != NULL) {
			map<string, shared_ptr<RelayChannel>>::iterator it;
			if (feeder.empty()) {
				it = mSessions[mline].mRelayChannels.begin();
				while(it != mSessions[mline].mRelayChannels.end() && !(it->second->getBehaviour() & RelayChannel::Receive)) ++it;
			} else
				it = mSessions[mline].mRelayChannels.find(feeder);
			if (it != mSessions[mline].mRelayChannels.end()) {
				shared_ptr<RelayChannel> &ms = it->second;
				ms->setBehaviour(RelayChannel::All);
			}
		}
	}
}

/* associates a transaction with a to-tag.
 * This might change, for example for a given transaction, a 183 can come from one to-tag, and the 200Ok from another to-tag.
 */
void RelayedCall::validateTransaction(const string &tag, const shared_ptr<Transaction> &transaction) {
	for (int mline = 0; mline < sMaxSessions; ++mline) {
		shared_ptr<RelaySession> s = mSessions[mline].mRelaySession;
		if (s != NULL) {
			auto it = mSessions[mline].mTransactions.find(transaction);
			if (it != mSessions[mline].mTransactions.end()) {
				it->second->setBehaviour(RelayChannel::Receive);
				mSessions[mline].mRelayChannels[tag]=it->second;
			}
		}
	}
}

bool RelayedCall::removeTransaction(const shared_ptr<Transaction> &transaction) {
	bool remove = (mState != Running);
	for (int mline = 0; mline < sMaxSessions; ++mline) {
		shared_ptr<RelaySession> s = mSessions[mline].mRelaySession;
		if (s != NULL) {
			auto it = mSessions[mline].mTransactions.find(transaction);
			if (it != mSessions[mline].mTransactions.end()) {
				shared_ptr<RelayChannel> &ms = it->second;
				s->removeBack(ms);
				mSessions[mline].mTransactions.erase(it);
			}
			if (!mSessions[mline].mTransactions.empty() || !mSessions[mline].mRelayChannels.empty())
				remove = false;
		}
	}
	update();
	return remove;
}

bool RelayedCall::removeBack(const string &tag) {
	bool remove = (mState != Running);
	for (int mline = 0; mline < sMaxSessions; ++mline) {
		shared_ptr<RelaySession> s = mSessions[mline].mRelaySession;
		if (s != NULL) {
			auto it = mSessions[mline].mRelayChannels.find(tag);
			if (it != mSessions[mline].mRelayChannels.end()) {
				shared_ptr<RelayChannel> &ms = it->second;
				s->removeBack(ms);
				mSessions[mline].mRelayChannels.erase(it);
			}
			if (!mSessions[mline].mTransactions.empty() || !mSessions[mline].mRelayChannels.empty())
				remove = false;
		}
	}
	update();
	return remove;
}

void RelayedCall::setUniqueBack(const string &tag) {
	if (mState == Initialized) {
		for (int mline = 0; mline < sMaxSessions; ++mline) {
			shared_ptr<RelaySession> s = mSessions[mline].mRelaySession;
			if (s != NULL) {
				//assert the tag exists before removing others
				if (mSessions[mline].mRelayChannels.find(tag)==mSessions[mline].mRelayChannels.end()){
					LOGE("RelayedCall::setUniqueBack(): could not find tag %s",tag.c_str());
					return;
				}
				auto it = mSessions[mline].mRelayChannels.begin();
				while (it != mSessions[mline].mRelayChannels.end()) {
					shared_ptr<RelayChannel> &ms = it->second;
					if (it->first == tag) {
						ms->setBehaviour(RelayChannel::BehaviourType::All);
						++it;
					} else {
						s->removeBack(ms);
						//the following is not accepted by gcc 4.4 though it is correct.
						//it=mSessions[mline].mRelayChannels.erase(it);
						auto previt=it;
						++it;
						mSessions[mline].mRelayChannels.erase(previt);
					}
				}
				mSessions[mline].mTransactions.clear();
			}
		}
	}
	mState = Running;
}

bool RelayedCall::isInactive(time_t cur) {
	time_t maxtime = 0;
	shared_ptr<RelaySession> r;
	for (int i = 0; i < sMaxSessions; ++i) {
		time_t tmp;
		r = mSessions[i].mRelaySession;
		if (r && ((tmp = r->getLastActivityTime()) > maxtime))
			maxtime = tmp;
	}
	if (cur - maxtime > 90){ // this value shall not be less than the time to establish a call.
		return true;
	}
	return false;
}

RelayedCall::~RelayedCall() {
	LOGD("Destroy RelayedCall %p", this);
	int i;
	for (i = 0; i < sMaxSessions; ++i) {
		shared_ptr<RelaySession> s = mSessions[i].mRelaySession;
		if (s) {
			s->unuse();
		}
	}
}


#ifdef MEDIARELAY_SPECIFIC_FEATURES_ENABLED

static bool isTls(url_t *url){
	if (url->url_type==url_sips) return true;
	char transport[20]={0};
	if (url_param(url->url_params,"transport",transport,sizeof(transport)-1)>0 && strcasecmp(transport,"tls")==0)
		return true;
	return false;
}
#endif

static bool isLastProxy(Agent *ag, sip_t *sip){
	sip_record_route_t *rr=sip->sip_record_route;
	if (!rr) {
		LOGE("No record-route in response handled by media-relay, should never happen");
		return false;
	}
	if (ag->isUs(rr->r_url)){
		LOGD("We are last proxy of the call flow.");
		return true;
	}
	return false;
}

void RelayedCall::configureRelayChannel(shared_ptr<RelayChannel> ms, sip_t *sip, sdp_session_t *session, int mline_nr){
	sdp_media_t *mline;
	int i;
	for(i=0,mline=session->sdp_media;i<mline_nr;mline=mline->m_next,++i){
	}
	if (mBandwidthThres>0){
		if (mline->m_type==sdp_media_video){
			if (mline->m_rtpmaps && strcmp(mline->m_rtpmaps->rm_encoding,"H264")==0){
				sdp_bandwidth_t *b=session->sdp_bandwidths;
				if (b && ((int)b->b_value) <= (int)mBandwidthThres){
					bool enabled=false;
					if (sip->sip_request == NULL){
						//for responses, we want to activate the feature only if we are the last proxy.
						enabled=isLastProxy(mServer->getAgent(),sip);
					}else enabled=true;
					if (enabled) {
						LOGI("Enabling H264 filtering for channel %p",ms.get());
						ms->setFilter(make_shared<H264IFrameFilter>(mDecim));
					}
				}
			}
		}
	}
#ifdef MEDIARELAY_SPECIFIC_FEATURES_ENABLED
	if (mDropTelephoneEvents){
		//only telephone event coming from tls clients are dropped.
		if (mline->m_type==sdp_media_audio){
			if (isTls(sip->sip_contact->m_url)){
				sdp_rtpmap_t *rtpmap;
				for (rtpmap=mline->m_rtpmaps;rtpmap!=NULL;rtpmap=rtpmap->rm_next){
					if (strcasecmp(rtpmap->rm_encoding,"telephone-event")==0){
						LOGI("Enabling telephone-event filtering on payload type %i",rtpmap->rm_pt);
						ms->setFilter(make_shared<TelephoneEventFilter>((int)rtpmap->rm_pt));
					}
				}
			}
		}
	}
#endif
}

