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

using namespace std;


RelayedCall::RelayedCall(MediaRelayServer *server, sip_t *sip, RTPDir dir) :
					CallContextBase(sip), mServer(server), mState(Idle), mEarlymediaRTPDir(dir), mBandwidthThres(0) {
	LOGD("New RelayedCall %p", this);
}

/*Enable filtering of H264 Iframes for low bandwidth.*/
void RelayedCall::enableH264IFrameFiltering(int bandwidth_threshold, int decim){
	mBandwidthThres=bandwidth_threshold;
	mDecim=decim;
}

/*this function is called to masquerade the SDP, for each mline*/
void RelayedCall::initChannels(SdpModifier *m, const string &tag, const shared_ptr<Transaction> &transaction, const string &frontRelayIp, const string&backRelayIp) {
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
			s->addFront(frontRelayIp);
		}
		if (!tag.empty()) {
			if (mSessions[i].mRelayChannels.find(tag) == mSessions[i].mRelayChannels.end()) {
				shared_ptr<RelayChannel> ms = s->addBack(backRelayIp);
				ms->setBehaviour(RelayChannel::Receive);
				mSessions[i].mRelayChannels.insert(pair<string, shared_ptr<RelayChannel>>(tag, ms));
			}
		} else {
			if (mSessions[i].mTransactions.find(transaction) == mSessions[i].mTransactions.end()) {
				shared_ptr<RelayChannel> ms = s->addBack(backRelayIp);
				ms->setBehaviour(RelayChannel::None);
				mSessions[i].mTransactions.insert(pair<shared_ptr<Transaction>, shared_ptr<RelayChannel>>(transaction, ms));
			}
		}
	}
	while (i < sMaxSessions) {
		if (mSessions[i].mRelaySession) {
			for (auto it = mSessions[i].mRelaySession->getFronts().begin(); it != mSessions[i].mRelaySession->getFronts().end(); ++it) {
				(*it)->setBehaviour(RelayChannel::None);
			}
			for (auto it = mSessions[i].mRelaySession->getBacks().begin(); it != mSessions[i].mRelaySession->getBacks().end(); ++it) {
				(*it)->setBehaviour(RelayChannel::None);
			}
			mSessions[i].mRelaySession->unuse();
			mSessions[i].mRelaySession = NULL;
			mSessions[i].mRelayChannels.clear();
			mSessions[i].mTransactions.clear();
		}
		++i;
	}
}

bool RelayedCall::checkMediaValid() {
	for (int i=0; i < sMaxSessions; ++i) {
		RelaySession *s=mSessions[i].mRelaySession;
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
	RelaySession *s = mSessions[mline].mRelaySession;
	if (s != NULL) {
		*port = s->getFronts().front()->getRelayPort();
		*ip = s->getFronts().front()->getPublicIp();
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
	RelaySession *s = mSessions[mline].mRelaySession;
	if (s != NULL) {
		*port = s->getFronts().front()->getPort();
		*ip = s->getFronts().front()->getIp();
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

void RelayedCall::masqueradeIceForBack(int mline, string *ip, int *port, const string &tag, const shared_ptr<Transaction> &transaction) {
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

void RelayedCall::assignFrontChannel(SdpModifier *m, int mline, const string &ip, int port) {
	if (mline >= sMaxSessions) {
		return;
	}
	RelaySession *s = mSessions[mline].mRelaySession;
	if (s != NULL) {
		shared_ptr<RelayChannel> ms = s->getFronts().front();
		if(ms->getPort() == -1) {
			configureMediaSource(ms,m->mSession,mline);
			ms->set(ip, port);
		}
		ms->setBehaviour(RelayChannel::All);
	}
}

void RelayedCall::assignBackChannel(SdpModifier *m, int mline, const string &ip, int port, const string &tag, const shared_ptr<Transaction> &transaction) {
	if (mline >= sMaxSessions) {
		return;
	}
	RelaySession *s = mSessions[mline].mRelaySession;
	if (s != NULL) {
		auto ms = getMS(mline, tag, transaction);
		if (ms != NULL && ms->getPort() == -1) {
			configureMediaSource(ms,m->mSession,mline);
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
		RelaySession *s = mSessions[mline].mRelaySession;
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
		RelaySession *s = mSessions[mline].mRelaySession;
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

void RelayedCall::validateTransaction(const string &tag, const shared_ptr<Transaction> &transaction) {
	for (int mline = 0; mline < sMaxSessions; ++mline) {
		RelaySession *s = mSessions[mline].mRelaySession;
		if (s != NULL) {
			auto it = mSessions[mline].mTransactions.find(transaction);
			if (it != mSessions[mline].mTransactions.end()) {
				it->second->setBehaviour(RelayChannel::Receive);
				mSessions[mline].mRelayChannels.insert(pair<string, shared_ptr<RelayChannel>>(tag, it->second));
				mSessions[mline].mTransactions.erase(it);
			}
		}
	}
}

bool RelayedCall::removeTransaction(const shared_ptr<Transaction> &transaction) {
	bool remove = (mState != Running);
	for (int mline = 0; mline < sMaxSessions; ++mline) {
		RelaySession *s = mSessions[mline].mRelaySession;
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
		RelaySession *s = mSessions[mline].mRelaySession;
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
			RelaySession *s = mSessions[mline].mRelaySession;
			if (s != NULL) {
				auto it = mSessions[mline].mRelayChannels.begin();
				while (it != mSessions[mline].mRelayChannels.end()) {
					shared_ptr<RelayChannel> &ms = it->second;
					if (it->first == tag) {
						ms->setBehaviour(RelayChannel::BehaviourType::All);
					} else {
						s->removeBack(ms);
						mSessions[mline].mRelayChannels.erase(it);
					}
					++it;
				}
				mSessions[mline].mTransactions.clear();
			}
		}
	}
	mState = Running;
}

bool RelayedCall::isInactive(time_t cur) {
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

RelayedCall::~RelayedCall() {
	LOGD("Destroy RelayedCall %p", this);
	int i;
	for (i = 0; i < sMaxSessions; ++i) {
		RelaySession *s = mSessions[i].mRelaySession;
		if (s) {
			s->unuse();
		}
	}
}

void RelayedCall::configureMediaSource(shared_ptr<RelayChannel> ms, sdp_session_t *session, int mline_nr){
	sdp_media_t *mline;
	int i;
	for(i=0,mline=session->sdp_media;i<mline_nr;mline=mline->m_next,++i){
	}
	if (mBandwidthThres>0){
		if (mline->m_type==sdp_media_video){
			if (mline->m_rtpmaps && strcmp(mline->m_rtpmaps->rm_encoding,"H264")==0){
				sdp_bandwidth_t *b=session->sdp_bandwidths;
				if (b && ((int)b->b_value) <= (int)mBandwidthThres){
					LOGI("Enabling H264 filtering");
					ms->setFilter(make_shared<H264IFrameFilter>(mDecim));
				}
			}
		}
	}
}

