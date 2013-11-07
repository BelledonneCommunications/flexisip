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


RelayedCall::RelayedCall(MediaRelayServer *server, sip_t *sip) :
					CallContextBase(sip), mServer(server), mBandwidthThres(0) {
	LOGD("New RelayedCall %p", this);
	mDropTelephoneEvents=false;
	mIsEstablished=false;
	mHasSendRecvBack=false;
}

/*Enable filtering of H264 Iframes for low bandwidth.*/
void RelayedCall::enableH264IFrameFiltering(int bandwidth_threshold, int decim){
	mBandwidthThres=bandwidth_threshold;
	mDecim=decim;
}

void RelayedCall::enableTelephoneEventDrooping(bool value){
	mDropTelephoneEvents=value;
}


void RelayedCall::initChannels(SdpModifier *m, const string &tag, const string &trid, const std::pair<std::string,std::string> &frontRelayIps, const std::pair<std::string,std::string> &backRelayIps) {
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
		shared_ptr<RelaySession> s = mSessions[i];
		if (s == NULL) {
			s = mServer->createSession(tag,frontRelayIps);
			mSessions[i] = s;
		}
		
		shared_ptr<RelayChannel> chan=s->getChannel("",trid);
		if (chan==NULL){
			/*this is a new outgoing branch to be established*/
			chan=s->createBranch(trid,backRelayIps);
		}
	}
}

bool RelayedCall::checkMediaValid() {
	for (int i=0; i < sMaxSessions; ++i) {
		shared_ptr<RelaySession> s=mSessions[i];
		if (s && !s->checkChannels()) return false;
	}
	return true;
}

/* Obtain the local address and port used for relaying */
std::pair<string,int> RelayedCall::getChannelSources(int mline, const std::string & partyTag, const std::string &trId){
	if (mline >= sMaxSessions) {
		return make_pair("",0);
	}
	shared_ptr<RelaySession> s = mSessions[mline];
	if (s != NULL) {
		shared_ptr<RelayChannel> chan=s->getChannel(partyTag,trId);
		return make_pair(chan->getLocalIp(),chan->getLocalPort());
	}
	return make_pair("",0);
}
	
/* Obtain destination (previously set by setChannelDestinations()*/
std::pair<string,int> RelayedCall::getChannelDestinations(int mline, const std::string & partyTag, const std::string &trId){
	if (mline >= sMaxSessions) {
		return make_pair("",0);
	}
	shared_ptr<RelaySession> s = mSessions[mline];
	if (s != NULL) {
		shared_ptr<RelayChannel> chan=s->getChannel(partyTag,trId);
		return make_pair(chan->getRemoteIp(),chan->getRemotePort());
	}
	return make_pair("",0);
}


void RelayedCall::setChannelDestinations(SdpModifier *m, int mline, const string &ip, int port, const string & partyTag, const string &trId, bool isEarlyMedia){
	if (mline >= sMaxSessions) {
		return;
	}
	RelayChannel::Dir dir=RelayChannel::SendRecv;
	/*The following code is to make sure than only one branch can send media to the caller,
		until the call is established.*/
	if (isEarlyMedia && !mIsEstablished){
		if (mHasSendRecvBack) dir=RelayChannel::SendOnly;
		else {
			dir=RelayChannel::SendRecv;
			mHasSendRecvBack=true;
		}
	}
	shared_ptr<RelaySession> s = mSessions[mline];
	if (s != NULL) {
		shared_ptr<RelayChannel> chan=s->getChannel(partyTag,trId);
		if(chan->getLocalPort()>0) {
			configureRelayChannel(chan,m->mSip,m->mSession,mline);
			chan->setRemoteAddr(ip, port,dir);
		}
	}
}

void RelayedCall::setEstablished(const string &trId){
	int i;
	mIsEstablished=true;
	for(i=0;i<sMaxSessions;++i){
		shared_ptr<RelaySession> s = mSessions[i];
		if (s){
			s->setEstablished(trId);
		}
	}
}

void RelayedCall::removeBranch(const string &trId) {
	int i;
	
	for(i=0;i<sMaxSessions;++i){
		shared_ptr<RelaySession> s = mSessions[i];
		if (s){
			s->removeBranch(trId);
		}
	}
}


bool RelayedCall::isInactive(time_t cur) {
	time_t maxtime = 0;
	shared_ptr<RelaySession> r;
	for (int i = 0; i < sMaxSessions; ++i) {
		time_t tmp;
		r = mSessions[i];
		if (r && ((tmp = r->getLastActivityTime()) > maxtime))
			maxtime = tmp;
	}
	if (cur - maxtime > 90){ // this value shall not be less than the time to establish a call.
		return true;
	}
	return false;
}

void RelayedCall::terminate(){
	int i;
	for (i = 0; i < sMaxSessions; ++i) {
		shared_ptr<RelaySession> s = mSessions[i];
		if (s) {
			s->unuse();
			mSessions[i]=0;
		}
	}
}

RelayedCall::~RelayedCall() {
	LOGD("Destroy RelayedCall %p", this);
	terminate();
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

