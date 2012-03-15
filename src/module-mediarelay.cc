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

#include "agent.hh"
#include "mediarelay.hh"
#include "callstore.hh"
#include "sdp-modifier.hh"

#include <vector>
#include <algorithm>

using namespace::std;

class RelayedCall;

class MediaRelay : public Module, protected ModuleToolbox{
	public:
		MediaRelay(Agent *ag);
		~MediaRelay();
		virtual void onLoad(Agent *ag, const ConfigStruct * modconf);
		virtual void onRequest(SipEvent *ev);
		virtual void onResponse(SipEvent *ev);
		virtual void onIdle();
	private:
		void processNewInvite(RelayedCall *c, msg_t *msg, sip_t *sip);
		void process200OkforInvite(RelayedCall *ctx, msg_t *msg, sip_t *sip);
		CallStore mCalls;
		MediaRelayServer *mServer;
		static ModuleInfo <MediaRelay> sInfo;
};

class RelayedCall : public CallContextBase, public Masquerader{
	public:
		static const int sMaxSessions=4;
		RelayedCall(MediaRelayServer *server, sip_t *sip) : CallContextBase (sip), mServer(server){
			memset(mSessions,0,sizeof(mSessions));
		}
		/*this function is called to masquerade the SDP, for each mline*/
		virtual void onNewMedia(int mline, std::string *ip, int *port, const char *party_tag){
			if (mline>=sMaxSessions){
				LOGE("Max sessions per relayed call is reached.");
				return;
			}
			RelaySession *s=mSessions[mline];
			if (s==NULL){
				s=mServer->createSession();
				mSessions[mline]=s;
			}
			
			if (getCallerTag()==party_tag){
				s->setFrontDefaultSource(ip->c_str(),*port);
				*port=s->getBackPort();
			}else{
				s->setBackDefaultSource(ip->c_str(),*port);
				*port=s->getFrontPort();
			}
			*ip=s->getPublicIp();
		}
		virtual bool isInactive(time_t cur){
			time_t maxtime=0;
			RelaySession *r;
			for (int i=0;i<sMaxSessions;++i){
				time_t tmp;
				r=mSessions[i];
				if (r && ((tmp=r->getLastActivityTime()) > maxtime) )
					maxtime=tmp;
			}
			if (cur-maxtime>30) return true;
			return false;
		}
		virtual ~RelayedCall(){
			int i;
			for(i=0;i<sMaxSessions;++i){
				RelaySession *s=mSessions[i];
				if (s) s->unuse();
			}
		}
	private:
		RelaySession * mSessions[sMaxSessions];
		MediaRelayServer *mServer;
};

ModuleInfo<MediaRelay> MediaRelay::sInfo("MediaRelay",
	"The MediaRelay module masquerades SDP message so that all RTP and RTCP streams go through the proxy. "
	"The RTP and RTCP streams are then routed so that each client receives the stream of the other. "
    "MediaRelay makes sure that RTP is ALWAYS established, even with uncooperative firewalls.",0);

MediaRelay::MediaRelay(Agent *ag) : Module(ag), mServer(0){
}

MediaRelay::~MediaRelay(){
	if (mServer) delete mServer;
}

void MediaRelay::onLoad(Agent *ag, const ConfigStruct * modconf){
	mServer=new MediaRelayServer(ag->getBindIp(),ag->getPublicIp());
}


void MediaRelay::processNewInvite(RelayedCall *c, msg_t *msg, sip_t *sip){
	SdpModifier *m=SdpModifier::createFromSipMsg(c->getHome(), sip);
	if (sip->sip_from==NULL || sip->sip_from->a_tag==NULL){
		LOGW("No tag in from !");
		return;
	}	
	if (m){
		m->changeIpPort(c,sip->sip_from->a_tag);
		m->update(msg,sip);
		//be in the record-route
		addRecordRoute(c->getHome(),getAgent(),msg,sip);
		c->storeNewInvite (msg);
		delete m;
	}
}


void MediaRelay::onRequest(SipEvent *ev){
	RelayedCall *c;
	msg_t *msg=ev->mMsg;
	sip_t *sip=ev->mSip;
	
	if (sip->sip_request->rq_method==sip_method_invite){
		if ((c=static_cast<RelayedCall*>(mCalls.find(sip)))==NULL){
			c=new RelayedCall(mServer,sip);
			mCalls.store(c);
			processNewInvite(c,msg,sip);
		}else{
			if (c->isNewInvite(sip)){
				processNewInvite(c,msg,sip);
			}else if (c->getLastForwardedInvite()!=NULL){
				msg=msg_copy(c->getLastForwardedInvite ());
				sip=(sip_t*)msg_object(msg);
				LOGD("Forwarding invite retransmission");
			}
		}
	}
	if (sip->sip_request->rq_method==sip_method_bye){
		if ((c=static_cast<RelayedCall*>(mCalls.find(sip)))!=NULL){
			mCalls.remove(c);
			delete c;
		}
	}
	ev->mMsg=msg;
	ev->mSip=sip;
	
}

static bool isEarlyMedia(sip_t *sip){
	if (sip->sip_status->st_status==180 || sip->sip_status->st_status==183){
		sip_payload_t *payload=sip->sip_payload;
		//TODO: should check if it is application/sdp
		return payload!=NULL;
	}
	return false;
}

void MediaRelay::process200OkforInvite(RelayedCall *ctx, msg_t *msg, sip_t *sip){
	LOGD("Processing 200 Ok");

	if (sip->sip_to==NULL || sip->sip_to->a_tag==NULL){
		LOGW("No tag in answer");
		return;
	}
	SdpModifier *m=SdpModifier::createFromSipMsg(ctx->getHome(), sip);
	if (m==NULL) return;
	
	m->changeIpPort(ctx, sip->sip_to->a_tag);
	m->update(msg,sip);
	ctx->storeNewResponse (msg);

	delete m;
}


void MediaRelay::onResponse(SipEvent *ev){
	sip_t *sip=ev->mSip;
	msg_t *msg=ev->mMsg;
	RelayedCall *c;
	
	if (sip->sip_cseq && sip->sip_cseq->cs_method==sip_method_invite){
		fixAuthChallengeForSDP(ev->getHome(),msg,sip);
		if (sip->sip_status->st_status==200 || isEarlyMedia(sip)){
			if ((c=static_cast<RelayedCall*>(mCalls.find(sip)))!=NULL){
				if (sip->sip_status->st_status==200 && c->isNew200Ok(sip)){
					process200OkforInvite (c,msg,sip);
				}else if (isEarlyMedia(sip) && c->isNewEarlyMedia (sip)){
					process200OkforInvite (c,msg,sip);
				}else if (sip->sip_status->st_status==200 || isEarlyMedia(sip)){
					LOGD("This is a 200 or 183  retransmission");
					if (c->getLastForwaredResponse()!=NULL){
						msg=msg_copy(c->getLastForwaredResponse ());
						sip=(sip_t*)msg_object (msg);
					}
				}
			}else LOGW("Receiving 200Ok for unknown call.");
		}
	}
	ev->mSip=sip;
	ev->mMsg=msg;
}


void MediaRelay::onIdle(){
	mCalls.dump();
	mCalls.removeAndDeleteInactives();
}
