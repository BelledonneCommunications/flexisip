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
		virtual void onLoad(Agent *ag, const ConfigArea & modconf);
		virtual void onRequest(SipEvent *ev);
		virtual void onResponse(SipEvent *ev);
		virtual void onIdle();
	private:
		void processNewInvite(RelayedCall *c, msg_t *msg, sip_t *sip);
		void process200OkforInvite(RelayedCall *ctx, msg_t *msg, sip_t *sip);
		CallStore mCalls;
		MediaRelayServer mServer;
		static ModuleInfo <MediaRelay> sInfo;
};

class RelayedCall : public CallContextBase, public Masquerader{
	public:
		RelayedCall(MediaRelayServer *server, sip_t *sip) : CallContextBase (sip), mServer(server){
		}
		virtual void onNewMedia(int mline, std::string *ip, int *port){
			int ports[2];
			if (mline>=(int)mSessions.size())
				mSessions.resize(mline+1);
			RelaySession *s=mSessions[mline];
			if (s){
				/*we are processing a SDP answer since sessions are created */
				 s->getPorts(ports);
				*ip=s->getAddr();
				*port=ports[1];
			}else{
				s=mServer->createSession();
				 s->getPorts(ports);
				*ip=s->getAddr();
				*port=ports[0];
				mSessions[mline]=s;
			}
		}
		virtual bool isInactive(time_t cur){
			time_t maxtime=0;
			vector<RelaySession*>::const_iterator it;
			for (it=mSessions.begin();it!=mSessions.end();++it){
				time_t tmp;
				if ((tmp=(*it)->getLastActivityTime()) > maxtime)
					maxtime=tmp;
			}
			if (cur-maxtime>30) return true;
			return false;
		}
		virtual ~RelayedCall(){
			for_each(mSessions.begin(),mSessions.end(),mem_fun(&RelaySession::unuse));
		}
	private:
		vector<RelaySession*> mSessions;
		MediaRelayServer *mServer;
};

ModuleInfo<MediaRelay> MediaRelay::sInfo("MediaRelay");

MediaRelay::MediaRelay(Agent *ag) : Module(ag), mServer(ag->getLocAddr ()){
}

MediaRelay::~MediaRelay(){
}

void MediaRelay::onLoad(Agent *ag, const ConfigArea & modconf){
}


void MediaRelay::processNewInvite(RelayedCall *c, msg_t *msg, sip_t *sip){
	SdpModifier *m=SdpModifier::createFromSipMsg(c->getHome(), sip);
	if (m){
		m->changeIpPort(c);
		m->update(msg,sip);
		//be in the record-route
		addRecordRoute(c->getHome(),getAgent(),sip);
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
			c=new RelayedCall(&mServer,sip);
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
	SdpModifier *m=SdpModifier::createFromSipMsg(ctx->getHome(), sip);

	if (m==NULL) return;
	
	m->changeIpPort (ctx);
	m->update(msg,sip);
	ctx->storeNewResponse (msg);

	delete m;
}


void MediaRelay::onResponse(SipEvent *ev){
	sip_t *sip=ev->mSip;
	msg_t *msg=ev->mMsg;
	RelayedCall *c;
	
	if (sip->sip_cseq && sip->sip_cseq->cs_method==sip_method_invite){
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
		}
	}
	ev->mSip=sip;
	ev->mMsg=msg;
}


void MediaRelay::onIdle(){
	mCalls.dump();
	mCalls.removeInactives();
}
