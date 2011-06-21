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
#include "callcontext.hh"
#include "sdp-modifier.hh"

class TranscodeModule : public Module, protected ModuleToolbox {
	public:
		TranscodeModule(Agent *ag);
		~TranscodeModule();
		virtual void onLoad(Agent *agent, const ConfigStruct *module_config);
		virtual void onRequest(SipEvent *ev);
		virtual void onResponse(SipEvent *ev);
		virtual void onIdle();
		virtual void onDeclare(ConfigStruct *module_config);
	private:
		void processNewInvite(CallContext *c, msg_t *msg, sip_t *sip);
		void process200OkforInvite(CallContext *ctx, msg_t *msg, sip_t *sip);
		bool processSipInfo(CallContext *c, msg_t *msg, sip_t *sip);
		void onTimer();		
		static void sOnTimer(void *unused, su_timer_t *t, void *zis);
		bool canDoRateControl(sip_t *sip);
		MSList *normalizePayloads(MSList *l);
		MSList *mSupportedAudioPayloads;
		MSTicker *mTicker;
		CallStore mCalls;
		su_timer_t *mTimer;
		std::list<std::string> mRcUserAgents;
		static ModuleInfo<TranscodeModule> sInfo;
};

ModuleInfo<TranscodeModule> TranscodeModule::sInfo("Transcoder",
	"The purpose of the Transcoder module is to transparently transcode from one audio codec to another to make "
    "the communication possible between clients that do not share the same set of supported codecs. "
    "Concretely it adds all missing codecs into the INVITEs it receives, and adds codecs matching the original INVITE into the 200Ok. "
	"Rtp ports and addresses are masqueraded so that the streams can be processed by the proxy. "
	"The transcoding job is done in the background by the mediastreamer2 library, as consequence the set of "
	"supported codecs is exactly the the same as the codec set supported by mediastreamer2, including "
    "the possible plugins you may installed to extend mediastreamer2. "
    "WARNING: this module can conflict with the MediaRelay module as both are changin the SDP. "
    "Make sure to configure them with different to-domains or from-domains filter if you want to enable both of them." );


static MSList *makeSupportedAudioPayloadList(){
	/* in mediastreamer2, we use normal_bitrate as an IP bitrate, not codec bitrate*/
	payload_type_speex_nb.normal_bitrate=32000;
	payload_type_speex_wb.normal_bitrate=42000;
	payload_type_speex_nb.recv_fmtp=ms_strdup("vbr=on");
	payload_type_amr.recv_fmtp=ms_strdup("octet-align=1");
	
	payload_type_set_number(&payload_type_pcmu8000,0);
	payload_type_set_number(&payload_type_pcma8000,8);
	payload_type_set_number(&payload_type_gsm,3);
	payload_type_set_number(&payload_type_speex_nb,-1);
	payload_type_set_number(&payload_type_speex_wb,-1);
	payload_type_set_number(&payload_type_amr,-1);
	MSList *l=ms_list_append(NULL,&payload_type_pcmu8000);
	l=ms_list_append(l,&payload_type_pcma8000);
	l=ms_list_append(l,&payload_type_gsm);
	l=ms_list_append(l,&payload_type_speex_nb);
	//l=ms_list_append(l,&payload_type_speex_wb);
	l=ms_list_append(l,&payload_type_amr);
	return l;
}


TranscodeModule::TranscodeModule(Agent *ag) : Module(ag){
	mTicker=NULL;
	mTimer=ag->createTimer(20,&sOnTimer,this);
	mSupportedAudioPayloads=makeSupportedAudioPayloadList();
}

TranscodeModule::~TranscodeModule(){
	if (mTicker) ms_ticker_destroy(mTicker);
	if (mTimer)
		getAgent()->stopTimer(mTimer);
	ms_list_free(mSupportedAudioPayloads);
}

void TranscodeModule::onDeclare(ConfigStruct *module_config){
	/*we need to be disabled by default*/
	module_config->get<ConfigBoolean>("enabled")->setDefault("false");
	ConfigItemDescriptor items[]={
		{	StringList	,	"rc-user-agents",	"List of whitelist separated user-agent string for which audio rate control is performed.",""},
			config_item_end
	};
	module_config->addChildrenValues(items);
}

void TranscodeModule::onLoad(Agent *agent, const ConfigStruct *module_config){

	mRcUserAgents=module_config->get<ConfigStringList>("rc-user-agents")->read();
}

void TranscodeModule::onIdle(){
	mCalls.dump();
	mCalls.removeAndDeleteInactives();
}

bool TranscodeModule::canDoRateControl(sip_t *sip){
	if (sip->sip_user_agent!=NULL && sip->sip_user_agent->g_string!=NULL){
		std::list<std::string>::const_iterator it;
		for(it=mRcUserAgents.begin();it!=mRcUserAgents.end();++it){
			if (strstr(sip->sip_user_agent->g_string,(*it).c_str())){
				LOGD("Audio rate control supported for %s",sip->sip_user_agent->g_string);
			}
		}
	}
	return false;
}

bool TranscodeModule::processSipInfo(CallContext *c, msg_t *msg, sip_t *sip){
	sip_payload_t *payload=sip->sip_payload;
	if (payload!=NULL && payload->pl_data!=NULL) {
		if (sip->sip_content_type!=NULL && 
		    strcasecmp(sip->sip_content_type->c_subtype,"dtmf-relay")==0){
			c->playTone (sip);
			nta_msg_treply(getSofiaAgent(),msg,200,NULL,TAG_END());
			return true;
		}
	}
	return false;
}

static const PayloadType *findPt(const MSList *l, const char *mime, int rate){
	for(;l!=NULL;l=l->next){
		const PayloadType *pt=(PayloadType*)l->data;
		if (pt->clock_rate==rate && strcasecmp(mime,pt->mime_type)==0)
			return pt;
	}
	return NULL;
}

MSList *TranscodeModule::normalizePayloads(MSList *l){
	MSList *it;
	for(it=l;it!=NULL;it=it->next){
		PayloadType *pt=(PayloadType*)l->data;
		if (pt->normal_bitrate==0){
			const PayloadType *refpt=findPt(mSupportedAudioPayloads,pt->mime_type,pt->clock_rate);
			if (refpt && refpt->normal_bitrate>0){
				ms_message("Using %s at bitrate %i",pt->mime_type,refpt->normal_bitrate);
				pt->normal_bitrate=refpt->normal_bitrate;
			}
		}
	}
	return l;
}

void TranscodeModule::processNewInvite(CallContext *c, msg_t *msg, sip_t *sip){
	std::string addr;
	int port;
	SdpModifier *m=SdpModifier::createFromSipMsg(c->getHome(), sip);
	if (m){
		c->prepare(sip);
		c->setInitialOffer (m->readPayloads ());
		m->getAudioIpPort (&addr,&port);
		c->getFrontSide()->setRemoteAddr(addr.c_str(),port);
		port=c->getBackSide()->getAudioPort();
		m->changeAudioIpPort(getAgent()->getLocAddr().c_str(),port);
		m->appendNewPayloadsAndRemoveUnsupported(mSupportedAudioPayloads);
		m->update(msg,sip);
		//be in the record-route
		addRecordRoute(c->getHome(),getAgent(),sip);
		c->storeNewInvite (msg);
		if (canDoRateControl(sip)){
			c->getFrontSide()->enableRc(true);
		}
		delete m;
	}
	
}

void TranscodeModule::onRequest(SipEvent *ev){
	CallContext *c;
	msg_t *msg=ev->mMsg;
	sip_t *sip=ev->mSip;
	
	if (sip->sip_request->rq_method==sip_method_invite){
		if ((c=static_cast<CallContext*>(mCalls.find(sip)))==NULL){
			c=new CallContext(sip);
			mCalls.store(c);
			processNewInvite(c,msg,sip);
		}else{
			if (c->isNewInvite(sip)){
				processNewInvite(c,msg,sip);
			}else if (mAgent->countUsInVia(sip->sip_via)) {
				LOGD("We are already in VIA headers of this request");
				return;
			}else if (c->getLastForwardedInvite()!=NULL){
				msg=msg_copy(c->getLastForwardedInvite ());
				sip=(sip_t*)msg_object(msg);
				LOGD("Forwarding invite retransmission");
			}
		}
	}else{
		 if (sip->sip_request->rq_method==sip_method_info){
			 if ((c=static_cast<CallContext*>(mCalls.find(sip)))!=NULL){
				if (processSipInfo(c,msg,sip)){
					ev->stopProcessing();
					/*stop the processing */
					return; 
				}
			}
		 }
		
		//all other requests go through

		if (sip->sip_request->rq_method==sip_method_bye){
			if ((c=static_cast<CallContext*>(mCalls.find(sip)))!=NULL){
				mCalls.remove(c);
				delete c;
			}
		}
	}
	ev->mMsg=msg;
	ev->mSip=sip;
}

void TranscodeModule::process200OkforInvite(CallContext *ctx, msg_t *msg, sip_t *sip){
	LOGD("Processing 200 Ok");
	const MSList *ioffer=ctx->getInitialOffer ();
	std::string addr;
	int port;
	SdpModifier *m=SdpModifier::createFromSipMsg(ctx->getHome(), sip);

	if (m==NULL) return;
	
	if (ctx->isJoined()) ctx->unjoin();
	
	m->getAudioIpPort (&addr,&port);
	LOGD("Backside remote address: %s:%i", addr.c_str(),port);
	ctx->getBackSide()->setRemoteAddr(addr.c_str(),port);
	m->changeAudioIpPort (getAgent()->getLocAddr().c_str(),ctx->getFrontSide()->getAudioPort());

	MSList *answer=m->readPayloads ();
	if (answer==NULL){
		LOGE("No payloads in 200Ok");
		delete m;
		return;
	}
	MSList *common=SdpModifier::findCommon (ioffer,mSupportedAudioPayloads, true);
	if (common!=NULL){
		m->appendNewPayloadsAndRemoveUnsupported(common);
		ms_list_for_each(common,(void(*)(void*))payload_type_destroy);
		ms_list_free(common);
	}
	m->update(msg,sip);
	ctx->storeNewResponse (msg);
	ctx->getBackSide ()->assignPayloads (normalizePayloads(answer));
	ms_list_free(answer);
	// read the modified answer to get payload list in right order:
	answer=m->readPayloads ();
	if (answer==NULL){
		LOGE("No payloads in forwarded 200Ok");
		delete m;
		return;
	}
	ctx->getFrontSide ()->assignPayloads (normalizePayloads(answer));
	ms_list_free(answer);

	if (canDoRateControl(sip)){
		ctx->getBackSide()->enableRc(true);
	}

	if (mTicker==NULL)
		mTicker=ms_ticker_new();
	ctx->join(mTicker);
	
	delete m;
}

static bool isEarlyMedia(sip_t *sip){
	if (sip->sip_status->st_status==180 || sip->sip_status->st_status==183){
		sip_payload_t *payload=sip->sip_payload;
		//TODO: should check if it is application/sdp
		return payload!=NULL;
	}
	return false;
}

void TranscodeModule::onResponse(SipEvent *ev){
	sip_t *sip=ev->mSip;
	msg_t *msg=ev->mMsg;
	CallContext *c;
	if (sip->sip_cseq && sip->sip_cseq->cs_method==sip_method_invite){
		if ((c=static_cast<CallContext*>(mCalls.find(sip)))!=NULL){
			if (sip->sip_status->st_status==200 && c->isNew200Ok(sip)){
				process200OkforInvite (c,msg,sip);
			}else if (isEarlyMedia(sip) && c->isNewEarlyMedia (sip)){
				process200OkforInvite (c,msg,sip);
			}else if (sip->sip_status->st_status==200 || isEarlyMedia(sip)){
				if (mAgent->countUsInVia(sip->sip_via)) {
					LOGD("We are already in VIA headers of this response");
					return;
				}
				LOGD("This is a 200 or 183 retransmission");
				if (c->getLastForwaredResponse()!=NULL){
					msg=msg_copy(c->getLastForwaredResponse ());
					sip=(sip_t*)msg_object (msg);
					ev->mSip=sip;
					ev->mMsg=msg;
				}
			}
		}
	}
}

void TranscodeModule::onTimer(){
	for(std::list<CallContextBase*>::const_iterator it=mCalls.getList().begin();it!=mCalls.getList().end();++it){
		static_cast<CallContext*>(*it)->doBgTasks();
	}	
}
		
void TranscodeModule::sOnTimer(void *unused, su_timer_t *t, void *zis){
	((TranscodeModule*)zis)->onTimer();
}

