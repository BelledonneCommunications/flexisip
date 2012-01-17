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

#include <vector>
#include <functional>
#include <algorithm>

class TickerManager{
	public:
		TickerManager(){
			mStarted=false;
		}
		MSTicker *chooseOne(){
			if (!mStarted){
				int cpucount=getCpuCount();
				mLastTickerIndex=0;
				for(int i=0;i<cpucount;++i){
					mTickers.push_back(ms_ticker_new());
				}
				mStarted=true;
			}
			if (mLastTickerIndex>=mTickers.size()) mLastTickerIndex=0;
			return mTickers[mLastTickerIndex++];
			
		}
		~TickerManager(){
			std::for_each(mTickers.begin(),mTickers.end(),std::ptr_fun(ms_ticker_destroy));
		}
	private:
		int getCpuCount(){
			char line[256]={0};
			int count=0;
			FILE *f=fopen("/proc/cpuinfo","r");
			if (f!=NULL){
				while(fgets(line,sizeof(line),f)){
					if (strstr(line,"processor")==line)
						count++;
				}
				LOGI("Found %i processors",count);
				fclose(f);
			}else count=1;
			return count;
		}
		std::vector<MSTicker*> mTickers;
		unsigned int mLastTickerIndex;
		bool mStarted;
};

class TranscodeModule : public Module, protected ModuleToolbox {
	public:
		TranscodeModule(Agent *ag);
		~TranscodeModule();
		virtual void onLoad(Agent *agent, const ConfigStruct *module_config);
		virtual void onRequest(std::shared_ptr<SipEvent> &ev);
		virtual void onResponse(std::shared_ptr<SipEvent> &ev);
		virtual void onIdle();
		virtual void onDeclare(ConfigStruct *module_config);
	private:
		TickerManager mTickerManager;
		int handleOffer(CallContext *c, std::shared_ptr<SipEvent> &ev);
		int handleAnswer(CallContext *c, std::shared_ptr<SipEvent> &ev);
		int processNewInvite(CallContext *c, std::shared_ptr<SipEvent> &ev);
		void process200OkforInvite(CallContext *ctx, std::shared_ptr<SipEvent> &ev);
		void processNewAck(CallContext *ctx, std::shared_ptr<SipEvent> &ev);
		bool processSipInfo(CallContext *c, msg_t *msg, sip_t *sip);
		void onTimer();	
		static void sOnTimer(void *unused, su_timer_t *t, void *zis);
		bool canDoRateControl(sip_t *sip);
		bool isOneCodecSupported(const MSList *ioffer);
		MSList *normalizePayloads(MSList *l);
		MSList *orderList(const std::list<std::string> &config, const MSList *l);
		MSList *mSupportedAudioPayloads;
		CallStore mCalls;
		su_timer_t *mTimer;
		std::list<std::string> mRcUserAgents;
		CallContextParams mCallParams;
		bool mBlockRetrans;
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
	payload_type_set_number(&payload_type_ilbc,-1);
	MSList *l=NULL;
	l=ms_list_append(l,&payload_type_speex_nb);
	l=ms_list_append(l,&payload_type_ilbc);
	l=ms_list_append(l,&payload_type_amr);
	l=ms_list_append(l,&payload_type_gsm);
	l=ms_list_append(l,&payload_type_pcmu8000);
	l=ms_list_append(l,&payload_type_pcma8000);
	//l=ms_list_append(l,&payload_type_speex_wb);
	
	return l;
}

bool TranscodeModule::isOneCodecSupported(const MSList *ioffer){
	const MSList *e1,*e2;
	for(e1=ioffer;e1!=NULL;e1=e1->next){
		PayloadType *p1=(PayloadType*)e1->data;
		for(e2=mSupportedAudioPayloads;e2!=NULL;e2=e2->next){
			PayloadType *p2=(PayloadType*)e2->data;
			if (strcasecmp(p1->mime_type,p2->mime_type)==0 && p1->clock_rate==p2->clock_rate)
				return true;
		}
	}
	return false;
}

TranscodeModule::TranscodeModule(Agent *ag) : Module(ag),mTimer(0){
	mSupportedAudioPayloads=NULL;
}

TranscodeModule::~TranscodeModule(){
	if (mTimer)
		getAgent()->stopTimer(mTimer);
	ms_list_free(mSupportedAudioPayloads);
}

void TranscodeModule::onDeclare(ConfigStruct *module_config){
	/*we need to be disabled by default*/
	module_config->get<ConfigBoolean>("enabled")->setDefault("false");
	ConfigItemDescriptor items[]={
		{	Integer		,	"jb-nom-size"	,	"Nominal size of RTP jitter buffer, in milliseconds. A value of 0 means no jitter buffer (packet processing).",
												"0" },
		{	StringList	,	"rc-user-agents",	"Whitespace separated list of user-agent strings for which audio rate control is performed.",""},
		{	StringList	,	"audio-codecs",	"Whitespace seprated list of audio codecs, in order of preference.",
			"speex/8000 amr/8000 iLBC/8000 gsm/8000 pcmu/8000 pcma/8000"},
		{	Boolean , "block-retransmissions", "If true, retransmissions of INVITEs will be blocked. "
			"The purpose of this option is to limit bandwidth usage and server load on reliable networks.","false" },
			config_item_end
	};
	module_config->addChildrenValues(items);
}

MSList *TranscodeModule::orderList(const std::list<std::string> &config, const MSList *l){
	int err;
	int rate;
	MSList *ret=NULL;
	const MSList *it;
	std::list<std::string>::const_iterator cfg_it;
	
	for(cfg_it=config.begin();cfg_it!=config.end();++cfg_it){
		char name[(*cfg_it).size()+1];
		char *p;

		strcpy(name,(*cfg_it).c_str());
		p=strchr(name,'/');
		if (p) {
			*p='\0';
			p++;
		}else LOGF("Error parsing audio codec list");
		
		err=sscanf(p,"%i",&rate);
		if (err!=1) LOGF("Error parsing audio codec list, missing rate information");
		for(it=l;it!=NULL;it=it->next){
			PayloadType *pt=(PayloadType*)it->data;
			if (strcasecmp(pt->mime_type,name)==0 && rate==pt->clock_rate){
				if (ms_filter_get_encoder(pt->mime_type)!=NULL){
					ret=ms_list_append(ret,pt);
				}else{
					LOGE("Codec %s/%i is configured but is not supported (missing plugin ?)",name,rate);
				}
			}
		}
	}
	return ret;
}

void TranscodeModule::onLoad(Agent *agent, const ConfigStruct *module_config){
	mTimer=agent->createTimer(20,&sOnTimer,this);
	mCallParams.mJbNomSize=module_config->get<ConfigInt>("jb-nom-size")->read();
	mRcUserAgents=module_config->get<ConfigStringList>("rc-user-agents")->read();
	MSList *l=makeSupportedAudioPayloadList();
	mSupportedAudioPayloads=orderList(module_config->get<ConfigStringList>("audio-codecs")->read(),l);
	mBlockRetrans=module_config->get<ConfigBoolean>("block-retransmissions")->read();
	ms_list_free(l);
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
				return true;
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
			c->playTone(sip);
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

int TranscodeModule::handleOffer(CallContext *c, std::shared_ptr<SipEvent> &ev){
	msg_t *msg=ev->mMsg;
	sip_t *sip=ev->mSip;
	std::string addr;
	int port;
	int ptime;
	SdpModifier *m=SdpModifier::createFromSipMsg(c->getHome(), ev->mSip);

	if (m==NULL) return -1;
	
	MSList *ioffer=m->readPayloads();
		
	if (isOneCodecSupported(ioffer)){
		c->prepare(mCallParams);
		c->setInitialOffer(ioffer);
		m->getAudioIpPort(&addr,&port);
		ptime=m->readPtime();
		/*forces the front side to bind and allocate a port immediately on the bind-address supplied in the config*/
		LOGD("Front side remote address: %s:%i", addr.c_str(),port);
		c->getFrontSide()->getAudioPort();
		c->getFrontSide()->setRemoteAddr(addr.c_str(),port);
		if (ptime>0){
			c->getFrontSide()->setPtime(ptime);
			m->setPtime(0);//remove the ptime attribute
		}
		port=c->getBackSide()->getAudioPort();
		m->changeAudioIpPort(getAgent()->getPublicIp().c_str(),port);
		m->replacePayloads(mSupportedAudioPayloads,c->getInitialOffer());
		m->update(msg,sip);
		
		if (canDoRateControl(sip)){
			c->getFrontSide()->enableRc(true);
		}
		delete m;
		return 0;
	}else{
		LOGW("No support for any of the codec offered by client, doing bypass.");
		ms_list_for_each(ioffer,(void (*)(void*))payload_type_destroy);
		ms_list_free(ioffer);
	}
	delete m;
	return -1;
}



int TranscodeModule::processNewInvite(CallContext *c,std::shared_ptr<SipEvent> &ev){
	int ret=0;
	if (SdpModifier::hasSdp(ev->mSip)){
		ret=handleOffer(c,ev);
	}
	if (ret==0){
		//be in the record-route
		addRecordRoute(c->getHome(),getAgent(),ev->mMsg,ev->mSip);
		c->storeNewInvite(ev->mMsg);
	}else{
		nta_msg_treply(getSofiaAgent(),ev->mMsg,415,"Unsupported codecs",TAG_END());
		ev->stopProcessing();
	}
	return ret;
}

void TranscodeModule::processNewAck(CallContext *ctx, std::shared_ptr<SipEvent> &ev){
	LOGD("Processing ACK");
	const MSList *ioffer=ctx->getInitialOffer();
	if (ioffer==NULL){
		LOGE("Processing ACK with SDP but no offer was made or processed.");
	}else{
		handleAnswer(ctx,ev);
		ctx->storeNewAck(ev->mMsg);
	}
}

void TranscodeModule::onRequest(std::shared_ptr<SipEvent> &ev){
	CallContext *c;
	msg_t *msg=ev->mMsg;
	sip_t *sip=ev->mSip;
	
	if (sip->sip_request->rq_method==sip_method_invite){
		if ((c=static_cast<CallContext*>(mCalls.find(sip)))==NULL){
			c=new CallContext(sip,getAgent()->getBindIp());
			mCalls.store(c);
			processNewInvite(c,ev);
		}else{
			if (c->isNewInvite(sip)){
				processNewInvite(c,ev);
			}else if (mAgent->countUsInVia(sip->sip_via)) {
				LOGD("We are already in VIA headers of this request");
				return;
			}else if (c->getLastForwardedInvite()!=NULL){
				if (!mBlockRetrans){
					LOGD("This is an invite retransmission.");
					msg=msg_copy(c->getLastForwardedInvite ());
					sip=(sip_t*)msg_object(msg);	
				}else{
					LOGD("Retransmission ignored.");
					ev->stopProcessing();
				}
			}
		}
	}else if (sip->sip_request->rq_method==sip_method_ack && SdpModifier::hasSdp(sip)){
		if ((c=static_cast<CallContext*>(mCalls.find(sip)))==NULL){
			LOGD("Seeing ACK with no call reference");
		}else{
			if (c->isNewAck(sip)){
				processNewAck(c,ev);
			}else if (mAgent->countUsInVia(sip->sip_via)) {
				LOGD("We are already in VIA headers of this request");
				return;
			}else if (c->getLastForwardedAck()!=NULL){
				msg=msg_copy(c->getLastForwardedAck());
				sip=(sip_t*)msg_object(msg);
				LOGD("Forwarding ack retransmission");
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

int TranscodeModule::handleAnswer(CallContext *ctx, std::shared_ptr<SipEvent> &ev){
	std::string addr;
	int port;
	const MSList *ioffer=ctx->getInitialOffer();
	SdpModifier *m=SdpModifier::createFromSipMsg(ctx->getHome(), ev->mSip);
	int ptime;
	
	if (m==NULL) return -1;
	if (ctx->isJoined()) ctx->unjoin();
	
	m->getAudioIpPort (&addr,&port);
	ptime=m->readPtime();
	LOGD("Backside remote address: %s:%i", addr.c_str(),port);
	ctx->getBackSide()->setRemoteAddr(addr.c_str(),port);
	if (ptime>0){
		ctx->getBackSide()->setPtime(ptime);
		m->setPtime(0);//remove the ptime attribute
	}
	m->changeAudioIpPort (getAgent()->getPublicIp().c_str(),ctx->getFrontSide()->getAudioPort());

	MSList *answer=m->readPayloads();
	if (answer==NULL){
		LOGE("No payloads in 200Ok");
		delete m;
		return -1;
	}
	ctx->getBackSide()->assignPayloads(normalizePayloads(answer));
	ms_list_free(answer);
	
	MSList *common=SdpModifier::findCommon(mSupportedAudioPayloads,ioffer,false);
	if (common!=NULL){
		m->replacePayloads(common,NULL);
	}
	m->update(ev->mMsg,ev->mSip);
	
	ctx->getFrontSide()->assignPayloads(normalizePayloads(common));

	if (canDoRateControl(ev->mSip)){
		ctx->getBackSide()->enableRc(true);
	}

	ctx->join(mTickerManager.chooseOne());
	delete m;
	return 0;
}

void TranscodeModule::process200OkforInvite(CallContext *ctx, std::shared_ptr<SipEvent> &ev){
	LOGD("Processing 200 Ok");
	if (SdpModifier::hasSdp((sip_t*)msg_object(ctx->getLastForwardedInvite()))){
		handleAnswer(ctx,ev);
	}else{
		handleOffer(ctx,ev);
	}
	ctx->storeNewResponse(ev->mMsg);
}

static bool isEarlyMedia(sip_t *sip){
	if (sip->sip_status->st_status==180 || sip->sip_status->st_status==183){
		return SdpModifier::hasSdp(sip);
	}
	return false;
}

void TranscodeModule::onResponse(std::shared_ptr<SipEvent> &ev){
	sip_t *sip=ev->mSip;
	msg_t *msg=ev->mMsg;
	CallContext *c;
	if (sip->sip_cseq && sip->sip_cseq->cs_method==sip_method_invite){
		fixAuthChallengeForSDP(ev->getHome(),msg,sip);
		if ((c=static_cast<CallContext*>(mCalls.find(sip)))!=NULL){
			if (sip->sip_status->st_status==200 && c->isNew200Ok(sip)){
				process200OkforInvite(c,ev);
			}else if (isEarlyMedia(sip) && c->isNewEarlyMedia (sip)){
				process200OkforInvite(c,ev);
			}else if (sip->sip_status->st_status==200 || isEarlyMedia(sip)){
				if (mAgent->countUsInVia(sip->sip_via)) {
					LOGD("We are already in VIA headers of this response");
					return;
				}
				LOGD("This is a 200 or 183 retransmission");
				if (c->getLastForwaredResponse()!=NULL){
					msg=msg_copy(c->getLastForwaredResponse ());
					sip=(sip_t*)msg_object(msg);
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

