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


#include "transcodeagent.hh"

#include "sdp-modifier.hh"

static MSList *makeSupportedAudioPayloadList(){
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
	l=ms_list_append(l,&payload_type_speex_wb);
	l=ms_list_append(l,&payload_type_amr);
	return l;
}

TranscodeAgent::TranscodeAgent(su_root_t *root, const char *locaddr, int port) :
	Agent(root,locaddr,port){
	ortp_init();
	ms_init();
	mTicker=ms_ticker_new();
	mSupportedAudioPayloads=makeSupportedAudioPayloadList();
}

TranscodeAgent::~TranscodeAgent(){
	ms_ticker_destroy(mTicker);
}

void TranscodeAgent::processNewInvite(CallContext *c, msg_t *msg, sip_t *sip){
	SdpModifier *m=SdpModifier::createFromSipMsg(c->getHome(), sip);
	c->setInitialOffer (m->readPayloads ());
	m->changeAudioIpPort (getLocAddr().c_str(),getPort());
	m->appendNewPayloadsAndRemoveUnsupported(mSupportedAudioPayloads);
	m->update(msg,sip);
	delete m;
	Agent::onRequest(msg,sip);
}

int TranscodeAgent::onRequest(msg_t *msg, sip_t *sip){
	CallContext *c;
	if (sip->sip_request->rq_method==sip_method_invite){
		if ((c=static_cast<CallContext*>(mCalls.find(sip)))==NULL){
			c=new CallContext(sip);
			mCalls.store(c);
			processNewInvite(c,msg,sip);
		}else{
			if (c->isNewInvite(sip)){
				processNewInvite(c,msg,sip);
			}else
				LOGW("Invite retransmission, not handled yet");
		}
	}else{
		//all other requests go through
		Agent::onRequest(msg,sip);
	}
	return 0;
}

void TranscodeAgent::process200OkforInvite(CallContext *ctx, msg_t *msg, sip_t *sip){
	LOGD("Processing 200 Ok");
	const MSList *ioffer=ctx->getInitialOffer ();
	SdpModifier *m=SdpModifier::createFromSipMsg(ctx->getHome(), sip);
	MSList *answer=m->readPayloads ();
	MSList *common=SdpModifier::findCommon (ioffer,mSupportedAudioPayloads);
	if (common!=NULL){
		m->appendNewPayloadsAndRemoveUnsupported(common);
		ms_list_for_each(common,(void(*)(void*))payload_type_destroy);
		ms_list_free(common);
	}
	ctx->getBackSide ()->assignPayloads (answer);
	ms_list_free(answer);
	// read the modified answer to get payload list in right order:
	answer=m->readPayloads ();
	ctx->getFrontSide ()->assignPayloads (answer);
}

int TranscodeAgent::onResponse(msg_t *msg, sip_t *sip){
	CallContext *c;
	if (sip->sip_status->st_status==200 && sip->sip_cseq 
	    && sip->sip_cseq->cs_method==sip_method_invite){
		if ((c=static_cast<CallContext*>(mCalls.find(sip)))!=NULL){
			if (c->isNew200Ok(sip))
				process200OkforInvite (c,msg,sip);
		}
	}
	return Agent::onResponse(msg,sip);
}


