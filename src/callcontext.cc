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


#include "callcontext.hh"

#include "mediastreamer2/dtmfgen.h"
#include "ortp/telephonyevents.h"

#include "sdp-modifier.hh"

using namespace ::std;

CallSide::CallSide(CallContext *ctx, const CallContextParams &params) : mCallCtx(ctx){
	mSession=rtp_session_new(RTP_SESSION_SENDRECV);
	mProfile=rtp_profile_new("Call profile");
	mEncoder=NULL;
	mDecoder=NULL;
	mRc=NULL;
	
	mReceiver=ms_filter_new(MS_RTP_RECV_ID);
	mSender=ms_filter_new(MS_RTP_SEND_ID);
	mToneGen=ms_filter_new(MS_DTMF_GEN_ID);

	rtp_session_set_profile(mSession,mProfile);
	rtp_session_set_recv_buf_size(mSession,300);
	rtp_session_set_scheduling_mode(mSession,0);
	rtp_session_set_blocking_mode(mSession,0);
	/*  no jitter buffer: we are just doing packet processing*/
	mUsePlc=params.mJbNomSize==0 ? false : true;
	JBParameters jbpar;
	jbpar.min_size=jbpar.nom_size=params.mJbNomSize;
	jbpar.max_size=200;
	jbpar.adaptive=true;
	jbpar.max_packets=100;
	rtp_session_enable_jitter_buffer(mSession,params.mJbNomSize==0 ? FALSE : TRUE);
	rtp_session_set_jitter_buffer_params(mSession, &jbpar);
	LOGD("Jitter buffer nominal size: %i",params.mJbNomSize);
	rtp_session_set_symmetric_rtp(mSession,TRUE);
	rtp_session_set_data(mSession,this);
	rtp_session_signal_connect(mSession,"payload_type_changed",(RtpCallback)&CallSide::payloadTypeChanged,
	                           reinterpret_cast<long>(ctx));
	rtp_session_signal_connect(mSession,"timestamp_jump",(RtpCallback)rtp_session_resync,(long unsigned int)NULL);
	rtp_session_signal_connect(mSession,"ssrc_changed",(RtpCallback)rtp_session_resync,(long unsigned int)NULL);
	rtp_session_signal_connect(mSession,"telephone-event",(RtpCallback)&CallSide::onTelephoneEvent,reinterpret_cast<long>(ctx));
	mRtpEvq=NULL;
	mLastCheck=0;
	mLastRecvCount=0;
	mPtime=0;
	mRcEnabled=false;
}

void CallSide::enableRc(bool enabled){
	mRcEnabled=enabled;
}

int CallSide::getAudioPort(){
	int port=rtp_session_get_local_port(mSession);
	if (port==-1){
		/*request oRTP to bind randomly*/
		rtp_session_set_local_addr(mSession,mCallCtx->getBindAddress().c_str(),-1);
		port=rtp_session_get_local_port(mSession);
	}
	return port;
}

void CallSide::setRemoteAddr(const char *addr, int port){
	rtp_session_set_remote_addr(mSession,addr,port);
}

void CallSide::setPtime(int ptime){
	mPtime=ptime;
}

void CallSide::assignPayloads(const MSList *payloads){
	const MSList *elem;
	for (elem=payloads;elem!=NULL;elem=elem->next){
		PayloadType *pt=(PayloadType*)elem->data;
		PayloadType *oldpt=rtp_profile_get_payload(mProfile,payload_type_get_number(pt));
		if (oldpt){
			payload_type_destroy(oldpt);
		}
		rtp_profile_set_payload(mProfile, payload_type_get_number(pt),pt);
		if (payloads==elem){
			rtp_session_set_payload_type(mSession,payload_type_get_number(pt));
		}
		if (strcmp("telephone-event",pt->mime_type)==0) {
			rtp_session_telephone_events_supported(mSession);
		}
	}
	ms_filter_call_method(mReceiver,MS_RTP_RECV_SET_SESSION,mSession);
	ms_filter_call_method(mSender,MS_RTP_SEND_SET_SESSION,mSession);
}

CallSide::~CallSide(){
	if (mRtpEvq) {
		ortp_ev_queue_destroy(mRtpEvq);
		rtp_session_unregister_event_queue(mSession,mRtpEvq);
	}
	rtp_session_destroy(mSession);
	rtp_profile_destroy(mProfile);
	ms_filter_destroy(mReceiver);
	ms_filter_destroy(mSender);
	ms_filter_destroy(mToneGen);
	if (mEncoder)
		ms_filter_destroy(mEncoder);
	if (mDecoder)
		ms_filter_destroy(mDecoder);
	if (mRc)
		ms_bitrate_controller_destroy(mRc);
}

void CallSide::dump(){
	const rtp_stats_t *stats=rtp_session_get_stats(mSession);
	rtp_stats_display(stats,"RTP Statistics:");
}

bool CallSide::isActive(time_t cur){
	const rtp_stats_t *stats=rtp_session_get_stats(mSession);
	if (mLastCheck==0){
		mLastCheck=cur;
		mLastRecvCount=stats->recv;
	}else{
		if (stats->recv!=mLastRecvCount){
			mLastRecvCount=stats->recv;
			mLastCheck=cur;
		}else if (cur-mLastCheck>60){
			ms_message("Inactive callside for more than 60 seconds.");
			return false;
		}
	}
	return true;
}

PayloadType *CallSide::getSendFormat(){
	int pt=rtp_session_get_send_payload_type(mSession);
	RtpProfile *prof=rtp_session_get_send_profile(mSession);
	return rtp_profile_get_payload(prof,pt);
}

MSConnectionPoint CallSide::getRecvPoint(){
	MSConnectionPoint ret;
	ret.filter=mReceiver;
	ret.pin=0;
	return ret;
}

PayloadType * CallSide::getRecvFormat(){
	int pt=rtp_session_get_recv_payload_type(mSession);
	RtpProfile *prof=rtp_session_get_recv_profile(mSession);
	return rtp_profile_get_payload(prof,pt);
}

void CallSide::connect(CallSide *recvSide, MSTicker *t){
	MSConnectionHelper h;
	PayloadType *recvpt;
	PayloadType *sendpt;
	
	recvpt=recvSide->getRecvFormat();
	sendpt=getSendFormat();
	ms_connection_helper_start(&h);
	ms_connection_helper_link(&h,recvSide->getRecvPoint().filter,-1,
	                          recvSide->getRecvPoint().pin);

	LOGD("recvside enc=%i %s/%i sendside enc=%i %s/%i",
	     payload_type_get_number(recvpt), recvpt->mime_type,recvpt->clock_rate,
	     payload_type_get_number(sendpt), sendpt->mime_type,sendpt->clock_rate);
	if (strcasecmp(recvpt->mime_type,sendpt->mime_type)!=0
	    || recvpt->clock_rate!=sendpt->clock_rate || mToneGen!=0){		

		if (mDecoder){
			if (t) ms_filter_postprocess(mDecoder);
			ms_filter_destroy(mDecoder);
		}
		rtp_session_flush_sockets(mSession);
			
		mDecoder=ms_filter_create_decoder(recvpt->mime_type);
		if (mDecoder==NULL){
			LOGE("Could not instanciate decoder for %s",recvpt->mime_type);
		}else{
			if (!mUsePlc) ms_filter_call_method(mDecoder,MS_FILTER_ADD_FMTP,(void*)"plc=0");
			if (t)
				ms_filter_preprocess(mDecoder,t);
		}
		if (mEncoder){
			if (t) ms_filter_postprocess(mEncoder);
			ms_filter_destroy(mEncoder);
			if (mRc) {
				ms_bitrate_controller_destroy(mRc);
				mRc=NULL;
			}
		}
		mEncoder=ms_filter_create_encoder(sendpt->mime_type);
		if (mEncoder==NULL){
			LOGE("Could not instanciate encoder for %s",sendpt->mime_type);
		}else{
			if (mPtime>0){
				char tmp[20];
				snprintf(tmp,sizeof(tmp),"ptime=%i",mPtime);
				ms_filter_call_method(mEncoder,MS_FILTER_ADD_FMTP,(void*)tmp);
			}
			if (sendpt->send_fmtp!=NULL)
				ms_filter_call_method(mEncoder,MS_FILTER_ADD_FMTP,(void*)sendpt->send_fmtp);
			if (sendpt->normal_bitrate>0)
				ms_filter_call_method(mEncoder,MS_FILTER_SET_BITRATE,(void*)&sendpt->normal_bitrate);
			if (t)
				ms_filter_preprocess(mEncoder,t);
		}
	}
	if (mDecoder)
		ms_connection_helper_link(&h,mDecoder,0,0);
	if (mToneGen)
		ms_connection_helper_link(&h,mToneGen,0,0);
	if (mEncoder)
		ms_connection_helper_link(&h,mEncoder,0,0);
	ms_connection_helper_link(&h,mSender,0,-1);
	if (mRcEnabled && mRc==NULL && mEncoder){
		if (mRtpEvq==NULL){
			mRtpEvq=ortp_ev_queue_new();
			rtp_session_register_event_queue(mSession,mRtpEvq);
		}
		mRc=ms_audio_bitrate_controller_new(mSession,mEncoder,0);
	}
}

void CallSide::disconnect(CallSide *recvSide){
	MSConnectionHelper h;

	ms_connection_helper_start(&h);
	ms_connection_helper_unlink(&h,recvSide->getRecvPoint().filter,-1,
	                            	recvSide->getRecvPoint().pin);
	if (mDecoder)
		ms_connection_helper_unlink(&h,mDecoder,0,0);
	if (mToneGen)
		ms_connection_helper_unlink(&h,mToneGen,0,0);
	if (mEncoder)
		ms_connection_helper_unlink(&h,mEncoder,0,0);
	ms_connection_helper_unlink(&h,mSender,0,-1);
}

void CallSide::payloadTypeChanged(RtpSession *session, unsigned long data){
	CallContext *ctx=reinterpret_cast<CallContext*>(data);
	CallSide *side=static_cast<CallSide*>(rtp_session_get_data(session));
	int num=rtp_session_get_recv_payload_type(session);
	RtpProfile *prof=rtp_session_get_profile(session);
	PayloadType *pt=rtp_profile_get_payload(prof,num);
	if (pt!=NULL){
		ctx->redraw(side);
	}else{
		LOGW("Receiving unknown payload type %i",num);
	}
}

void CallSide::onTelephoneEvent(RtpSession *s, int dtmf, void * data){
	CallContext *ctx=reinterpret_cast<CallContext*>(data);
	CallSide *side=static_cast<CallSide*>(rtp_session_get_data(s));
	LOGD("Receiving telephone event %c",dtmf);
	ctx->playTone(side,dtmf);
}

void CallSide::playTone(char tone_name){
	if (mSession && rtp_session_telephone_events_supported(mSession)!=-1) {
		LOGD("Sending dtmf signal %c",tone_name);
		ms_filter_call_method(mSender,MS_RTP_SEND_SEND_DTMF,&tone_name);
	} else 	if (mEncoder && mToneGen){
		const char *enc_fmt=mEncoder->desc->enc_fmt;
		if (strcasecmp(enc_fmt,"pcmu")==0 || strcasecmp(enc_fmt,"pcma")==0){
			LOGD("Modulating dtmf %c",tone_name);
			ms_filter_call_method(mToneGen,MS_DTMF_GEN_PUT,&tone_name);
		}
	} else {
		ms_warning("Cannot send tone [%i] because neither rfc2833 nor G711 codec selected",tone_name);
	}
}

void CallSide::doBgTasks(){
	if (mRtpEvq){
		OrtpEvent *ev=ortp_ev_queue_get(mRtpEvq);
		if (ev!=NULL){
			OrtpEventType evt=ortp_event_get_type(ev);
			if (evt==ORTP_EVENT_RTCP_PACKET_RECEIVED){
				if (mRc) ms_bitrate_controller_process_rtcp(mRc,ortp_event_get_data(ev)->packet);
			}
			ortp_event_destroy(ev);
		}
	}
}


CallContext::CallContext(sip_t *sip, const string &bind_address) : CallContextBase(sip), mFrontSide(0), mBackSide(0),mBindAddress(bind_address){
	mInitialOffer=NULL;
	mTicker=NULL;
	mInfoCSeq=-1;
	mCreateTime=time(NULL);
}

void CallContext::prepare( const CallContextParams &params){
	if (mFrontSide){
		if (isJoined())
			unjoin();
		delete mFrontSide;
		delete mBackSide;
	}
	if (mInitialOffer){
		ms_list_for_each(mInitialOffer,(void(*)(void*))payload_type_destroy);
		ms_list_free(mInitialOffer);
		mInitialOffer=NULL;
	}
	mFrontSide=new CallSide(this,params);
	mBackSide=new CallSide(this,params);
}

void CallContext::join(MSTicker *t){
	LOGD("Joining...");
	mFrontSide->connect(mBackSide);
	mBackSide->connect(mFrontSide);
	ms_ticker_attach(t,mFrontSide->getRecvPoint().filter);
	ms_ticker_attach(t,mBackSide->getRecvPoint().filter);
	mTicker=t;
	LOGD("Graphs now running");
}

void CallContext::unjoin(){
	LOGD("Unjoining...");
	ms_ticker_detach(mTicker,mFrontSide->getRecvPoint().filter);
	ms_ticker_detach(mTicker,mBackSide->getRecvPoint().filter);
	mFrontSide->disconnect(mBackSide);
	mBackSide->disconnect(mFrontSide);
	mTicker=NULL;
}

bool CallContext::isJoined()const{
	return mTicker!=NULL;
}

void CallContext::redraw(CallSide *r){
	LOGI("Redrawing in context of MSTicker");
	CallSide *s=(r==mFrontSide) ? mBackSide : mFrontSide;
	s->disconnect(r);
	s->connect(r,mTicker);
}

bool CallContext::isInactive(time_t cur){
	if (mFrontSide==NULL) {
		if (cur>mCreateTime+180){
			LOGD("CallContext %p usage timeout expired",this);
			return true;
		}else return false;
	}
	return !(mFrontSide->isActive(cur) || mBackSide->isActive(cur));
}

void CallContext::setInitialOffer(MSList *payloads){
	mInitialOffer=payloads;
}

const MSList *CallContext::getInitialOffer()const{
	return mInitialOffer;
}

void CallContext::dump(){
	CallContextBase::dump();
	if (mTicker!=NULL){
		LOGD("Front side:");
		mFrontSide->dump();
		LOGD("Back side:");
		mBackSide->dump();
	}else LOGD("is inactive");
}

void CallContext::playTone(sip_t *info){
	if (mFrontSide && mBackSide){
		if (mInfoCSeq==-1 || ((unsigned int)mInfoCSeq)!=info->sip_cseq->cs_seq){
			mInfoCSeq=info->sip_cseq->cs_seq;
			const char *p=strstr(info->sip_payload->pl_data,"Signal=");
			if (p){
				char dtmf;
				p+=strlen("Signal=");
				dtmf=p[0];
				if (dtmf!=0){
					LOGD("Intercepting dtmf in SIP info");
					getBackSide()->playTone(dtmf);
				}
			}
		}
	}else LOGW("Tone not played because graph is not ready.");
}

CallSide *CallContext::getOther(CallSide *cs){
	if (cs==mBackSide)
		return mFrontSide;
	else if (cs==mFrontSide)
		return mBackSide;
	else{
		LOGA("Big problem.");
		return NULL;
	}
}

void CallContext::playTone(CallSide *origin, const char dtmf){
	getOther(origin)->playTone (dtmf);
}

void CallContext::doBgTasks(){
	if (mFrontSide && mBackSide){
		mFrontSide->doBgTasks();
		mBackSide->doBgTasks();
	}
}

CallContext::~CallContext(){
	if (mTicker!=NULL)
		unjoin();
	if (mFrontSide) delete mFrontSide;
	if (mBackSide) delete mBackSide;
	if (mInitialOffer){
		ms_list_for_each(mInitialOffer,(void(*)(void*))payload_type_destroy);
		ms_list_free(mInitialOffer);
	}
}

