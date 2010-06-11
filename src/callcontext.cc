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

#include "sdp-modifier.hh"

CallSide::CallSide(CallContext *ctx){
	mSession=rtp_session_new(RTP_SESSION_SENDRECV);
	mProfile=rtp_profile_new("Call profile");
	mEncoder=NULL;
	mDecoder=NULL;
	mReceiver=ms_filter_new(MS_RTP_RECV_ID);
	mSender=ms_filter_new(MS_RTP_SEND_ID);

	rtp_session_set_profile(mSession,mProfile);
	rtp_session_set_recv_buf_size(mSession,300);
	rtp_session_set_scheduling_mode(mSession,0);
	rtp_session_set_blocking_mode(mSession,0);
	rtp_session_enable_adaptive_jitter_compensation(mSession,TRUE);
	rtp_session_set_symmetric_rtp(mSession,TRUE);
	rtp_session_set_data(mSession,this);
	rtp_session_signal_connect(mSession,"payload_type_changed",(RtpCallback)&CallSide::payloadTypeChanged,
	                           reinterpret_cast<long>(ctx));
}

int CallSide::getAudioPort(){
	return rtp_session_get_local_port(mSession);
}

void  CallSide::setRemoteAddr(const char *addr, int port){
	rtp_session_set_remote_addr(mSession,addr,port);
}

void  CallSide::assignPayloads(const MSList *payloads){
	const MSList *elem;
	for (elem=payloads;elem!=NULL;elem=elem->next){
		PayloadType *pt=(PayloadType*)elem->data;
		rtp_profile_set_payload(mProfile, payload_type_get_number(pt),pt);
		if (payloads==elem){
			rtp_session_set_payload_type(mSession,payload_type_get_number(pt));
		}
	}
}

CallSide::~CallSide(){
	rtp_session_destroy(mSession);
	ms_filter_destroy(mReceiver);
	ms_filter_destroy(mSender);
	if (mEncoder)
		ms_filter_destroy(mEncoder);
	if (mSender)
		ms_filter_destroy(mDecoder);
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

void CallSide::connect(CallSide *recvSide){
	MSConnectionHelper h;
	PayloadType *recvpt;
	PayloadType *sendpt;

	recvpt=recvSide->getRecvFormat();
	sendpt=getSendFormat();
	ms_connection_helper_start(&h);
	ms_connection_helper_link(&h,recvSide->getRecvPoint().filter,-1,
	                          recvSide->getRecvPoint().pin);
	
	if (strcasecmp(recvpt->mime_type,sendpt->mime_type)!=0
	    && recvpt->clock_rate!=sendpt->clock_rate){
		mDecoder=ms_filter_create_decoder(recvpt->mime_type);
		mEncoder=ms_filter_create_encoder(sendpt->mime_type);
	}
	if (mDecoder)
		ms_connection_helper_link(&h,mDecoder,0,0);
	if (mEncoder)
		ms_connection_helper_link(&h,mEncoder,0,0);
	ms_connection_helper_link(&h,mSender,0,-1);
}

void CallSide::disconnect(CallSide *recvSide){
	MSConnectionHelper h;

	ms_connection_helper_start(&h);
	ms_connection_helper_unlink(&h,recvSide->getRecvPoint().filter,-1,
	                            	recvSide->getRecvPoint().pin);
	if (mDecoder)
		ms_connection_helper_unlink(&h,mDecoder,0,0);
	if (mEncoder)
		ms_connection_helper_unlink(&h,mEncoder,0,0);
	ms_connection_helper_unlink(&h,mSender,0,-1);
}

void CallSide::payloadTypeChanged(RtpSession *s, unsigned long data){
	CallContext *ctx=reinterpret_cast<CallContext*>(data);
	CallSide *side=static_cast<CallSide*>(rtp_session_get_data(s));
	ctx->redraw(side);
}

CallContext::CallContext(sip_t *sip) : CallContextBase(sip), mFrontSide(this), mBackSide(this){
	su_home_init(&mHome);
	mInitialOffer=NULL;
}

void CallContext::join(MSTicker *t){
	mFrontSide.connect(&mBackSide);
	mBackSide.connect(&mFrontSide);
	ms_ticker_attach(t,mFrontSide.getRecvPoint().filter);
	ms_ticker_attach(t,mBackSide.getRecvPoint().filter);
	mTicker=t;
}

void CallContext::unjoin(){
	ms_ticker_detach(mTicker,mFrontSide.getRecvPoint().filter);
	ms_ticker_detach(mTicker,mFrontSide.getRecvPoint().filter);
	mFrontSide.disconnect(&mBackSide);
	mBackSide.disconnect(&mFrontSide);
}

void CallContext::redraw(CallSide *r){
	LOGI("Redrawing in context of MSTicker");
	CallSide *s=(r==&mFrontSide) ? &mBackSide : &mFrontSide;
	s->disconnect(r);
	s->connect(r);
}

void CallContext::setInitialOffer(MSList *payloads){
	mInitialOffer=payloads;
}

const MSList *CallContext::getInitialOffer()const{
	return mInitialOffer;
}

CallContext::~CallContext(){
	su_home_deinit(&mHome);
	if (mInitialOffer){
		ms_list_for_each(mInitialOffer,(void(*)(void*))payload_type_destroy);
		ms_list_free(mInitialOffer);
	}
}

