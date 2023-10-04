/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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

#include "callcontext-transcoder.hh"
#include "flexisip-config.h"
#include "mediastreamer2/dtmfgen.h"
#include "ortp/telephonyevents.h"

#include "sdp-modifier.hh"

using namespace std;
using namespace flexisip;

static void rtpSessionResync(RtpSession* session, void*, void*, void*) {
	rtp_session_resync(session);
}

CallSide::CallSide(TranscodedCall* ctx, const CallContextParams& params) : mCallCtx(ctx) {
	MSFactory* factory = ctx->getFactory();
	mSession = rtp_session_new(RTP_SESSION_SENDRECV);
#if ORTP_HAS_REUSEADDR
	rtp_session_set_reuseaddr(mSession, FALSE);
#endif
	mProfile = rtp_profile_new("Call profile");
	mEncoder = NULL;
	mDecoder = NULL;
	mRc = NULL;
	mReceiver = ms_factory_create_filter(factory, MS_RTP_RECV_ID);
	mSender = ms_factory_create_filter(factory, MS_RTP_SEND_ID);
	mToneGen = ms_factory_create_filter(factory, MS_DTMF_GEN_ID);

	rtp_session_set_profile(mSession, mProfile);
	rtp_session_set_recv_buf_size(mSession, 300);
	rtp_session_set_scheduling_mode(mSession, 0);
	rtp_session_set_blocking_mode(mSession, 0);
	/*  no jitter buffer: we are just doing packet processing*/
	mUsePlc = params.mJbNomSize == 0 ? false : true;
	JBParameters jbpar;
	rtp_session_get_jitter_buffer_params(mSession, &jbpar);
	jbpar.min_size = jbpar.nom_size = params.mJbNomSize;
	jbpar.max_size = 200;
	jbpar.adaptive = true;
	jbpar.max_packets = 100;
	rtp_session_enable_jitter_buffer(mSession, params.mJbNomSize == 0 ? FALSE : TRUE);
	rtp_session_set_jitter_buffer_params(mSession, &jbpar);
	LOGD("Jitter buffer nominal size: %d", params.mJbNomSize);
	rtp_session_set_symmetric_rtp(mSession, TRUE);
	rtp_session_set_data(mSession, this);
	rtp_session_signal_connect(mSession, "payload_type_changed", &CallSide::payloadTypeChanged,
	                           reinterpret_cast<void*>(ctx));
	rtp_session_signal_connect(mSession, "timestamp_jump", rtpSessionResync, nullptr);
	rtp_session_signal_connect(mSession, "ssrc_changed", rtpSessionResync, nullptr);
	rtp_session_signal_connect(mSession, "telephone-event", &CallSide::onTelephoneEvent, reinterpret_cast<void*>(ctx));
	mRtpEvq = NULL;
	mLastCheck = 0;
	mLastRecvCount = 0;
	mPtime = 0;
	mRcEnabled = false;
	mLocalAddress = "0.0.0.0";
}

void CallSide::enableRc(bool enabled) {
	mRcEnabled = enabled;
}

const string& CallSide::getLocalAddress() {
	return mLocalAddress;
}

int CallSide::getAudioPort() {
	int port = rtp_session_get_local_port(mSession);
	if (port == -1) {
		/*request oRTP to bind randomly*/
		mLocalAddress = mCallCtx->getBindAddress();
#if ORTP_ABI_VERSION >= 9
		rtp_session_set_local_addr(mSession, mLocalAddress.c_str(), -1, -1);
#else
		rtp_session_set_local_addr(mSession, mLocalAddress.c_str(), -1);
#endif
		port = rtp_session_get_local_port(mSession);
	}
	return port;
}

void CallSide::setRemoteAddr(const char* addr, int port) {
	rtp_session_set_remote_addr(mSession, addr, port);
}

void CallSide::setPtime(int ptime) {
	mPtime = ptime;
}

void CallSide::assignPayloads(std::list<PayloadType*>& payloads) {
	bool first = true;
	for (auto elem = payloads.cbegin(); elem != payloads.cend(); ++elem) {
		PayloadType* pt = *elem;
		PayloadType* oldpt = rtp_profile_get_payload(mProfile, payload_type_get_number(pt));
		if (oldpt) {
			payload_type_destroy(oldpt);
		}
		rtp_profile_set_payload(mProfile, payload_type_get_number(pt), pt);
		if (first) {
			rtp_session_set_payload_type(mSession, payload_type_get_number(pt));
			first = false;
		}
		if (strcmp("telephone-event", pt->mime_type) == 0) {
			rtp_session_telephone_events_supported(mSession);
		}
	}
	ms_filter_call_method(mReceiver, MS_RTP_RECV_SET_SESSION, mSession);
	ms_filter_call_method(mSender, MS_RTP_SEND_SET_SESSION, mSession);
}

CallSide::~CallSide() {
	if (mRtpEvq) {
		ortp_ev_queue_destroy(mRtpEvq);
		rtp_session_unregister_event_queue(mSession, mRtpEvq);
	}
	rtp_session_destroy(mSession);
	rtp_profile_destroy(mProfile);

	ms_filter_destroy(mReceiver);
	ms_filter_destroy(mSender);
	ms_filter_destroy(mToneGen);
	if (mEncoder) ms_filter_destroy(mEncoder);
	if (mDecoder) ms_filter_destroy(mDecoder);
	if (mRc) ms_bitrate_controller_destroy(mRc);
}

void CallSide::dump() {
	const rtp_stats_t* stats = rtp_session_get_stats(mSession);
	rtp_stats_display(stats, "RTP Statistics:");
}

time_t CallSide::getLastActivity() {
	const rtp_stats_t* stats = rtp_session_get_stats(mSession);
	if (mLastCheck == 0) {
		mLastCheck = getCurrentTime();
		mLastRecvCount = stats->recv;
	} else {
		if (stats->recv != mLastRecvCount) {
			mLastRecvCount = stats->recv;
			mLastCheck = getCurrentTime();
		}
	}
	return mLastCheck;
}

PayloadType* CallSide::getSendFormat() {
	int pt = rtp_session_get_send_payload_type(mSession);
	RtpProfile* prof = rtp_session_get_send_profile(mSession);
	return rtp_profile_get_payload(prof, pt);
}

MSConnectionPoint CallSide::getRecvPoint() {
	MSConnectionPoint ret;
	ret.filter = mReceiver;
	ret.pin = 0;
	return ret;
}

PayloadType* CallSide::getRecvFormat() {
	int pt = rtp_session_get_recv_payload_type(mSession);
	RtpProfile* prof = rtp_session_get_recv_profile(mSession);
	return rtp_profile_get_payload(prof, pt);
}

void CallSide::connect(CallSide* recvSide, MSTicker* ticker) {
	MSFactory* factory = mCallCtx->getFactory();
	MSConnectionHelper conHelper;
	PayloadType* recvpt;
	PayloadType* sendpt;

	recvpt = recvSide->getRecvFormat();
	sendpt = getSendFormat();
	ms_connection_helper_start(&conHelper);
	ms_connection_helper_link(&conHelper, recvSide->getRecvPoint().filter, -1, recvSide->getRecvPoint().pin);

	LOGD("recvside (%p) enc=%i %s/%i sendside (%p) enc=%i %s/%i", recvSide, payload_type_get_number(recvpt),
	     recvpt->mime_type, recvpt->clock_rate, this, payload_type_get_number(sendpt), sendpt->mime_type,
	     sendpt->clock_rate);
	if (strcasecmp(recvpt->mime_type, sendpt->mime_type) != 0 || recvpt->clock_rate != sendpt->clock_rate ||
	    mToneGen != 0) {

		LOGD("Will instanciate new codecs");
		if (mDecoder) {
			if (ticker) ms_filter_postprocess(mDecoder);
			ms_filter_destroy(mDecoder);
		}
		rtp_session_flush_sockets(mSession);

		mDecoder = ms_factory_create_decoder(factory, recvpt->mime_type);
		if (mDecoder == NULL) {
			LOGE("Could not instanciate decoder for %s", recvpt->mime_type);
		} else {
			if (!mUsePlc) ms_filter_call_method(mDecoder, MS_FILTER_ADD_FMTP, (void*)"plc=0");
			if (recvpt->clock_rate > 0)
				ms_filter_call_method(mDecoder, MS_FILTER_SET_SAMPLE_RATE, (void*)&recvpt->clock_rate);
			if (ticker) ms_filter_preprocess(mDecoder, ticker);
		}
		if (mEncoder) {
			if (ticker) ms_filter_postprocess(mEncoder);
			ms_filter_destroy(mEncoder);
			if (mRc) {
				ms_bitrate_controller_destroy(mRc);
				mRc = NULL;
			}
		}
		mEncoder = ms_factory_create_encoder(factory, sendpt->mime_type);
		if (mEncoder == NULL) {
			LOGE("Could not instanciate encoder for %s", sendpt->mime_type);
		} else {
			if (mPtime > 0) {
				char tmp[20];
				snprintf(tmp, sizeof(tmp), "ptime=%i", mPtime);
				ms_filter_call_method(mEncoder, MS_FILTER_ADD_FMTP, (void*)tmp);
			}
			if (sendpt->clock_rate > 0)
				ms_filter_call_method(mEncoder, MS_FILTER_SET_SAMPLE_RATE, (void*)&sendpt->clock_rate);
			if (sendpt->send_fmtp != NULL)
				ms_filter_call_method(mEncoder, MS_FILTER_ADD_FMTP, (void*)sendpt->send_fmtp);
			if (sendpt->normal_bitrate > 0)
				ms_filter_call_method(mEncoder, MS_FILTER_SET_BITRATE, (void*)&sendpt->normal_bitrate);
			if (ticker) ms_filter_preprocess(mEncoder, ticker);
		}
	}

	if (mDecoder) ms_connection_helper_link(&conHelper, mDecoder, 0, 0);
	if (mToneGen) ms_connection_helper_link(&conHelper, mToneGen, 0, 0);
	if (mEncoder) ms_connection_helper_link(&conHelper, mEncoder, 0, 0);
	ms_connection_helper_link(&conHelper, mSender, 0, -1);
	if (mRcEnabled && mRc == NULL && mEncoder) {
		if (mRtpEvq == NULL) {
			mRtpEvq = ortp_ev_queue_new();
			rtp_session_register_event_queue(mSession, mRtpEvq);
		}
		mRc = ms_audio_bitrate_controller_new(mSession, mEncoder, 0);
	}
}

void CallSide::disconnect(CallSide* recvSide) {
	MSConnectionHelper h;

	ms_connection_helper_start(&h);
	ms_connection_helper_unlink(&h, recvSide->getRecvPoint().filter, -1, recvSide->getRecvPoint().pin);
	if (mDecoder) ms_connection_helper_unlink(&h, mDecoder, 0, 0);
	if (mToneGen) ms_connection_helper_unlink(&h, mToneGen, 0, 0);
	if (mEncoder) ms_connection_helper_unlink(&h, mEncoder, 0, 0);
	ms_connection_helper_unlink(&h, mSender, 0, -1);
}

void CallSide::payloadTypeChanged(RtpSession* session, void* data, void*, void*) {
	TranscodedCall* ctx = static_cast<TranscodedCall*>(data);
	CallSide* side = static_cast<CallSide*>(rtp_session_get_data(session));
	int num = rtp_session_get_recv_payload_type(session);
	RtpProfile* prof = rtp_session_get_profile(session);
	PayloadType* pt = rtp_profile_get_payload(prof, num);
	if (pt != NULL) {
		ctx->redraw(side);
	} else {
		LOGW("Receiving unknown payload type %i", num);
	}
}

void CallSide::onTelephoneEvent(RtpSession* s, void* dtmfIndex, void* userData, void*) {
	static constexpr int dtmfs[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8',
	                                '9', '*', '#', 'A', 'B', 'C', 'D', '!'};
	TranscodedCall* ctx = static_cast<TranscodedCall*>(userData);
	CallSide* side = static_cast<CallSide*>(rtp_session_get_data(s));

	const uintptr_t i = reinterpret_cast<intptr_t>(dtmfIndex);
	if (i > sizeof dtmfs / sizeof dtmfs[0]) {
		SLOGE << "Unsupported telephone-event type: " << i;
		return;
	}

	const int dtmf = dtmfs[i];
	SLOGD << "Receiving telephone event: " << dtmf;
	ctx->playTone(side, dtmf);
}

void CallSide::playTone(char tone_name) {
	if (mSession && rtp_session_telephone_events_supported(mSession) != -1) {
		LOGD("Sending dtmf signal %c", tone_name);
		ms_filter_call_method(mSender, MS_RTP_SEND_SEND_DTMF, &tone_name);
	} else if (mEncoder && mToneGen) {
		const char* enc_fmt = mEncoder->desc->enc_fmt;
		if (strcasecmp(enc_fmt, "pcmu") == 0 || strcasecmp(enc_fmt, "pcma") == 0) {
			LOGD("Modulating dtmf %c", tone_name);
			ms_filter_call_method(mToneGen, MS_DTMF_GEN_PUT, &tone_name);
		} else {
			ms_warning("Cannot send tone [%i] because selected codec is not G711", tone_name);
		}
	} else {
		ms_warning("Cannot send tone [%i] because neither rfc2833 nor G711 codec selected", tone_name);
	}
}

void CallSide::doBgTasks() {
	if (mRtpEvq) {
		OrtpEvent* ev = ortp_ev_queue_get(mRtpEvq);
		if (ev != NULL) {
			OrtpEventType evt = ortp_event_get_type(ev);
			if (evt == ORTP_EVENT_RTCP_PACKET_RECEIVED) {
				if (mRc) ms_bitrate_controller_process_rtcp(mRc, ortp_event_get_data(ev)->packet);
			}
			ortp_event_destroy(ev);
		}
	}
}

TranscodedCall::TranscodedCall(MSFactory* factory, sip_t* sip, const string& bind_address)
    : CallContextBase(sip), mFactory(factory), mFrontSide(0), mBackSide(0), mInitialOffer(),
      mBindAddress(bind_address) {
	mTicker = NULL;
	mInfoCSeq = -1;
	mCreateTime = getCurrentTime();
}

void TranscodedCall::prepare(const CallContextParams& params) {
	LOGD("Preparing...");
	if (mFrontSide) {
		LOGD("Call sides used to be front=%p back=%p", mFrontSide, mBackSide);
		if (isJoined()) unjoin();
		delete mFrontSide;
		delete mBackSide;
	}
	if (!mInitialOffer.empty()) {
		for (auto it = mInitialOffer.begin(); it != mInitialOffer.cend(); ++it) {
			payload_type_destroy(*it);
		}
		mInitialOffer.clear();
	}
	mFrontSide = new CallSide(this, params);
	mBackSide = new CallSide(this, params);
	LOGD("Call sides are now front=%p back=%p", mFrontSide, mBackSide);
}

void TranscodedCall::join(MSTicker* t) {
	LOGD("Joining...");
	mFrontSide->connect(mBackSide);
	mBackSide->connect(mFrontSide);
	ms_ticker_attach(t, mFrontSide->getRecvPoint().filter);
	ms_ticker_attach(t, mBackSide->getRecvPoint().filter);
	mTicker = t;
	LOGD("Graphs now running");
}

void TranscodedCall::unjoin() {
	LOGD("Unjoining...");
	ms_ticker_detach(mTicker, mFrontSide->getRecvPoint().filter);
	ms_ticker_detach(mTicker, mBackSide->getRecvPoint().filter);
	mFrontSide->disconnect(mBackSide);
	mBackSide->disconnect(mFrontSide);
	mTicker = NULL;
}

bool TranscodedCall::isJoined() const {
	return mTicker != NULL;
}

void TranscodedCall::redraw(CallSide* r) {
	LOGI("Redrawing in context of MSTicker");
	CallSide* s = (r == mFrontSide) ? mBackSide : mFrontSide;
	s->disconnect(r);
	s->connect(r, mTicker);
}

time_t TranscodedCall::getLastActivity() {
	if (mFrontSide == NULL) {
		return CallContextBase::getLastActivity();
	}
	return MAX(mFrontSide->getLastActivity(), mBackSide->getLastActivity());
}

void TranscodedCall::setInitialOffer(std::list<PayloadType*>& payloads) {
	mInitialOffer = payloads;
}

const std::list<PayloadType*>& TranscodedCall::getInitialOffer() const {
	return mInitialOffer;
}

void TranscodedCall::dump() {
	CallContextBase::dump();
	if (mTicker != NULL) {
		LOGD("Front side %p: %i", mFrontSide, mFrontSide->getAudioPort());
		mFrontSide->dump();
		LOGD("Back side %p: %i", mBackSide, mBackSide->getAudioPort());
		mBackSide->dump();
	} else LOGD("is inactive");
}

void TranscodedCall::playTone(sip_t* info) {
	if (mFrontSide && mBackSide) {
		if (mInfoCSeq == -1 || ((unsigned int)mInfoCSeq) != info->sip_cseq->cs_seq) {
			mInfoCSeq = info->sip_cseq->cs_seq;
			const char* p = strstr(info->sip_payload->pl_data, "Signal=");
			if (p) {
				char dtmf;
				p += strlen("Signal=");
				dtmf = p[0];
				if (dtmf != 0) {
					LOGD("Intercepting dtmf in SIP info");
					mBackSide->playTone(dtmf);
				}
			}
		}
	} else LOGW("Tone not played because graph is not ready.");
}

CallSide* TranscodedCall::getOther(CallSide* cs) {
	if (cs == mBackSide) return mFrontSide;
	else if (cs == mFrontSide) return mBackSide;
	else {
		LOGA("Big problem.");
		return NULL;
	}
}

void TranscodedCall::playTone(CallSide* origin, const char dtmf) {
	getOther(origin)->playTone(dtmf);
}

void TranscodedCall::doBgTasks() {
	if (mFrontSide && mBackSide) {
		mFrontSide->doBgTasks();
		mBackSide->doBgTasks();
	}
}

TranscodedCall::~TranscodedCall() {
	if (mTicker != NULL) unjoin();
	if (mFrontSide) delete mFrontSide;
	if (mBackSide) delete mBackSide;
	if (!mInitialOffer.empty()) {
		for (auto it = mInitialOffer.begin(); it != mInitialOffer.cend(); ++it) {
			payload_type_destroy(*it);
		}
		mInitialOffer.clear();
	}
}
