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

#ifndef callcontext_hh
#define callcontext_hh

#include "callstore.hh"


#include <mediastreamer2/msfilter.h>
#include <mediastreamer2/msticker.h>
#include <mediastreamer2/msrtp.h>
#include <mediastreamer2/bitratecontrol.h>

class CallContext;
class CallContextParams{
	public:
		int mJbNomSize;
};


class CallSide{
	public:
		CallSide(CallContext *ctx, const CallContextParams & params);
		~CallSide();
		MSConnectionPoint getRecvPoint();
		PayloadType *getRecvFormat();
		void enableRc(bool enabled);
		void connect(CallSide *recvSide, MSTicker *t=NULL);
		void disconnect(CallSide *recvSide);
		int getAudioPort();
		void setRemoteAddr(const char *addr, int port);
		void assignPayloads(const MSList *payloads);
		void setPtime(int ptime);
		void dump();
		void playTone(char tone_name);
		bool isActive(time_t cur);
		void doBgTasks();
	private:
		static void payloadTypeChanged(RtpSession *s, unsigned long data);
		static void onTelephoneEvent(RtpSession *s, int dtmf, void * user_data);
		CallContext *mCallCtx;
		RtpSession *mSession;
		RtpProfile *mProfile;
		PayloadType *getSendFormat();
		MSFilter *mReceiver;
		MSFilter *mSender;
		MSFilter *mDecoder;
		MSFilter *mEncoder;
		MSBitrateController *mRc;
		MSFilter *mToneGen;
		time_t mLastCheck;
		uint64_t mLastRecvCount;
		OrtpEvQueue *mRtpEvq;
		int mPtime;
		bool mRcEnabled;
		bool mUsePlc;
};



class CallContext : public CallContextBase{
	public:
		CallContext(sip_t *invite, const std::string &bind_address);
		void prepare(const CallContextParams & params);
		void join(MSTicker *ticker);
		void unjoin();
		bool isJoined()const;
		void redraw(CallSide *receiver);
		void setInitialOffer(MSList *payloads);
		const MSList *getInitialOffer()const;
		CallSide *getFrontSide(){
			return mFrontSide;
		}
		CallSide *getBackSide() {
			return mBackSide;
		}
		void playTone(sip_t *info);
		void playTone(CallSide *origin, char dtmf);
		~CallContext();
		void dump();
		void doBgTasks();
		virtual bool isInactive(time_t);
		const std::string &getBindAddress()const{
			return mBindAddress;
		}
	private:
		CallSide *getOther(CallSide *cs);
		MSTicker *mTicker;
		CallSide *mFrontSide;
		CallSide *mBackSide;
		MSList *mInitialOffer;
		int mInfoCSeq;
		std::string mBindAddress;
};


#endif

