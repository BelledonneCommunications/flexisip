#ifndef transcodeagent_hh
#define transcodeagent_hh

#include "agent.hh"

#include <mediastreamer2/msfilter.h>
#include <mediastreamer2/msticker.h>
#include <mediastreamer2/msrtp.h>

class CallSide{
	public:
		CallSide();
		~CallSide();
		MSConnectionPoint getRecvPoint();
		PayloadType *getRecvFormat();
		void connect(CallSide *recvSide);
		void disconnect(CallSide *recvSide);
	private:
		RtpSession *mSession;
		PayloadType *getSendFormat();
		RtpSession *mRtpSession;
		MSFilter *mReceiver;
		MSFilter *mSender;
		MSFilter *mDecoder;
		MSFilter *mEncoder;
};

class CallContext{
	public:
		CallContext(Transaction *t);
		void join(MSTicker *ticker);
		void unjoin();
	private:
		Transaction *mTransaction;
		MSTicker *mTicker;
		CallSide mFrontSide;
		CallSide mBackSide;
		
};

class TranscodeAgent : public Agent{
	public:
		TranscodeAgent(su_root_t *root, const char *locaddr, int port);
		~TranscodeAgent();
		virtual int onRequest(msg_t *msg, sip_t *sip);
		virtual int onResponse(msg_t *msg, sip_t *sip);
	private:
		void processNewInvite(msg_t *msg, sip_t *sip);
		void process200Ok(Transaction *t, msg_t *msg, sip_t *sip);
		MSList *mSupportedAudioPayloads;
		MSTicker *mTicker;
};

#endif
