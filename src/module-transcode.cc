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

#include "module.hh"
#include "agent.hh"
#include "callcontext-transcoder.hh"
#include "sdp-modifier.hh"

#include <vector>
#include <functional>
#include <algorithm>

using namespace ::std;

class TickerManager {
public:
	TickerManager() {
		mStarted = false;
	}
	MSTicker *chooseOne() {
		if (!mStarted) {
			int cpucount = getCpuCount();
			mLastTickerIndex = 0;
			for (int i = 0; i < cpucount; ++i) {
				mTickers.push_back(ms_ticker_new());
			}
			mStarted = true;
		}
		if (mLastTickerIndex >= mTickers.size())
			mLastTickerIndex = 0;
		return mTickers[mLastTickerIndex++];

	}
	~TickerManager() {
		for_each(mTickers.begin(), mTickers.end(), ptr_fun(ms_ticker_destroy));
	}
private:
	int getCpuCount() {
		char line[256] = { 0 };
		int count = 0;
		FILE *f = fopen("/proc/cpuinfo", "r");
		if (f != NULL) {
			while (fgets(line, sizeof(line), f)) {
				if (strstr(line, "processor") == line)
					count++;
			}
			LOGI("Found %i processors", count);
			fclose(f);
		} else
			count = 1;
		return count;
	}
	vector<MSTicker*> mTickers;
	unsigned int mLastTickerIndex;
	bool mStarted;
};

class TranscodeModule: public Module, protected ModuleToolbox {
public:
	TranscodeModule(Agent *ag);
	~TranscodeModule();
	virtual void onLoad(const GenericStruct *module_config);
	virtual void onRequest(shared_ptr<RequestSipEvent> &ev);
	virtual void onResponse(shared_ptr<ResponseSipEvent> &ev);
	virtual void onIdle();
	virtual void onDeclare(GenericStruct *mc);
private:
	TickerManager mTickerManager;
	int handleOffer(TranscodedCall *c, shared_ptr<SipEvent> &&ev);
	int handleAnswer(TranscodedCall *c, shared_ptr<SipEvent> &&ev);
	int processNewInvite(TranscodedCall *c, shared_ptr<RequestSipEvent> &ev);
	void process200OkforInvite(TranscodedCall *ctx, shared_ptr<ResponseSipEvent> &ev);
	void processNewAck(TranscodedCall *ctx, shared_ptr<RequestSipEvent> &ev);
	bool processSipInfo(TranscodedCall *c, shared_ptr<RequestSipEvent> &ev);
	void onTimer();
	static void sOnTimer(void *unused, su_timer_t *t, void *zis);
	bool canDoRateControl(sip_t *sip);
	bool isOneCodecSupported(const MSList *ioffer);
	MSList *normalizePayloads(MSList *l);
	MSList *orderList(const list<string> &config, const MSList *l);
	MSList *mSupportedAudioPayloads;
	CallStore mCalls;
	su_timer_t *mTimer;
	list<string> mRcUserAgents;
	CallContextParams mCallParams;
	bool mBlockRetrans;
	static ModuleInfo<TranscodeModule> sInfo;
};

ModuleInfo<TranscodeModule> TranscodeModule::sInfo("Transcoder", "The purpose of the Transcoder module is to transparently transcode from one audio codec to another to make "
		"the communication possible between clients that do not share the same set of supported codecs. "
		"Concretely it adds all missing codecs into the INVITEs it receives, and adds codecs matching the original INVITE into the 200Ok. "
		"Rtp ports and addresses are masqueraded so that the streams can be processed by the proxy. "
		"The transcoding job is done in the background by the mediastreamer2 library, as consequence the set of "
		"supported codecs is exactly the the same as the codec set supported by mediastreamer2, including "
		"the possible plugins you may installed to extend mediastreamer2. "
		"WARNING: this module can conflict with the MediaRelay module as both are changin the SDP. "
		"Make sure to configure them with different to-domains or from-domains filter if you want to enable both of them.",
		ModuleInfoBase::ModuleOid::Transcoder);

static MSList *makeSupportedAudioPayloadList() {
	/* in mediastreamer2, we use normal_bitrate as an IP bitrate, not codec bitrate*/
	payload_type_speex_nb.normal_bitrate = 32000;
	payload_type_speex_wb.normal_bitrate = 42000;
	payload_type_speex_nb.recv_fmtp = ms_strdup("vbr=on");
	payload_type_amr.recv_fmtp = ms_strdup("octet-align=1");

	payload_type_set_number(&payload_type_pcmu8000, 0);
	payload_type_set_number(&payload_type_pcma8000, 8);
	payload_type_set_number(&payload_type_gsm, 3);
	payload_type_set_number(&payload_type_speex_nb, -1);
	payload_type_set_number(&payload_type_speex_wb, -1);
	payload_type_set_number(&payload_type_amr, -1);
	payload_type_set_number(&payload_type_amrwb, -1);
	payload_type_set_number(&payload_type_ilbc, -1);
	payload_type_set_number(&payload_type_silk_nb, -1);
	payload_type_set_number(&payload_type_silk_mb, -1);
	payload_type_set_number(&payload_type_silk_wb, -1);
	payload_type_set_number(&payload_type_silk_swb, -1);
	payload_type_set_number(&payload_type_telephone_event, -1);
	MSList *l = NULL;
	l = ms_list_append(l, &payload_type_speex_nb);
	l = ms_list_append(l, &payload_type_ilbc);
	l = ms_list_append(l, &payload_type_amr);
	l = ms_list_append(l, &payload_type_amrwb);
	l = ms_list_append(l, &payload_type_gsm);
	l = ms_list_append(l, &payload_type_pcmu8000);
	l = ms_list_append(l, &payload_type_pcma8000);
	l = ms_list_append(l, &payload_type_telephone_event);
	l = ms_list_append(l,&payload_type_silk_nb);
	l = ms_list_append(l,&payload_type_silk_mb);
	l = ms_list_append(l,&payload_type_silk_wb);
	l = ms_list_append(l,&payload_type_silk_swb);


	return l;
}

bool TranscodeModule::isOneCodecSupported(const MSList *ioffer) {
	const MSList *e1, *e2;
	for (e1 = ioffer; e1 != NULL; e1 = e1->next) {
		PayloadType *p1 = (PayloadType*) e1->data;
		for (e2 = mSupportedAudioPayloads; e2 != NULL; e2 = e2->next) {
			PayloadType *p2 = (PayloadType*) e2->data;
			if (strcasecmp(p1->mime_type, p2->mime_type) == 0 && p1->clock_rate == p2->clock_rate)
				return true;
		}
	}
	return false;
}

TranscodeModule::TranscodeModule(Agent *ag) :
		Module(ag), mTimer(0) {
	mSupportedAudioPayloads = NULL;
}

TranscodeModule::~TranscodeModule() {
	if (mTimer)
		getAgent()->stopTimer(mTimer);
	ms_list_free(mSupportedAudioPayloads);
}

void TranscodeModule::onDeclare(GenericStruct *mc) {
	/*we need to be disabled by default*/
	mc->get<ConfigBoolean>("enabled")->setDefault("false");
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
	mc->addChildrenValues(items);

	auto p=mc->createStatPair("count-calls", "Number of transcoded calls.");
	mCalls.setCallStatCounters(p.first, p.second);
}

MSList *TranscodeModule::orderList(const list<string> &config, const MSList *l) {
	int err;
	int rate;
	MSList *ret = NULL;
	const MSList *it;
	list<string>::const_iterator cfg_it;

	for (cfg_it = config.begin(); cfg_it != config.end(); ++cfg_it) {
		char name[(*cfg_it).size() + 1];
		char *p;

		strcpy(name, (*cfg_it).c_str());
		p = strchr(name, '/');
		if (p) {
			*p = '\0';
			p++;
		} else
			LOGF("Error parsing audio codec list");

		err = sscanf(p, "%i", &rate);
		if (err != 1)
			LOGF("Error parsing audio codec list, missing rate information");
		for (it = l; it != NULL; it = it->next) {
			PayloadType *pt = (PayloadType*) it->data;
			if (strcasecmp(pt->mime_type, name) == 0 && rate == pt->clock_rate) {
				if (ms_filter_get_encoder(pt->mime_type) != NULL || strcmp("telephone-event", pt->mime_type) == 0) {
					ret = ms_list_append(ret, pt);
				} else {
					LOGE("Codec %s/%i is configured but is not supported (missing plugin ?)", name, rate);
				}
			}
		}
	}
	return ret;
}

void TranscodeModule::onLoad(const GenericStruct *module_config){
	mTimer=mAgent->createTimer(20,&sOnTimer,this);
	mCallParams.mJbNomSize=module_config->get<ConfigInt>("jb-nom-size")->read();
	mRcUserAgents=module_config->get<ConfigStringList>("rc-user-agents")->read();
	MSList *l=makeSupportedAudioPayloadList();
	mSupportedAudioPayloads=orderList(module_config->get<ConfigStringList>("audio-codecs")->read(),l);
	mBlockRetrans=module_config->get<ConfigBoolean>("block-retransmissions")->read();
	ms_list_free(l);
}

void TranscodeModule::onIdle() {
	mCalls.dump();
	mCalls.removeAndDeleteInactives();
}

bool TranscodeModule::canDoRateControl(sip_t *sip) {
	if (sip->sip_user_agent != NULL && sip->sip_user_agent->g_string != NULL) {
		list<string>::const_iterator it;
		for (it = mRcUserAgents.begin(); it != mRcUserAgents.end(); ++it) {
			if (strstr(sip->sip_user_agent->g_string, (*it).c_str())) {
				LOGD("Audio rate control supported for %s", sip->sip_user_agent->g_string);
				return true;
			}
		}
	}
	return false;
}

bool TranscodeModule::processSipInfo(TranscodedCall *c, shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
	sip_payload_t *payload = sip->sip_payload;
	if (payload != NULL && payload->pl_data != NULL) {
		if (sip->sip_content_type != NULL && strcasecmp(sip->sip_content_type->c_subtype, "dtmf-relay") == 0) {
			c->playTone(sip);
			ev->reply(ms, 200, NULL, TAG_END());
			return true;
		}
	}
	return false;
}

static const PayloadType *findPt(const MSList *l, const char *mime, int rate) {
	for (; l != NULL; l = l->next) {
		const PayloadType *pt = (PayloadType*) l->data;
		if (pt->clock_rate == rate && strcasecmp(mime, pt->mime_type) == 0)
			return pt;
	}
	return NULL;
}

MSList *TranscodeModule::normalizePayloads(MSList *l) {
	MSList *it;
	for (it = l; it != NULL; it = it->next) {
		PayloadType *pt = (PayloadType*) l->data;
		if (pt->normal_bitrate == 0) {
			const PayloadType *refpt = findPt(mSupportedAudioPayloads, pt->mime_type, pt->clock_rate);
			if (refpt && refpt->normal_bitrate > 0) {
				ms_message("Using %s at bitrate %i", pt->mime_type, refpt->normal_bitrate);
				pt->normal_bitrate = refpt->normal_bitrate;
			}
		}
	}
	return l;
}

int TranscodeModule::handleOffer(TranscodedCall *c, shared_ptr<SipEvent> &&ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	msg_t *msg = ms->getMsg();
	sip_t *sip = ms->getSip();
	SdpModifier *m = SdpModifier::createFromSipMsg(c->getHome(), ms->getSip());

	if (m == NULL)
		return -1;

	MSList *ioffer = m->readPayloads();

	if (isOneCodecSupported(ioffer)) {
		string addr;
		int frport;
		c->prepare(mCallParams);
		c->setInitialOffer(ioffer);

		/*forces the front side to bind and allocate a port immediately on the bind-address supplied in the config*/
		m->getAudioIpPort(&addr, &frport);
		c->getFrontSide()->setRemoteAddr(addr.c_str(), frport);
		int flport= c->getFrontSide()->getAudioPort(); //assign port
		LOGD("Front side %s:%i <-> local:%i", addr.c_str(), frport, flport);

		int ptime = m->readPtime();
		if (ptime > 0) {
			c->getFrontSide()->setPtime(ptime);
			m->setPtime(0); //remove the ptime attribute
		}

		int blport = c->getBackSide()->getAudioPort();
		const char *publicIp=getAgent()->getPublicIp().c_str();
		m->changeAudioIpPort(publicIp, blport);
		LOGD("Back side local port: %s:%i <-> ?", publicIp, blport);

		m->replacePayloads(mSupportedAudioPayloads, c->getInitialOffer());
		m->update(msg, sip);

		if (canDoRateControl(sip)) {
			c->getFrontSide()->enableRc(true);
		}
		delete m;
		return 0;
	} else {
		LOGW("No support for any of the codec offered by client, doing bypass.");
		ms_list_for_each(ioffer, (void(*)(void*))payload_type_destroy);ms_list_free
		(ioffer);
	}
	delete m;
	return -1;
}

int TranscodeModule::processNewInvite(TranscodedCall *c, shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	int ret = 0;
	if (SdpModifier::hasSdp(ms->getSip())) {
		ret = handleOffer(c, ev);
	}
	if (ret == 0) {
		//be in the record-route
		addRecordRouteIncoming(c->getHome(), getAgent(), ev);
		c->storeNewInvite(ms->getMsg());
	} else {
		ev->reply(ms, 415, "Unsupported codecs", TAG_END());
	}
	return ret;
}

void TranscodeModule::processNewAck(TranscodedCall *ctx, shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	LOGD("Processing ACK");
	const MSList *ioffer = ctx->getInitialOffer();
	if (ioffer == NULL) {
		LOGE("Processing ACK with SDP but no offer was made or processed.");
	} else {
		handleAnswer(ctx, ev);
		ctx->storeNewAck(ms->getMsg());
	}
}

void TranscodeModule::onRequest(shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	shared_ptr<TranscodedCall> c;
	msg_t *msg = ms->getMsg();
	sip_t *sip = ms->getSip();

	if (sip->sip_request->rq_method == sip_method_invite) {
		if ((c = dynamic_pointer_cast<TranscodedCall>(mCalls.find(getAgent(), sip))) == NULL) {
			c = make_shared<TranscodedCall>(sip, getAgent()->getBindIp());
			mCalls.store(c);
			processNewInvite(c.get(), ev);
		} else {
			if (c->isNewInvite(sip)) {
				processNewInvite(c.get(), ev);
			} else if (mAgent->countUsInVia(sip->sip_via)) {
				LOGD("We are already in VIA headers of this request");
				return;
			} else if (c->getLastForwardedInvite() != NULL) {
				if (!mBlockRetrans) {
					LOGD("This is an invite retransmission.");
					msg = msg_copy(c->getLastForwardedInvite());
					sip = (sip_t*) msg_object(msg);
				} else {
					LOGD("Retransmission ignored.");
					ev->suspendProcessing();
				}
			}
		}
	} else if (sip->sip_request->rq_method == sip_method_ack && SdpModifier::hasSdp(sip)) {
		if ((c = dynamic_pointer_cast<TranscodedCall>(mCalls.find(getAgent(), sip))) == NULL) {
			LOGD("Seeing ACK with no call reference");
		} else {
			if (c->isNewAck(sip)) {
				processNewAck(c.get(), ev);
			} else if (mAgent->countUsInVia(sip->sip_via)) {
				LOGD("We are already in VIA headers of this request");
				return;
			} else if (c->getLastForwardedAck() != NULL) {
				msg = msg_copy(c->getLastForwardedAck());
				sip = (sip_t*) msg_object(msg);
				LOGD("Forwarding ack retransmission");
			}
		}
	} else {
		if (sip->sip_request->rq_method == sip_method_info) {
			if ((c = dynamic_pointer_cast<TranscodedCall>(mCalls.find(getAgent(), sip))) != NULL) {
				if (processSipInfo(c.get(), ev)) {
					/*stop the processing */
					return;
				}
			}
		}
		//all other requests go through

		if (sip->sip_request->rq_method == sip_method_bye) {
			if ((c = dynamic_pointer_cast<TranscodedCall>(mCalls.find(getAgent(), sip))) != NULL) {
				mCalls.remove(c);
			}
		}
	}

	ev->setMsgSip(make_shared<MsgSip>(*ms,msg));
}

int TranscodeModule::handleAnswer(TranscodedCall *ctx, shared_ptr<SipEvent> &&ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	string addr;
	int port;
	SdpModifier *m = SdpModifier::createFromSipMsg(ctx->getHome(), ms->getSip());
	int ptime;

	if (m == NULL)
		return -1;
	if (ctx->isJoined())
		ctx->unjoin();

	m->getAudioIpPort(&addr, &port);
	ptime = m->readPtime();
	LOGD("Backside remote address: %s:%i", addr.c_str(), port);
	ctx->getBackSide()->setRemoteAddr(addr.c_str(), port);
	if (ptime > 0) {
		ctx->getBackSide()->setPtime(ptime);
		m->setPtime(0); //remove the ptime attribute
	}
	m->changeAudioIpPort(getAgent()->getPublicIp().c_str(), ctx->getFrontSide()->getAudioPort());

	MSList *answer = m->readPayloads();
	if (answer == NULL) {
		LOGE("No payloads in 200Ok");
		delete m;
		return -1;
	}
	ctx->getBackSide()->assignPayloads(normalizePayloads(answer));
	ms_list_free(answer);

	const MSList *ioffer = ctx->getInitialOffer();
	MSList *common = SdpModifier::findCommon(mSupportedAudioPayloads, ioffer, false);
	if (common != NULL) {
		m->replacePayloads(common, NULL);
	}
	m->update(ms->getMsg(), ms->getSip());

	ctx->getFrontSide()->assignPayloads(normalizePayloads(common));

	if (canDoRateControl(ms->getSip())) {
		ctx->getBackSide()->enableRc(true);
	}

	ctx->join(mTickerManager.chooseOne());
	delete m;
	return 0;
}

void TranscodeModule::process200OkforInvite(TranscodedCall *ctx, shared_ptr<ResponseSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	LOGD("Processing 200 Ok");
	if (SdpModifier::hasSdp((sip_t*) msg_object(ctx->getLastForwardedInvite()))) {
		handleAnswer(ctx, ev);
	} else {
		handleOffer(ctx, ev);
	}
	ctx->storeNewResponse(ms->getMsg());
}

static bool isEarlyMedia(sip_t *sip) {
	if (sip->sip_status->st_status == 180 || sip->sip_status->st_status == 183) {
		return SdpModifier::hasSdp(sip);
	}
	return false;
}

void TranscodeModule::onResponse(shared_ptr<ResponseSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
	msg_t *msg = ms->getMsg();
	shared_ptr<TranscodedCall> c;
	if (sip->sip_cseq && sip->sip_cseq->cs_method == sip_method_invite && mAgent->countUsInVia(sip->sip_via) < 2) { //If we are more than 1 time in via headers, wait until next time we receive this message for any processing
		fixAuthChallengeForSDP(ms->getHome(), msg, sip);
		if ((c = dynamic_pointer_cast<TranscodedCall>(mCalls.find(getAgent(), sip))) != NULL) {
			if (sip->sip_status->st_status == 200 && c->isNew200Ok(sip)) {
				process200OkforInvite(c.get(), ev);
			} else if (isEarlyMedia(sip) && c->isNewEarlyMedia(sip)) {
				process200OkforInvite(c.get(), ev);
			} else if (sip->sip_status->st_status == 200 || isEarlyMedia(sip)) {
				LOGD("This is a 200 or 183 retransmission");
				if (c->getLastForwaredResponse() != NULL) {
					msg = msg_copy(c->getLastForwaredResponse());
					sip = (sip_t*) msg_object(msg);
					ev->setMsgSip(make_shared<MsgSip>(*ms, msg));
				}
			}
		}
	}
}

void TranscodeModule::onTimer() {
	for(auto it = mCalls.getList().begin(); it != mCalls.getList().end(); ++it) {
		dynamic_pointer_cast<TranscodedCall>(*it)->doBgTasks();
	}
}

void TranscodeModule::sOnTimer(void *unused, su_timer_t *t, void *zis) {
	((TranscodeModule*) zis)->onTimer();
}

