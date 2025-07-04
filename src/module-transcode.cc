/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "module-transcode.hh"

#include <charconv>
#include <functional>

#include "exceptions/bad-configuration.hh"
#include "module-toolbox.hh"
#include "transaction/outgoing-transaction.hh"

#ifdef ENABLE_TRANSCODER
#include "sdp-modifier.hh"
#endif

using namespace std;
using namespace flexisip;

ModuleInfo<Transcoder> Transcoder::sInfo(
    "Transcoder",
    "The purpose of the Transcoder module is to transparently transcode from one audio codec to another to make "
    "the communication possible between clients that do not share the same set of supported codecs. Concretely, it "
    "adds all missing codecs into the INVITEs it receives, and adds codecs matching the original INVITE into the "
    "200Ok. "
    "Rtp ports and addresses are masqueraded so that the streams can be processed by the proxy. The transcoding job is "
    "done in the background by the Mediastreamer2 library, as consequence the set of supported codecs is exactly the "
    "the same as the codec set supported by Mediastreamer2, including the possible plugins you may installed to "
    "extend Mediastreamer2.\n"
    "\n"
    "WARNING: this module can conflict with the MediaRelay module as they are both changing the SDP. Make sure to "
    "configure them with different to-domains or from-domains filter if you want to enable both of them.",
    {"MediaRelay"},
    ModuleInfoBase::ModuleOid::Transcoder,

    [](GenericStruct& moduleConfig) {
	    /*we need to be disabled by default*/
	    moduleConfig.get<ConfigBoolean>("enabled")->setDefault("false");
	    ConfigItemDescriptor items[] = {
	        {
	            DurationMS,
	            "jb-nom-size",
	            "Nominal size of RTP jitter buffer. A value of 0 means no jitter buffer (packet processing).",
	            "0",
	        },
	        {
	            StringList,
	            "rc-user-agents",
	            "Whitespace separated list of user-agent strings for which audio rate control is performed.",
	            "",
	        },
	        {
	            StringList,
	            "audio-codecs",
	            "Whitespace seprated list of audio codecs, in order of preference. The 'telephone-event' codec is "
	            "necessary "
	            "for inband DTMF processing.",
	            "speex/8000 amr/8000 iLBC/8000 gsm/8000 pcmu/8000 pcma/8000 telephone-event/8000",
	        },
	        {
	            Boolean,
	            "remove-bw-limits",
	            "Remove the bandwidth limitations from SDP offers and answers",
	            "false",
	        },
	        {
	            Boolean,
	            "block-retransmissions",
	            "If true, retransmissions of INVITEs will be blocked. The purpose of this option is to limit bandwidth "
	            "usage "
	            "and server load on reliable networks.",
	            "false",
	        },
	        config_item_end,
	    };
	    moduleConfig.addChildrenValues(items);
	    moduleConfig.createStatPair("count-calls", "Number of transcoded calls.");
    });

#ifndef ENABLE_TRANSCODER
Transcoder::Transcoder(Agent* ag, const ModuleInfoBase* moduleInfo) : Module(ag, moduleInfo) {
}
Transcoder::~Transcoder() {
}
void Transcoder::onLoad(const GenericStruct*) {
}
void Transcoder::onIdle() {
}
unique_ptr<RequestSipEvent> Transcoder::onRequest(unique_ptr<RequestSipEvent>&&) {
	throw FlexisipException{"Transcoder support is not compiled"};
}
unique_ptr<ResponseSipEvent> Transcoder::onResponse(unique_ptr<ResponseSipEvent>&&) {
	throw FlexisipException{"Transcoder support is not compiled"};
}
#endif

#ifdef ENABLE_TRANSCODER
static list<PayloadType*> makeSupportedAudioPayloadList() {
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
	payload_type_set_number(&payload_type_telephone_event, -1);

	list<PayloadType*> l;
	l.push_back(&payload_type_speex_nb);
	l.push_back(&payload_type_ilbc);
	l.push_back(&payload_type_amr);
	l.push_back(&payload_type_amrwb);
	l.push_back(&payload_type_gsm);
	l.push_back(&payload_type_pcmu8000);
	l.push_back(&payload_type_pcma8000);
	l.push_back(&payload_type_telephone_event);

	return l;
}

bool Transcoder::hasSupportedCodec(const std::list<PayloadType*>& ioffer) {
	for (auto e1 = ioffer.cbegin(); e1 != ioffer.cend(); ++e1) {
		PayloadType* p1 = *e1;
		for (auto e2 = mSupportedAudioPayloads.cbegin(); e2 != mSupportedAudioPayloads.cend(); ++e2) {
			PayloadType* p2 = *e2;
			if (strcasecmp(p1->mime_type, p2->mime_type) == 0 && p1->clock_rate == p2->clock_rate) return true;
		}
	}
	return false;
}

Transcoder::Transcoder(Agent* ag, const ModuleInfoBase* moduleInfo)
    : Module(ag, moduleInfo), mSupportedAudioPayloads(), mTimer(0) {
	mFactory = ms_factory_new_with_voip();
	auto p = mModuleConfig->getStatPair("count-calls");
	mCalls.setCallStatCounters(p.first, p.second);
}

Transcoder::~Transcoder() {
	if (mTimer) getAgent()->stopTimer(mTimer);
	// Prevent double-free by deleting calls before factory
	mCalls = {};
	if (mFactory) {
		ms_factory_destroy(mFactory);
	}
}

list<PayloadType*> Transcoder::orderList(const list<string>& config, const list<PayloadType*>& l) {
	list<PayloadType*> ret;
	list<string>::const_iterator cfg_it;

	for (const auto& configName : config) {
		auto splitConfigName = string_utils::splitOnce(configName, "/");
		if (!splitConfigName.has_value()) {
			throw BadConfiguration{"error parsing audio codec list, no '/' found in config name"};
		}
		const auto& [name, rateString] = *splitConfigName;
		if (name.empty()) throw BadConfiguration{"error parsing audio codec list, missing name information"};
		if (rateString.empty()) throw BadConfiguration{"error parsing audio codec list, missing rate information"};
		int rate{};
		auto [ptr, ec] = std::from_chars(rateString.data(), rateString.data() + rateString.size(), rate);
		if (ec == std::errc::invalid_argument)
			throw BadConfiguration{"error parsing audio codec list, rate information is not an integer"};
		if (ec == std::errc::result_out_of_range)
			throw BadConfiguration{"error parsing audio codec list, rate information is larger than int integer"};
		for (auto* pt : l) {
			if (string_utils::iequals(pt->mime_type, name) && rate == pt->clock_rate) {
				if (ms_factory_codec_supported(mFactory, pt->mime_type) ||
				    strcmp("telephone-event", pt->mime_type) == 0) {
					ret.push_back(pt);
				} else {
					LOGE << "Codec " << name << "/" << rate << " is configured but is not supported (missing plugin?)";
				}
			}
		}
	}
	return ret;
}

void Transcoder::onLoad(const GenericStruct* mc) {
	mTimer = mAgent->createTimer(20, &sOnTimer, this);
	mCallParams.mJbNomSize = mc->get<ConfigDuration<chrono::milliseconds>>("jb-nom-size")->read().count();
	mRcUserAgents = mc->get<ConfigStringList>("rc-user-agents")->read();
	mRemoveBandwidthsLimits = mc->get<ConfigBoolean>("remove-bw-limits")->read();
	list<PayloadType*> l = makeSupportedAudioPayloadList();
	mSupportedAudioPayloads = orderList(mc->get<ConfigStringList>("audio-codecs")->read(), l);
}

void Transcoder::onIdle() {
	mCalls.dump();
	mCalls.removeAndDeleteInactives(180);
}

bool Transcoder::canDoRateControl(sip_t* sip) {
	if (sip->sip_user_agent != NULL && sip->sip_user_agent->g_string != NULL) {
		list<string>::const_iterator it;
		for (it = mRcUserAgents.begin(); it != mRcUserAgents.end(); ++it) {
			if (strstr(sip->sip_user_agent->g_string, (*it).c_str())) {
				LOGD << "Audio rate control supported for " << sip->sip_user_agent->g_string;
				return true;
			}
		}
	}
	return false;
}

bool Transcoder::processSipInfo(TranscodedCall* c, RequestSipEvent& ev) {
	const shared_ptr<MsgSip>& ms = ev.getMsgSip();
	sip_t* sip = ms->getSip();
	sip_payload_t* payload = sip->sip_payload;
	if (payload != NULL && payload->pl_data != NULL) {
		if (sip->sip_content_type != NULL && strcasecmp(sip->sip_content_type->c_subtype, "dtmf-relay") == 0) {
			c->playTone(sip);
			ev.reply(200, NULL, TAG_END());
			return true;
		}
	}
	return false;
}

static const PayloadType* findPt(const list<PayloadType*>& l, const char* mime, int rate) {
	for (auto it = l.cbegin(); it != l.cend(); ++it) {
		const PayloadType* pt = *it;
		if (pt->clock_rate == rate && strcasecmp(mime, pt->mime_type) == 0) return pt;
	}
	return NULL;
}

void Transcoder::normalizePayloads(std::list<PayloadType*>& l) {
	for (auto it = l.cbegin(); it != l.cend(); ++it) {
		PayloadType* pt = *it;
		if (pt->normal_bitrate == 0) {
			const PayloadType* refpt = findPt(mSupportedAudioPayloads, pt->mime_type, pt->clock_rate);
			if (refpt && refpt->normal_bitrate > 0) {
				ms_message("Using %s at bitrate %i", pt->mime_type, refpt->normal_bitrate);
				pt->normal_bitrate = refpt->normal_bitrate;
			}
		}
	}
}

static void removeBandwidths(sdp_session_t* sdp) {
	sdp_media_t* mline = sdp->sdp_media;
	while (mline != NULL) {
		mline->m_bandwidths = NULL;
		mline = mline->m_next;
	}
}

int Transcoder::handleOffer(TranscodedCall* c, MsgSip& ms) {
	msg_t* msg = ms.getMsg();
	sip_t* sip = ms.getSip();
	shared_ptr<SdpModifier> m = SdpModifier::createFromSipMsg(ms.getHome(), ms.getSip(), "");

	if (m == NULL) return -1;

	list<PayloadType*> ioffer = m->readPayloads();

	if (hasSupportedCodec(ioffer)) {
		string fraddr;
		int frport;
		c->prepare(mCallParams);
		c->setInitialOffer(ioffer);

		m->getAudioIpPort(&fraddr, &frport);
// Force front side to bind and allocate a port immediately on the bind-address
// BIG FAT WARNING: call getAudioPort BEFORE the setRemoteAddr
// to get the local address bound correctly
#if ORTP_DEBUG_MODE
		int flport = c->getFrontSide()->getAudioPort();
#endif

		string fladdr = c->getFrontSide()->getLocalAddress();
		c->getFrontSide()->setRemoteAddr(fraddr.c_str(), frport);
#if ORTP_DEBUG_MODE
		LOGD << "Front side " << fraddr << ":" << frport << " <-> " << fladdr << ":" << flport;
#endif

		int ptime = m->readPtime();
		if (ptime > 0) {
			c->getFrontSide()->setPtime(ptime);
			m->setPtime(0); // remove the ptime attribute
		}

		int blport = c->getBackSide()->getAudioPort();
		const short ipVersion = m->getAudioIpVersion();
		const char* publicIp = getAgent()->getResolvedPublicIp(ipVersion == 6).c_str();
		LOGD << "Using public ip" << (ipVersion == 6 ? "v6" : "v4") << " " << publicIp;
		m->changeAudioIpPort(publicIp, blport);
		LOGD << "Back side local port: " << publicIp << ":" << blport << " <-> ?";

		if (mRemoveBandwidthsLimits) removeBandwidths(m->mSession);

		m->replacePayloads(mSupportedAudioPayloads, c->getInitialOffer());
		m->update(msg, sip);

		if (canDoRateControl(sip)) {
			c->getFrontSide()->enableRc(true);
		}
		return 0;
	} else {
		LOGD << "No support for any of the codec offered by client, doing bypass";
		if (!ioffer.empty()) {
			for (auto it = ioffer.begin(); it != ioffer.cend(); ++it) {
				payload_type_destroy(*it);
			}
			ioffer.clear();
		}
	}
	return -1;
}

int Transcoder::processInvite(TranscodedCall* c, RequestSipEvent& ev) {
	MsgSip& ms = *ev.getMsgSip();
	int ret = 0;
	if (SdpModifier::hasSdp(ms.getSip())) {
		ret = handleOffer(c, ms);
	}
	if (ret == 0) {
		// be in the record-route
		ModuleToolbox::addRecordRouteIncoming(getAgent(), ev);
		c->storeNewInvite(ms.getMsg());
	} else {
		ev.reply(415, "Unsupported codecs", TAG_END());
	}
	return ret;
}

void Transcoder::processAck(TranscodedCall* ctx, MsgSip& ms) {
	LOGD << "Processing ACK";
	auto ioffer = ctx->getInitialOffer();
	if (!ioffer.empty()) {
		LOGD << "Processing ACK with SDP but no offer was made or processed";
	} else {
		handleAnswer(ctx, ms);
	}
}

unique_ptr<RequestSipEvent> Transcoder::onRequest(unique_ptr<RequestSipEvent>&& ev) {
	const shared_ptr<MsgSip>& ms = ev->getMsgSip();
	sip_t* sip = ms->getSip();

	if (sip->sip_request->rq_method == sip_method_invite) {
		ev->createIncomingTransaction();
		auto ot = ev->createOutgoingTransaction();
		auto c = make_shared<TranscodedCall>(mFactory, sip, getAgent()->getRtpBindIp());
		if (processInvite(c.get(), *ev) == 0) {
			mCalls.store(c);
			ot->setProperty<TranscodedCall>(getModuleName(), c);
		} else {
			LOGD << "Transcoder: could not process invite, stopping processing";
			return {};
		}
	} else if (sip->sip_request->rq_method == sip_method_ack) {
		auto c = dynamic_pointer_cast<TranscodedCall>(mCalls.find(getAgent(), sip, true));
		if (c == NULL) {
			LOGD << "Transcoder: could not find call context for ack";
			return {};
		} else {
			processAck(c.get(), *ms);
		}
	} else if (sip->sip_request->rq_method == sip_method_info) {
		auto c = dynamic_pointer_cast<TranscodedCall>(mCalls.find(getAgent(), sip, true));
		if (c == NULL) {
			LOGD << "Transcoder: could not find call context for info";
			return {};
		} else if (processSipInfo(c.get(), *ev)) {
			/*stop the processing */
			return {};
		}
	} else if (sip->sip_request->rq_method == sip_method_bye) {
		auto c = dynamic_pointer_cast<TranscodedCall>(mCalls.find(getAgent(), sip, true));
		if (c != NULL) {
			mCalls.remove(c);
		}
	} else {
		// all other requests go through
	}
	return std::move(ev);
}

int Transcoder::handleAnswer(TranscodedCall* ctx, MsgSip& ms) {
	LOGD << "Handler answer";
	string addr;
	int port;
	shared_ptr<SdpModifier> m = SdpModifier::createFromSipMsg(ms.getHome(), ms.getSip());
	int ptime;

	if (m == NULL) return -1;
	if (ctx->isJoined()) ctx->unjoin();

	m->getAudioIpPort(&addr, &port);
	ptime = m->readPtime();
	LOGD << "Backside remote address: " << addr << ":" << port;
	ctx->getBackSide()->setRemoteAddr(addr.c_str(), port);
	if (ptime > 0) {
		ctx->getBackSide()->setPtime(ptime);
		m->setPtime(0); // remove the ptime attribute
	}
	const short ipVersion = m->getAudioIpVersion();
	const char* publicIp = getAgent()->getResolvedPublicIp(ipVersion == 6).c_str();
	LOGD << "Using public ip" << (ipVersion == 6 ? "v6" : "v4") << " " << publicIp;
	m->changeAudioIpPort(publicIp, ctx->getFrontSide()->getAudioPort());

	auto answer = m->readPayloads();
	if (answer.empty()) {
		LOGE << "No payloads in 200Ok";
		return -1;
	}
	normalizePayloads(answer);
	ctx->getBackSide()->assignPayloads(answer);

	const auto ioffer = ctx->getInitialOffer();
	auto common = SdpModifier::findCommon(mSupportedAudioPayloads, ioffer, false);
	if (!common.empty()) {
		m->replacePayloads(common, {});
	}

	if (mRemoveBandwidthsLimits) removeBandwidths(m->mSession);

	m->update(ms.getMsg(), ms.getSip());

	normalizePayloads(common);
	ctx->getFrontSide()->assignPayloads(common);

	if (canDoRateControl(ms.getSip())) {
		ctx->getBackSide()->enableRc(true);
	}

	ctx->join(mTickerManager.chooseOne());
	return 0;
}

void Transcoder::process200OkforInvite(TranscodedCall* ctx, MsgSip& ms) {
	LOGD << "Processing 200 Ok";
	if (SdpModifier::hasSdp((sip_t*)msg_object(ctx->getLastForwardedInvite()))) {
		handleAnswer(ctx, ms);
	} else {
		handleOffer(ctx, ms);
	}
}

static bool isEarlyMedia(sip_t* sip) {
	if (sip->sip_status->st_status == 180 || sip->sip_status->st_status == 183) {
		return SdpModifier::hasSdp(sip);
	}
	return false;
}

unique_ptr<ResponseSipEvent> Transcoder::onResponse(unique_ptr<ResponseSipEvent>&& ev) {
	const shared_ptr<MsgSip>& ms = ev->getMsgSip();
	sip_t* sip = ms->getSip();
	msg_t* msg = ms->getMsg();

	if (sip->sip_cseq && sip->sip_cseq->cs_method == sip_method_invite) {
		if (mAgent->countUsInVia(sip->sip_via) > 1) {
			LOGD << "We are more than 1 time in via headers, wait until next time we receive this message for any "
			        "processing";
			return std::move(ev);
		}

		ModuleToolbox::fixAuthChallengeForSDP(ms->getHome(), msg, sip);

		auto transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
		if (transaction == NULL) {
			LOGD << "No transaction found";
			return std::move(ev);
		}

		shared_ptr<TranscodedCall> c = transaction->getProperty<TranscodedCall>(getModuleName());
		if (c == NULL) {
			LOGD << "No transcoded call context found";
			return std::move(ev);
		}

		if (sip->sip_status->st_status == 200 || isEarlyMedia(sip)) {
			// Remove all call contexts maching the sip message
			// Except the one from this outgoing transaction
			mCalls.findAndRemoveExcept(getAgent(), sip, c, true);
			process200OkforInvite(c.get(), *ev->getMsgSip());
		}
	}
	return std::move(ev);
}

void Transcoder::onTimer() {
	for (auto it = mCalls.getList().begin(); it != mCalls.getList().end(); ++it) {
		dynamic_pointer_cast<TranscodedCall>(*it)->doBgTasks();
	}
}

void Transcoder::sOnTimer([[maybe_unused]] void* unused, [[maybe_unused]] su_timer_t* t, void* zis) {
	((Transcoder*)zis)->onTimer();
}

const std::list<const PayloadType*>& flexisip::Transcoder::getSupportedPayloads() const {
	return castToConst(mSupportedAudioPayloads);
}

#endif