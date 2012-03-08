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
#include "mediarelay.hh"
#include "callstore.hh"
#include "sdp-modifier.hh"

#include <vector>
#include <algorithm>

using namespace ::std;

class RelayedCall;

class MediaRelay: public Module, protected ModuleToolbox {
public:
	MediaRelay(Agent *ag);
	~MediaRelay();
	virtual void onLoad(Agent *ag, const ConfigStruct * modconf);
	virtual void onRequest(std::shared_ptr<SipEvent> &ev);
	virtual void onResponse(std::shared_ptr<SipEvent> &ev);
	virtual void onIdle();
protected:
	virtual void onDeclare(ConfigStruct * module_config) {
		ConfigItemDescriptor items[] = { { String, "nortpproxy", "SDP attribute set by the first proxy to forbid subsequent proxies to provide relay.", "nortpproxy" }, config_item_end };
		module_config->addChildrenValues(items);
	}
private:
	bool processNewInvite(RelayedCall *c, msg_t *msg, sip_t *sip);
	void process200OkforInvite(RelayedCall *ctx, msg_t *msg, sip_t *sip);
	CallStore *mCalls;
	MediaRelayServer *mServer;
	std::string mSdpMangledParam;
	static ModuleInfo<MediaRelay> sInfo;
};

class RelayedCall: public CallContextBase, public Masquerader {
private:
	typedef std::tuple<int, std::string, uint16_t> line_addr_type;
	std::map<line_addr_type, std::shared_ptr<RelaySessionRtp>> mMapping;
	line_addr_type createTuple(int mline, url_t *url) {
		uint16_t port = (url->url_port) ? atoi(url->url_port) : 5060;
		std::string host(url->url_host);
		return std::make_tuple(mline, host, port);
	}

public:
	static const int sMaxSessions = 4;
	RelayedCall(MediaRelayServer *server, sip_t *sip) :
			CallContextBase(sip), mServer(server) {
		memset(mSessions, 0, sizeof(mSessions));
	}

	virtual void translate(int mline, url_t *to, std::string *ip, int *port) {
		RelaySession *s = mSessions[mline];
		std::shared_ptr<RelaySessionRtp> rsr;
		if (to != NULL) {
			line_addr_type id = createTuple(mline, to);
			auto it = mMapping.find(id);
			if (it == mMapping.end()) {
				rsr = s->createBackDefaultSource(ip->c_str(), *port);
				mMapping.insert(std::pair<line_addr_type, std::shared_ptr<RelaySessionRtp>>(id, rsr));
			} else {
				rsr = it->second;
			}
		} else {
			rsr = s->getFront();
		}
		*port = rtp_session_get_local_port(rsr->mSession);
		*ip = s->getPublicIp();
	}

	/*this function is called to masquerade the SDP, for each mline*/
	virtual void onNewMedia(int mline, url_t *from, const std::string &ip, int port) {
		if (mline >= sMaxSessions) {
			LOGE("Max sessions per relayed call is reached.");
			return;
		}
		RelaySession *s = mSessions[mline];
		if (s == NULL) {
			s = mServer->createSession();
			LOGD("RelayedCall %p %p", this, s);
			mSessions[mline] = s;
		}

		std::shared_ptr<RelaySessionRtp> rsr;
		line_addr_type id = createTuple(mline, from);
		auto it = mMapping.find(id);
		if (it == mMapping.end()) {
			rsr = s->setFrontDefaultSource(ip.c_str(), port);
			mMapping.insert(std::pair<line_addr_type, std::shared_ptr<RelaySessionRtp>>(id, rsr));
		} else {
			rsr = it->second;
		}
		s->setBackDefaultSource(rsr, ip.c_str(), port);
	}

	virtual bool isInactive(time_t cur) {
		time_t maxtime = 0;
		RelaySession *r;
		for (int i = 0; i < sMaxSessions; ++i) {
			time_t tmp;
			r = mSessions[i];
			if (r && ((tmp = r->getLastActivityTime()) > maxtime))
				maxtime = tmp;
		}
		if (cur - maxtime > 30)
			return true;
		return false;
	}
	virtual ~RelayedCall() {
		int i;
		for (i = 0; i < sMaxSessions; ++i) {
			RelaySession *s = mSessions[i];
			if (s)
				s->unuse();
		}
	}

protected:
	RelaySession *mSessions[sMaxSessions];
	MediaRelayServer *mServer;
};

ModuleInfo<MediaRelay> MediaRelay::sInfo("MediaRelay", "The MediaRelay module masquerades SDP message so that all RTP and RTCP streams go through the proxy. "
		"The RTP and RTCP streams are then routed so that each client receives the stream of the other. "
		"MediaRelay makes sure that RTP is ALWAYS established, even with uncooperative firewalls.");

MediaRelay::MediaRelay(Agent *ag) :
		Module(ag), mServer(0) {
}

MediaRelay::~MediaRelay() {
	if (mCalls)
		delete mCalls;
	if (mServer)
		delete mServer;
}

void MediaRelay::onLoad(Agent *ag, const ConfigStruct * modconf) {
	mCalls = new CallStore();
	mServer = new MediaRelayServer(ag->getBindIp(), ag->getPublicIp());
	mSdpMangledParam = modconf->get<ConfigString>("nortpproxy")->read();
}

bool MediaRelay::processNewInvite(RelayedCall *c, msg_t *msg, sip_t *sip) {
	if (sip->sip_from == NULL || sip->sip_from->a_tag == NULL) {
		LOGW("No tag in from !");
		return false;
	}
	SdpModifier *m = SdpModifier::createFromSipMsg(c->getHome(), sip);
	if (m->hasAttribute(mSdpMangledParam.c_str())) {
		LOGD("Invite is already relayed");
		delete m;
		return false;
	}
	if (m) {
		m->changeIpPort(c, sip->sip_contact->m_url, sip->sip_request->rq_url);
		m->addAttribute(mSdpMangledParam.c_str(), "yes");
		m->update(msg, sip);
		//be in the record-route
		addRecordRoute(c->getHome(), getAgent(), msg, sip);
		c->storeNewInvite(msg);
		delete m;
	}
	return true;
}

void MediaRelay::onRequest(std::shared_ptr<SipEvent> &ev) {
	RelayedCall *c;
	msg_t *msg = ev->getMsg();
	sip_t *sip = ev->getSip();

	if (sip->sip_request->rq_method == sip_method_invite) {
		if ((c = static_cast<RelayedCall*>(mCalls->similar(getAgent(), sip))) == NULL) {
			c = new RelayedCall(mServer, sip);
			if (processNewInvite(c, msg, sip)) {
				mCalls->store(c);
			} else {
				delete c;
			}
		} else {
			processNewInvite(c, msg, sip);
		}
	}
	if (sip->sip_request->rq_method == sip_method_bye) {
		if ((c = static_cast<RelayedCall*>(mCalls->similar(getAgent(), sip))) != NULL) {
			mCalls->remove(c);
			delete c;
		}
	}

	ev->setMsgSip(msg, sip);
}

static bool isEarlyMedia(sip_t *sip) {
	if (sip->sip_status->st_status == 180 || sip->sip_status->st_status == 183) {
		sip_payload_t *payload = sip->sip_payload;
		//TODO: should check if it is application/sdp
		return payload != NULL;
	}
	return false;
}

void MediaRelay::process200OkforInvite(RelayedCall *ctx, msg_t *msg, sip_t *sip) {
	LOGD("Processing 200 Ok");

	if (sip->sip_to == NULL || sip->sip_to->a_tag == NULL) {
		LOGW("No tag in answer");
		return;
	}
	SdpModifier *m = SdpModifier::createFromSipMsg(ctx->getHome(), sip);
	if (m == NULL)
		return;

	m->changeIpPort(ctx, sip->sip_contact->m_url, NULL);
	m->update(msg, sip);
	ctx->storeNewResponse(msg);

	delete m;
}

void MediaRelay::onResponse(std::shared_ptr<SipEvent> &ev) {
	sip_t *sip = ev->getSip();
	msg_t *msg = ev->getMsg();
	RelayedCall *c;

	if (sip->sip_cseq && sip->sip_cseq->cs_method == sip_method_invite) {
		fixAuthChallengeForSDP(ev->getHome(), msg, sip);
		if (sip->sip_status->st_status == 200 || isEarlyMedia(sip)) {
			if ((c = static_cast<RelayedCall*>(mCalls->similar(getAgent(), sip))) != NULL) {
				process200OkforInvite(c, msg, sip);
			} else {
				LOGD("Receiving 200Ok for unknown call.");
			}
		}
	}

	ev->setMsgSip(msg, sip);
}

void MediaRelay::onIdle() {
	mCalls->dump();
	mCalls->removeAndDeleteInactives();
}
