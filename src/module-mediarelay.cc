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

class RelayedCall: public CallContextBase {
public:
	static const int sMaxSessions = 4;
	RelayedCall(MediaRelayServer *server, sip_t *sip) :
			CallContextBase(sip), mServer(server) {
		memset(mSessions, 0, sizeof(mSessions));
	}
	typedef std::tuple<std::string, int> addr_type;
	std::map<std::string, addr_type> tagMap;

	/*this function is called to masquerade the SDP, for each mline*/
	void onNewMedia(int mline, std::string *ip, int *port, const char *party_tag) {
		if (mline >= sMaxSessions) {
			LOGE("Max sessions per relayed call is reached.");
			return;
		}
		RelaySession *s = mSessions[mline];
		if (s == NULL) {
			s = mServer->createSession();
			mSessions[mline] = s;
		}
	}

	void onTranslate(int mline, std::string *ip, int *port, const char *party_tag) {
		if (mline >= sMaxSessions) {
			return;
		}
		RelaySession *s = mSessions[mline];
		if (s != NULL) {
			if (getCallerTag() == party_tag) {
				*port = s->getBackPort();
			} else {
				*port = s->getFrontPort();
			}
			*ip = s->getPublicIp();
		}
	}

	void onAdd(int mline, std::string *ip, int *port, const char *party_tag) {
		if (mline >= sMaxSessions) {
			return;
		}
		RelaySession *s = mSessions[mline];
		if (s != NULL) {
			if (getCallerTag() == party_tag) {
				s->addFront(*ip, *port);
			} else {
				s->addBack(*ip, *port);
			}
			if (party_tag != NULL) {
				addr_type addr = std::make_tuple(std::string(*ip), *port);
				tagMap.insert(std::pair<std::string, addr_type>(std::string(party_tag), addr));
			}
		}
	}

	void onRemove(const char *party_tag) {
		if (party_tag != NULL) {
			auto it = tagMap.find(std::string(party_tag));
			if (it != tagMap.end()) {
				tagMap.erase(it);
				addr_type &addr = it->second;
				std::string &ip = std::get<0>(addr);
				int port = std::get<1>(addr);
				for (int mline = 0; mline < sMaxSessions; ++mline) {
					RelaySession *s = mSessions[mline];
					if (s != NULL) {
						if (getCallerTag() == party_tag) {
							s->removeFront(ip, port);
						} else {
							s->removeBack(ip, port);
						}
					}
				}
			}
		}
	}

	bool isInactive(time_t cur) {
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

	~RelayedCall() {
		int i;
		for (i = 0; i < sMaxSessions; ++i) {
			RelaySession *s = mSessions[i];
			if (s)
				s->unuse();
		}
	}
private:
	RelaySession * mSessions[sMaxSessions];
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
		m->iterate(std::bind(&RelayedCall::onNewMedia, c, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, sip->sip_from->a_tag));
		m->iterate(std::bind(&RelayedCall::onAdd, c, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, sip->sip_from->a_tag));
		m->iterate(std::bind(&RelayedCall::onTranslate, c, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, sip->sip_from->a_tag));
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
	std::shared_ptr<MsgSip> ms = ev->getMsgSip();
	RelayedCall *c;
	msg_t *msg = ms->getMsg();
	sip_t *sip = ms->getSip();

	StatefulSipEvent *sse = dynamic_cast<StatefulSipEvent *>(ev.get());
	if (sse != NULL) {
		//Stateful
		if (sip->sip_request->rq_method == sip_method_invite) {
			if ((c = static_cast<RelayedCall*>(mCalls->find(getAgent(), sip, true))) == NULL) {
				c = new RelayedCall(mServer, sip);
				if (processNewInvite(c, msg, sip)) {
					mCalls->store(c);
				} else {
					delete c;
				}
			} else {
				processNewInvite(c, msg, sip);
			}
		} else if (sip->sip_request->rq_method == sip_method_bye) {
			if ((c = static_cast<RelayedCall*>(mCalls->find(getAgent(), sip, true))) != NULL) {
				mCalls->remove(c);
				delete c;
			}
		}
	} else {
		//Stateless
		if (sip->sip_request->rq_method == sip_method_invite) {
			if ((c = static_cast<RelayedCall*>(mCalls->find(getAgent(), sip))) == NULL) {
				c = new RelayedCall(mServer, sip);
				if (processNewInvite(c, msg, sip)) {
					mCalls->store(c);
				} else {
					delete c;
				}
			} else {
				if (c->isNewInvite(sip)) {
					processNewInvite(c, msg, sip);
				} else if (c->getLastForwardedInvite() != NULL) {
					uint32_t via_count = 0;
					for (sip_via_t *via = sip->sip_via; via != NULL; via = via->v_next)
						++via_count;

					// Same vias?
					if (via_count == c->getViaCount()) {
						msg = msg_copy(c->getLastForwardedInvite());
						sip = (sip_t*) msg_object(msg);
						LOGD("Forwarding invite retransmission");
					}
				}
			}
		} else if (sip->sip_request->rq_method == sip_method_bye) {
			if ((c = static_cast<RelayedCall*>(mCalls->find(getAgent(), sip))) != NULL) {
				mCalls->remove(c);
				delete c;
			}
		}
	}

	ev->setMsgSip(std::make_shared<MsgSip>(msg, sip));

}

static bool isEarlyMedia(sip_t *sip) {
	if (sip->sip_status->st_status == 180 || sip->sip_status->st_status == 183) {
		sip_payload_t *payload = sip->sip_payload;
		//TODO: should check if it is application/sdp
		return payload != NULL;
	}
	return false;
}

void MediaRelay::process200OkforInvite(RelayedCall *c, msg_t *msg, sip_t *sip) {
	LOGD("Processing 200 Ok");

	if (sip->sip_to == NULL || sip->sip_to->a_tag == NULL) {
		LOGW("No tag in answer");
		return;
	}
	SdpModifier *m = SdpModifier::createFromSipMsg(c->getHome(), sip);
	if (m == NULL)
		return;

	m->iterate(std::bind(&RelayedCall::onAdd, c, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, sip->sip_to->a_tag));
	m->iterate(std::bind(&RelayedCall::onTranslate, c, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, sip->sip_to->a_tag));
	m->update(msg, sip);
	c->storeNewResponse(msg);

	delete m;
}

void MediaRelay::onResponse(std::shared_ptr<SipEvent> &ev) {
	std::shared_ptr<MsgSip> ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
	msg_t *msg = ms->getMsg();
	RelayedCall *c;
	StatefulSipEvent *sse = dynamic_cast<StatefulSipEvent *>(ev.get());
	if (sse != NULL) {
		//Stateful
		if (sip->sip_cseq && sip->sip_cseq->cs_method == sip_method_invite) {
			fixAuthChallengeForSDP(ms->getHome(), msg, sip);
			if (sip->sip_status->st_status == 200 || isEarlyMedia(sip)) {
				if ((c = static_cast<RelayedCall*>(mCalls->find(getAgent(), sip, true))) != NULL) {
					process200OkforInvite(c, msg, sip);
				} else {
					LOGD("Receiving 200Ok for unknown call.");
				}
			}
		}
	} else {
		//Stateless
		if (sip->sip_cseq && sip->sip_cseq->cs_method == sip_method_invite) {
			fixAuthChallengeForSDP(ms->getHome(), msg, sip);
			if (sip->sip_status->st_status == 200 || isEarlyMedia(sip)) {
				if ((c = static_cast<RelayedCall*>(mCalls->find(getAgent(), sip))) != NULL) {
					if (sip->sip_status->st_status == 200 && c->isNew200Ok(sip)) {
						process200OkforInvite(c, msg, sip);
					} else if (isEarlyMedia(sip) && c->isNewEarlyMedia(sip)) {
						process200OkforInvite(c, msg, sip);
					} else if (sip->sip_status->st_status == 200 || isEarlyMedia(sip)) {
						LOGD("This is a 200 or 183  retransmission");
						if (c->getLastForwaredResponse() != NULL) {
							msg = msg_copy(c->getLastForwaredResponse());
							sip = (sip_t*) msg_object(msg);
						}
					}
				} else {
					LOGD("Receiving 200Ok for unknown call.");
				}
			}
		}
	}

	ev->setMsgSip(make_shared<MsgSip>(msg, sip));
}

void MediaRelay::onIdle() {
	mCalls->dump();
	mCalls->removeAndDeleteInactives();
}
