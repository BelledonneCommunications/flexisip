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
#include "mediarelay.hh"
#include "callstore.hh"
#include "sdp-modifier.hh"
#include "transaction.hh"

#include <vector>
#include <algorithm>

using namespace ::std;

const static char* countInvitesStr = "count-invites";
const static char* countInvitesFinishedStr = "count-invites-finished";

class RelayedCall;

class MediaRelay: public Module, protected ModuleToolbox {
public:
	MediaRelay(Agent *ag);
	~MediaRelay();
	virtual void onLoad(Agent *ag, const GenericStruct * modconf);
	virtual void onRequest(shared_ptr<SipEvent> &ev);
	virtual void onResponse(shared_ptr<SipEvent> &ev);
	virtual void onTransactionEvent(const std::shared_ptr<Transaction> &transaction, Transaction::Event event);
	virtual void onIdle();
protected:
	virtual void onDeclare(GenericStruct * module_config) {
		ConfigItemDescriptor items[] = { { String, "nortpproxy", "SDP attribute set by the first proxy to forbid subsequent proxies to provide relay.", "nortpproxy" }, config_item_end };
		module_config->addChildrenValues(items);

		StatItemDescriptor stats[] = {
			{	Counter64,	countInvitesStr, "Number of calls."},
			{	Counter64,	countInvitesFinishedStr, "Number of calls finished."},
			stat_item_end };
		module_config->addChildrenValues(stats);
	}
private:
	bool processNewInvite(const shared_ptr<RelayedCall> &c, const std::shared_ptr<OutgoingTransaction>& transaction, const shared_ptr<MsgSip> &msgSip);
	void process200OkforInvite(const shared_ptr<RelayedCall> &c, const std::shared_ptr<OutgoingTransaction>& transaction, const shared_ptr<MsgSip> &msgSip);
	CallStore *mCalls;
	MediaRelayServer *mServer;
	string mSdpMangledParam;
	static ModuleInfo<MediaRelay> sInfo;
};

class RelayedCall: public CallContextBase {
	class RelaySessionTransaction {
	public:
		RelaySessionTransaction() :
				mRelaySession(NULL) {

		}

		RelaySession *mRelaySession;
		map<shared_ptr<Transaction>, shared_ptr<MediaSource>> mTransactions;
	};
public:
	static const int sMaxSessions = 4;
	RelayedCall(MediaRelayServer *server, sip_t *sip) :
			CallContextBase(sip), mServer(server) {
		LOGD("New RelayedCall %p", this);
	}

	/*this function is called to masquerade the SDP, for each mline*/
	void newMedia(int mline, string *ip, int *port) {
		if (mline >= sMaxSessions) {
			LOGE("Max sessions per relayed call is reached.");
			return;
		}
		RelaySession *s = mSessions[mline].mRelaySession;
		if (s == NULL) {
			s = mServer->createSession();
			mSessions[mline].mRelaySession = s;
			s->addFront()->set(*ip, *port);
		}

	}

	void backwardTranslate(int mline, string *ip, int *port) {
		if (mline >= sMaxSessions) {
			return;
		}
		RelaySession *s = mSessions[mline].mRelaySession;
		if (s != NULL) {
			*port = s->getFronts().front()->getRelayPort();
			*ip = s->getPublicIp();
		}
	}

	void forwardTranslate(int mline, string *ip, int *port, const std::shared_ptr<Transaction> &transaction) {
		if (mline >= sMaxSessions) {
			return;
		}
		RelaySession *s = mSessions[mline].mRelaySession;
		if (s != NULL) {
			auto it = mSessions[mline].mTransactions.find(transaction);
			if (it != mSessions[mline].mTransactions.end()) {
				*port = it->second->getRelayPort();
			} else {
				LOGE("Can't find transaction %p", transaction.get());
			}
			*ip = s->getPublicIp();
		}
	}

	void addBack(int mline, string *ip, int *port, const std::shared_ptr<Transaction> &transaction) {
		if (mline >= sMaxSessions) {
			return;
		}
		RelaySession *s = mSessions[mline].mRelaySession;
		if (s != NULL) {
			mSessions[mline].mTransactions.insert(pair<shared_ptr<Transaction>, shared_ptr<MediaSource>>(transaction, s->addBack()));

			s->setType((mSessions[mline].mTransactions.size() > 1) ? RelaySession::FrontToBack : RelaySession::All);
		}
	}

	void setBack(int mline, string *ip, int *port, const std::shared_ptr<Transaction> &transaction) {
		if (mline >= sMaxSessions) {
			return;
		}
		RelaySession *s = mSessions[mline].mRelaySession;
		if (s != NULL) {
			auto it = mSessions[mline].mTransactions.find(transaction);
			if (it != mSessions[mline].mTransactions.end()) {
				std::shared_ptr<MediaSource> ms = it->second;
				ms->set(*ip, *port);
			} else {
				LOGE("Can't find transaction %p", transaction.get());
			}
		}
	}

	void removeBack(const std::shared_ptr<Transaction> transaction) {
		for (int mline = 0; mline < sMaxSessions; ++mline) {
			RelaySession *s = mSessions[mline].mRelaySession;
			if (s != NULL) {
				auto it = mSessions[mline].mTransactions.find(transaction);
				if (it != mSessions[mline].mTransactions.end()) {
					std::shared_ptr<MediaSource> ms = it->second;
					s->removeBack(ms);
					s->setType((mSessions[mline].mTransactions.size() > 1) ? RelaySession::FrontToBack : RelaySession::All);
				} else {
					LOGE("Can't find transaction %p", transaction.get());
				}
			}
		}
	}

	void cleanTransaction(const std::shared_ptr<Transaction> transaction) {
		for (int mline = 0; mline < sMaxSessions; ++mline) {
			RelaySession *s = mSessions[mline].mRelaySession;
			if (s != NULL) {
				auto it = mSessions[mline].mTransactions.find(transaction);
				if (it != mSessions[mline].mTransactions.end()) {
					mSessions[mline].mTransactions.erase(it);
				} else {
					LOGE("Can't find transaction %p", transaction.get());
				}
			}
		}
	}

	void update() {
		mServer->update();
	}

	bool isInactive(time_t cur) {
		time_t maxtime = 0;
		RelaySession *r;
		for (int i = 0; i < sMaxSessions; ++i) {
			time_t tmp;
			r = mSessions[i].mRelaySession;
			if (r && ((tmp = r->getLastActivityTime()) > maxtime))
				maxtime = tmp;
		}
		if (cur - maxtime > 30)
			return true;
		return false;
	}

	~RelayedCall() {
		LOGD("Destroy RelayedCall %p", this);
		int i;
		for (i = 0; i < sMaxSessions; ++i) {
			RelaySession *s = mSessions[i].mRelaySession;
			if (s) {
				s->unuse();
			}
		}
	}

private:
	RelaySessionTransaction mSessions[sMaxSessions];
	MediaRelayServer *mServer;
};

static bool isEarlyMedia(sip_t *sip) {
	if (sip->sip_status->st_status == 180 || sip->sip_status->st_status == 183) {
		sip_payload_t *payload = sip->sip_payload;
		//TODO: should check if it is application/sdp
		return payload != NULL;
	}
	return false;
}

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

void MediaRelay::onLoad(Agent *ag, const GenericStruct * modconf) {
	mCalls = new CallStore();
	mServer = new MediaRelayServer(ag->getBindIp(), ag->getPublicIp());
	mSdpMangledParam = modconf->get<ConfigString>("nortpproxy")->read();
}

bool MediaRelay::processNewInvite(const shared_ptr<RelayedCall> &c, const std::shared_ptr<OutgoingTransaction>& transaction, const shared_ptr<MsgSip> &msgSip) {
	sip_t *sip = msgSip->getSip();
	msg_t *msg = msgSip->getMsg();

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
		// Create Media
		m->iterate(bind(&RelayedCall::newMedia, c, placeholders::_1, placeholders::_2, placeholders::_3));

		// Add back
		m->iterate(bind(&RelayedCall::addBack, c, placeholders::_1, placeholders::_2, placeholders::_3, ref(transaction)));

		// Translate
		m->iterate(bind(&RelayedCall::forwardTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3, ref(transaction)));

		m->addAttribute(mSdpMangledParam.c_str(), "yes");
		m->update(msg, sip);
		c->update();

		//be in the record-route
		addRecordRoute(c->getHome(), getAgent(), msg, sip);
		delete m;
	}
	return true;
}

void MediaRelay::onRequest(shared_ptr<SipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();

	shared_ptr<RelayedCall> c;

	if (sip->sip_request->rq_method == sip_method_invite) {
		ev->createIncomingTransaction();
		shared_ptr<OutgoingTransaction> ot = ev->createOutgoingTransaction();
		if ((c = dynamic_pointer_cast<RelayedCall>(mCalls->find(getAgent(), sip, true))) == NULL) {
			c = make_shared<RelayedCall>(mServer, sip);
			if (processNewInvite(c, ot, ev->getMsgSip())) {
				mCalls->store(c);
				ot->setProperty<RelayedCall>(MediaRelay::sInfo.getModuleName(), c);
			}
		} else {
			processNewInvite(c, ot, ev->getMsgSip());
			ot->setProperty(getModuleName(), c);
		}
	} else if (sip->sip_request->rq_method == sip_method_bye) {
		if ((c = dynamic_pointer_cast<RelayedCall>(mCalls->find(getAgent(), sip, true))) != NULL) {
			mCalls->remove(c);
		}
	} else if (sip->sip_request->rq_method == sip_method_cancel) {
		if ((c = dynamic_pointer_cast<RelayedCall>(mCalls->find(getAgent(), sip, true))) != NULL) {
			mCalls->remove(c);
		}
	}
}

void MediaRelay::process200OkforInvite(const shared_ptr<RelayedCall> &c, const std::shared_ptr<OutgoingTransaction>& transaction, const shared_ptr<MsgSip> &msgSip) {
	sip_t *sip = msgSip->getSip();
	msg_t *msg = msgSip->getMsg();
	LOGD("Processing 200 Ok");

	if (sip->sip_to == NULL || sip->sip_to->a_tag == NULL) {
		LOGW("No tag in answer");
		return;
	}
	SdpModifier *m = SdpModifier::createFromSipMsg(c->getHome(), sip);
	if (m == NULL)
		return;

	m->iterate(bind(&RelayedCall::setBack, c, placeholders::_1, placeholders::_2, placeholders::_3, ref(transaction)));
	m->iterate(bind(&RelayedCall::backwardTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3));
	m->update(msg, sip);

	delete m;
}

void MediaRelay::onResponse(shared_ptr<SipEvent> &ev) {
	shared_ptr<MsgSip> ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
	msg_t *msg = ms->getMsg();

	// Handle SipEvent associated with a Stateful transaction
	std::shared_ptr<OutgoingTransaction> transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
	if (transaction != NULL) {
		shared_ptr<RelayedCall> ptr = transaction->getProperty<RelayedCall>(getModuleName());
		if (ptr != NULL) {
			if (sip->sip_cseq && sip->sip_cseq->cs_method == sip_method_invite) {
				fixAuthChallengeForSDP(ms->getHome(), msg, sip);
				if (sip->sip_status->st_status == 200 || isEarlyMedia(sip)) {
					process200OkforInvite(ptr, transaction, ev->getMsgSip());
				} else if (sip->sip_status->st_status == 487) {
					ptr->removeBack(transaction);
				}
			}
			return;
		}
	}
}

void MediaRelay::onTransactionEvent(const std::shared_ptr<Transaction> &transaction, Transaction::Event event) {
	shared_ptr<RelayedCall> ptr = transaction->getProperty<RelayedCall>(getModuleName());
	if (ptr != NULL) {
		std::shared_ptr<OutgoingTransaction> ot = dynamic_pointer_cast<OutgoingTransaction>(transaction);
		if (ot != NULL) {
			switch (event) {
			case Transaction::Destroy:
				ptr->cleanTransaction(transaction); //Free transaction reference
				break;

			default:
				break;
			}
		}
	}
}

void MediaRelay::onIdle() {
	mCalls->dump();
	mCalls->removeAndDeleteInactives();
}
