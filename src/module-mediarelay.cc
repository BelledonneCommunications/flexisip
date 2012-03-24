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

const static char* countCallsStr = "count-calls";
const static char* countCallsFinishedStr = "count-calls-finished";

class RelayedCall;

class MediaRelay: public Module, protected ModuleToolbox {
public:
	MediaRelay(Agent *ag);
	~MediaRelay();
	virtual void onLoad(Agent *ag, const GenericStruct * modconf);
	virtual void onRequest(shared_ptr<SipEvent> &ev);
	virtual void onResponse(shared_ptr<SipEvent> &ev);
	virtual void onTransactionEvent(const shared_ptr<Transaction> &transaction, Transaction::Event event);
	virtual void onIdle();
protected:
	virtual void onDeclare(GenericStruct * module_config) {
		ConfigItemDescriptor items[] = { { String, "nortpproxy", "SDP attribute set by the first proxy to forbid subsequent proxies to provide relay.", "nortpproxy" }, config_item_end };
		module_config->addChildrenValues(items);

		StatItemDescriptor stats[] = { { Counter64, countCallsStr, "Number of calls." }, { Counter64, countCallsFinishedStr, "Number of calls finished." }, stat_item_end };
		module_config->addChildrenValues(stats);
	}
private:
	bool processNewInvite(const shared_ptr<RelayedCall> &c, const shared_ptr<OutgoingTransaction>& transaction, const shared_ptr<MsgSip> &msgSip);
	void process200OkforInvite(const shared_ptr<RelayedCall> &c, const shared_ptr<OutgoingTransaction>& transaction, const shared_ptr<MsgSip> &msgSip);
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
	typedef enum {
		Idle, Initialized, Running
	} State;
public:
	static const int sMaxSessions = 4;
	RelayedCall(MediaRelayServer *server, sip_t *sip) :
			CallContextBase(sip), mServer(server), mState(Idle) {
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
			shared_ptr<MediaSource> ms = s->addFront();
			ms->set(*ip, *port);
			ms->setBehaviour(MediaSource::All);
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

	void forwardTranslate(int mline, string *ip, int *port, const shared_ptr<Transaction> &transaction) {
		if (mline >= sMaxSessions) {
			return;
		}
		RelaySession *s = mSessions[mline].mRelaySession;
		if (s != NULL) {
			auto it = mSessions[mline].mTransactions.find(transaction);
			if (it != mSessions[mline].mTransactions.end()) {
				*port = it->second->getRelayPort();
			} else {
				*port = -1;
			}
			*ip = s->getPublicIp();
		}
	}

	void addBack(const shared_ptr<Transaction> &transaction) {
		for (int mline = 0; mline < sMaxSessions; ++mline) {
			RelaySession *s = mSessions[mline].mRelaySession;
			if (s != NULL) {
				shared_ptr<MediaSource> ms = s->addBack();
				ms->setBehaviour(MediaSource::Receive);
				mSessions[mline].mTransactions.insert(pair<shared_ptr<Transaction>, shared_ptr<MediaSource>>(transaction, ms));
			}
		}
	}

	void setBack(int mline, string *ip, int *port, const shared_ptr<Transaction> &transaction) {
		if (mline >= sMaxSessions) {
			return;
		}
		RelaySession *s = mSessions[mline].mRelaySession;
		if (s != NULL) {
			auto it = mSessions[mline].mTransactions.find(transaction);
			if (it != mSessions[mline].mTransactions.end()) {
				shared_ptr<MediaSource> &ms = it->second;
				ms->set(*ip, *port);
			}
		}
	}

	void update(const shared_ptr<Transaction> &transaction = shared_ptr<Transaction>()) {
		if (mState == Idle)
			mState = Initialized;

		// Only one feed from back to front
		bool isSendingFeed = false;
		for (int mline = 0; mline < sMaxSessions; ++mline) {
			RelaySession *s = mSessions[mline].mRelaySession;
			if (s != NULL) {
				for (auto it = mSessions[mline].mTransactions.begin(); it != mSessions[mline].mTransactions.end(); ++it) {
					shared_ptr<MediaSource> &ms = it->second;
					isSendingFeed |= (ms->getBehaviour() & MediaSource::Send);
				}
				break;
			}
		}
		if (!isSendingFeed) {
			for (int mline = 0; mline < sMaxSessions; ++mline) {
				RelaySession *s = mSessions[mline].mRelaySession;
				if (s != NULL) {
					auto it = mSessions[mline].mTransactions.begin();
					if (it != mSessions[mline].mTransactions.end()) {
						shared_ptr<MediaSource> &ms = it->second;
						ms->setBehaviour(MediaSource::All);
					}
				}
			}
		}
	}

	bool removeBack(const shared_ptr<Transaction> &transaction) {
		bool remove = (mState != Running);
		for (int mline = 0; mline < sMaxSessions; ++mline) {
			RelaySession *s = mSessions[mline].mRelaySession;
			if (s != NULL) {
				auto it = mSessions[mline].mTransactions.find(transaction);
				if (it != mSessions[mline].mTransactions.end()) {
					shared_ptr<MediaSource> &ms = it->second;
					s->removeBack(ms);
					mSessions[mline].mTransactions.erase(it);
				}
				if (!mSessions[mline].mTransactions.empty())
					remove = false;
			}
		}
		update();
		return remove;
	}

	void validBack(const shared_ptr<Transaction> &transaction) {
		for (int mline = 0; mline < sMaxSessions; ++mline) {
			RelaySession *s = mSessions[mline].mRelaySession;
			if (s != NULL) {
				auto it = mSessions[mline].mTransactions.find(transaction);
				if (it != mSessions[mline].mTransactions.end()) {
					shared_ptr<MediaSource> &ms = it->second;
					mSessions[mline].mTransactions.erase(it);
					ms->setBehaviour(MediaSource::BehaviourType::All);
				}
				it = mSessions[mline].mTransactions.begin();
				while (it != mSessions[mline].mTransactions.end()) {
					shared_ptr<MediaSource> &ms = it->second;
					s->removeBack(ms);
					mSessions[mline].mTransactions.erase(it++);
				}
			}
		}
		mState = Running;
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
	State mState;
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
		Module(ag), mCalls(NULL), mServer(NULL) {
}

MediaRelay::~MediaRelay() {
	if (mCalls)
		delete mCalls;
	if (mServer)
		delete mServer;
}

void MediaRelay::onLoad(Agent *ag, const GenericStruct * modconf) {
	mCalls = new CallStore();
	mCalls->setCallStatCounters(&findStat(countCallsStr), &findStat(countCallsFinishedStr));
	mServer = new MediaRelayServer(ag->getBindIp(), ag->getPublicIp());
	mSdpMangledParam = modconf->get<ConfigString>("nortpproxy")->read();
}

bool MediaRelay::processNewInvite(const shared_ptr<RelayedCall> &c, const shared_ptr<OutgoingTransaction>& transaction, const shared_ptr<MsgSip> &msgSip) {
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
		c->addBack(transaction);

		// Translate
		m->iterate(bind(&RelayedCall::forwardTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3, ref(transaction)));

		m->addAttribute(mSdpMangledParam.c_str(), "yes");
		m->update(msg, sip);

		mServer->update();

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

void MediaRelay::process200OkforInvite(const shared_ptr<RelayedCall> &c, const shared_ptr<OutgoingTransaction>& transaction, const shared_ptr<MsgSip> &msgSip) {
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

	c->update(transaction);

	m->iterate(bind(&RelayedCall::backwardTranslate, c, placeholders::_1, placeholders::_2, placeholders::_3));

	m->update(msg, sip);

	delete m;
}

void MediaRelay::onResponse(shared_ptr<SipEvent> &ev) {
	shared_ptr<MsgSip> ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
	msg_t *msg = ms->getMsg();

	// Handle SipEvent associated with a Stateful transaction
	shared_ptr<OutgoingTransaction> transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
	if (transaction != NULL) {
		shared_ptr<RelayedCall> c = transaction->getProperty<RelayedCall>(getModuleName());
		if (c != NULL) {
			if (sip->sip_cseq && sip->sip_cseq->cs_method == sip_method_invite) {
				fixAuthChallengeForSDP(ms->getHome(), msg, sip);
				if (sip->sip_status->st_status == 200 || isEarlyMedia(sip)) {
					process200OkforInvite(c, transaction, ev->getMsgSip());
					if (sip->sip_status->st_status == 200)
						c->validBack(transaction);
				}
			}
			return;
		}
	}
}

void MediaRelay::onTransactionEvent(const shared_ptr<Transaction> &transaction, Transaction::Event event) {
	shared_ptr<RelayedCall> c = transaction->getProperty<RelayedCall>(getModuleName());
	if (c != NULL) {
		shared_ptr<OutgoingTransaction> ot = dynamic_pointer_cast<OutgoingTransaction>(transaction);
		if (ot != NULL) {
			switch (event) {
			case Transaction::Destroy:
				if (c->removeBack(transaction)) {
					mCalls->remove(c);
				}
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
