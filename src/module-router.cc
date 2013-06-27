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
#include "registrardb.hh"
#include "forkcallcontext.hh"
#include "forkmessagecontext.hh"
#include "forkbasiccontext.hh"
#include "log/logmanager.hh"
#include <sofia-sip/sip_status.h>

#include "lateforkapplier.hh"

using namespace ::std;

class ModuleRouter;


struct RouterStats {
	unique_ptr<StatPair> mCountForks;
	unique_ptr<StatPair> mCountForkTransactions;
	StatCounter64 *mCountNonForks;
	StatCounter64 *mCountLocalActives;	
};

class ModuleRouter: public Module, public ModuleToolbox, public ForkContextListener{
	friend class LateForkApplier;
	RouterStats mStats;
	bool rewriteContactUrl(const shared_ptr<MsgSip> &ms, const url_t *ct_url, const char *route);
public:
	void sendReply(shared_ptr<RequestSipEvent> &ev, int code, const char *reason);
	void routeRequest(shared_ptr<RequestSipEvent> &ev, Record *aorb, const url_t *sipUri);
	void onContactRegistered(const sip_contact_t *ct, const sip_path_t *path, Record *aor, const url_t * sipUri);

	ModuleRouter(Agent *ag) : Module(ag) {
	}

	~ModuleRouter() {
	}

	virtual void onDeclare(GenericStruct *mc) {
		ConfigItemDescriptor configs[] = {
			{ Boolean , "use-global-domain", "Store and retrieve contacts without using the domain.","false"},
			{ Boolean, "fork", "Fork messages to all registered devices", "true" },
			{ Boolean, "stateful", "Force forking and thus the creation of an outgoing transaction even when only one contact found", "true" },
			{ Boolean, "fork-late", "Fork invites to late registers", "false" },
			{ Boolean, "fork-no-global-decline", "All the forked have to decline in order to decline the caller invite", "false" },
			{ Boolean, "treat-decline-as-urgent", "Treat 603 Declined answers as urgent. Only relevant if fork-no-global-decline is set to true.", "false"}, 
			{ Integer, "call-fork-timeout", "Maximum time for a call fork to try to reach a callee, in seconds.","90"},
			{ Integer, "call-fork-urgent-timeout", "Maximum time before delivering urgent responses during a call fork, in seconds. "
				"The typical fork process requires to wait the best response from all branches before transmitting it to the client. "
				"However some error responses are retryable immediately (like 415 unsupported media, 401, 407) thus it is painful for the client to need to wait the end of the transaction time (32 seconds) for these error codes.", "5" },
			{ Integer , "message-delivery-timeout", "Maximum duration for delivering a message (text)","3600"},
			{ String, "generated-contact-route" , "Generate a contact from the TO header and route it to the above destination. [sip:host:port]", ""},
			{ String, "generated-contact-expected-realm" , "Require presence of authorization header for specified realm. [Realm]", ""},
			{ Boolean, "generate-contact-even-on-filled-aor", "Generate a contact route even on filled AOR.", "false"},
			{ Boolean, "fork-one-response", "Only forward one response of forked invite to the caller", "true" },
			{ Boolean, "remove-to-tag", "Remove to tag from 183, 180, and 101 responses to workaround buggy gateways", "false" },
			config_item_end
		};
		mc->addChildrenValues(configs);

		mStats.mCountForks = mc->createStats("count-forks", "Number of forks");
		mStats.mCountForkTransactions = mc->createStats("count-fork-transactions", "Number of outgoing transaction created for forking");

		mStats.mCountNonForks = mc->createStat("count-non-forked", "Number of non forked invites.");
		mStats.mCountLocalActives = mc->createStat("count-local-registered-users", "Number of users currently registered through this server.");
	}

	virtual void onLoad(const GenericStruct *mc) {
		GenericStruct *cr=GenericManager::get()->getRoot();
		const GenericStruct *mReg=cr->get<GenericStruct>("module::Registrar");
	
		mDomains = mReg->get<ConfigStringList>("reg-domains")->read();
		for (auto it = mDomains.begin(); it != mDomains.end(); ++it) {
			LOGD("Found registrar domain: %s", (*it).c_str());
		}
		mStateful=mc->get<ConfigBoolean>("stateful");
		mFork = mc->get<ConfigBoolean>("fork")->read();
		if (mStateful && !mFork) {
			LOGI("Stateful router implies fork=true");
			mFork=true;
		}
		mGeneratedContactRoute = mc->get<ConfigString>("generated-contact-route")->read();
		mExpectedRealm = mc->get<ConfigString>("generated-contact-expected-realm")->read();
		mGenerateContactEvenOnFilledAor = mc->get<ConfigBoolean>("generate-contact-even-on-filled-aor")->read();
		mForkCfg=make_shared<ForkContextConfig>();
		mMessageForkCfg=make_shared<ForkContextConfig>();
		mForkCfg->mForkOneResponse = mc->get<ConfigBoolean>("fork-one-response")->read();
		mForkCfg->mForkNoGlobalDecline = mc->get<ConfigBoolean>("fork-no-global-decline")->read();
		mForkCfg->mUrgentTimeout = mc->get<ConfigInt>("call-fork-urgent-timeout")->read();
		mForkCfg->mDeliveryTimeout = mc->get<ConfigInt>("call-fork-timeout")->read();
		mForkCfg->mTreatDeclineAsUrgent = mc->get<ConfigBoolean>("treat-decline-as-urgent")->read();
		mForkCfg->mRemoveToTag = mc->get<ConfigBoolean>("remove-to-tag")->read();

		mMessageForkCfg->mForkLate=mForkCfg->mForkLate = mc->get<ConfigBoolean>("fork-late")->read();
		mMessageForkCfg->mDeliveryTimeout = mc->get<ConfigInt>("message-delivery-timeout")->read();
		mOtherForkCfg=make_shared<ForkContextConfig>();
		mOtherForkCfg->mForkOneResponse=true;
		mOtherForkCfg->mForkLate=false;
		mOtherForkCfg->mDeliveryTimeout=30;
		
		
		mUseGlobalDomain=mc->get<ConfigBoolean>("use-global-domain")->read();
		RegistrarDb::get(mAgent)->useGlobalDomain(mUseGlobalDomain);
	}

	virtual void onUnload() {
	}

	virtual void onRequest(shared_ptr<RequestSipEvent> &ev);

	virtual void onResponse(shared_ptr<ResponseSipEvent> &ev);

	virtual void onTransactionEvent(shared_ptr<TransactionEvent> ev);

	virtual void onForkContextFinished(shared_ptr<ForkContext> ctx);

private:
	bool isManagedDomain(const url_t *url) {
		return ModuleToolbox::isManagedDomain(getAgent(), mDomains, url);
	}
	bool dispatch(const shared_ptr<RequestSipEvent> &ev, const sip_contact_t *ct, const list<string> &path, shared_ptr<ForkContext> context = shared_ptr<ForkContext>());
	string routingKey(const url_t* sipUri) {
		ostringstream oss;
		if (sipUri->url_user) {
			oss << sipUri->url_user << "@";
		}
		if (mUseGlobalDomain){
			oss << "merged";
		} else {
			oss << sipUri->url_host;
		}
		return oss.str();
	}
	list<string> mDomains;
	bool mFork;
	shared_ptr<ForkContextConfig> mForkCfg;
	shared_ptr<ForkContextConfig> mMessageForkCfg;
	shared_ptr<ForkContextConfig> mOtherForkCfg;
	typedef multimap<string, shared_ptr<ForkContext>> ForkMap;
	ForkMap mForks;
	string mGeneratedContactRoute;
	string mExpectedRealm;
	bool mUseGlobalDomain;
	bool mStateful;

	static ModuleInfo<ModuleRouter> sInfo;
	bool mGenerateContactEvenOnFilledAor;
};


void ModuleRouter::sendReply(shared_ptr<RequestSipEvent> &ev, int code, const char *reason) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip=ms->getSip();
	
	if (sip->sip_request->rq_method==sip_method_invite){
		shared_ptr<CallLog> clog=ev->getEventLog<CallLog>();
		if (clog){
			clog->setStatusCode(code,reason);
			clog->setCompleted();
		}
	}else if (sip->sip_request->rq_method==sip_method_message){
		shared_ptr<MessageLog> mlog=ev->getEventLog<MessageLog>();
		if (mlog){
			mlog->setStatusCode(code,reason);
			mlog->setCompleted();
		}
	}
	ev->reply(code, reason, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
}

/**
 * Check if the contact is in one via.
 * Avoid to check a contact information that already known
 */
static bool contactUrlInVia(const url_t *url, sip_via_t * via) {
	while (via != NULL) {
		if (via->v_host && url->url_host && !strcmp(via->v_host, url->url_host)) {
			const char *port1 = (via->v_port) ? via->v_port : "5060";
			const char *port2 = (url->url_port) ? url->url_port : "5060";
			if (!strcmp(port1, port2))
				return true;
		}
		via = via->v_next;
	}

	return false;
}

bool ModuleRouter::rewriteContactUrl(const shared_ptr<MsgSip> &ms, const url_t *ct_url, const char *route) {
	sip_t *sip=ms->getSip();
	su_home_t *home=ms->getHome();

	if (!contactUrlInVia(ct_url, sip->sip_via)) {
		/*sanity check on the contact address: might be '*' or whatever useless information*/
		if (ct_url->url_host != NULL && ct_url->url_host[0] != '\0') {
			LOGD("ModuleRouter: found contact information in database, rewriting request uri");
			/*rewrite request-uri */
			sip->sip_request->rq_url[0] = *url_hdup(home, ct_url);
			if (route && 0 != strcmp(mAgent->getPreferredRoute().c_str(), route)) {
				LOGD("This flexisip instance is not responsible for contact %s:%s:%s -> %s",
						ct_url->url_user?ct_url->url_user:"",
						ct_url->url_host?ct_url->url_host:"",
						ct_url->url_params?ct_url->url_params:"",
						route);
				cleanAndPrependRoute(home, mAgent, ms->getMsg(), sip, route);
			}
			// Back to work
			return true;
		} else {
			LOGW("Unrouted request because of incorrect address of record.");
		}
	} else {
		LOGW("Contact is already routed");
	}
	return false;
}

bool ModuleRouter::dispatch(const shared_ptr<RequestSipEvent> &ev, const sip_contact_t *ct, const list<string> &path, shared_ptr<ForkContext> context) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();

	/*sanity check on the contact address: might be '*' or whatever useless information*/
	if (ct->m_url[0].url_host == NULL || ct->m_url[0].url_host[0] == '\0') {
		LOGW("Unrouted request because of incorrect address of contact");
		return false;
	}

#if not(__GNUC__ == 4 && __GNUC_MINOR__ < 5 )
	sip_t *sip = ms->getSip();
	auto lambdaContactUrlInVia = [=]() {
		return contactUrlInVia(ct->m_url, sip->sip_via);
	};
	static auto lambdaMsg = [](flexisip_record_type &strm) {
		strm << "Contact url in vias, the message will be routed backward";
	};
	LOGDFN(lambdaContactUrlInVia, lambdaMsg);
#endif

	// not too expensive I guess when LOGD disabled
	char __attribute__ ((unused)) *contact_url_string = url_as_string(ms->getHome(), ct->m_url);
	auto new_msgsip = context ? make_shared<MsgSip>(*ms) : ms;
	msg_t *new_msg = new_msgsip->getMsg();
	sip_t *new_sip = new_msgsip->getSip();

	/* Rewrite request-uri */
	new_sip->sip_request->rq_url[0] = *url_hdup(msg_home(new_msg), ct->m_url);
	removeParamsFromUrl(msg_home(new_msg), new_sip->sip_request->rq_url, sPushNotifParams);

	// Convert path to routes
	new_sip->sip_route=NULL;
	cleanAndPrependRoutable(msg_home(new_msg),getAgent(), new_msg, new_sip, path);

	shared_ptr<RequestSipEvent> new_ev;
	if (context) {
		shared_ptr<RequestSipEvent> req_ev = make_shared<RequestSipEvent>(ev);
		req_ev->setMsgSip(new_msgsip);
		shared_ptr<OutgoingTransaction> transaction = req_ev->createOutgoingTransaction();
		transaction->setProperty(ModuleRouter::sInfo.getModuleName(), context);

		new_ev = req_ev;
		LOGD("Fork to %s", contact_url_string);
	} else {
		new_ev = ev;
		LOGD("Dispatch to %s", contact_url_string);
	}

	/* Back to work */
	getAgent()->injectRequestEvent(new_ev);
	return true;
}


void LateForkApplier::onContactRegistered(const Agent *agent, const sip_contact_t *ct, const sip_path_t *path, Record *aor, const url_t * sipUri) {
	ModuleRouter *module=(ModuleRouter*) agent->findModule(ModuleRouter::sInfo.getModuleName());
	module->onContactRegistered(ct, path, aor, sipUri);
}

void ModuleRouter::onContactRegistered(const sip_contact_t *ct, const sip_path_t *path, Record *aor, const url_t * sipUri) {
	SLOGD << "ModuleRouter::onContactRegistered";
	if (aor == NULL) {
		SLOGE << "aor was null...";
		return;
	}


	if (!mForkCfg->mForkLate && !mMessageForkCfg->mForkLate) return;
	if (!ct || !sipUri) return; // nothing to do


	char sipUriRef[256]={0};
	url_t urlcopy=*sipUri;
	
	if (mUseGlobalDomain){
		urlcopy.url_host="merged";
	}
	url_e(sipUriRef,sizeof(sipUriRef)-1,&urlcopy);
	
	// Find all contexts
	const string key(routingKey(sipUri));
	auto range = mForks.equal_range(key.c_str());
	SLOGD << "Searching for fork context with key " << key;

	// First use sipURI
	for(auto it = range.first; it != range.second; ++it) {
		shared_ptr<ForkContext> context = it->second;
		if (context->onNewRegister(ct)){
			SLOGD << "Found a pending context for key " << key << ": " << context.get();
			auto stlpath=Record::route_to_stl(context->getEvent()->getMsgSip()->getHome(), path);
			dispatch( context->getEvent(), ct, stlpath, context);
		}else LOGD("Found a pending context but not interested in this new register.");
	}

	// If not found find in aliases
	const auto contacts = aor->getExtendedContacts();
	for (auto it = contacts.begin(); it != contacts.end(); ++it) {
		const shared_ptr<ExtendedContact> ec = *it;
		if (!ec || !ec->mAlias) continue;

		// Find all contexts
		auto range = mForks.equal_range(ec->mSipUri);
		for(auto it = range.first; it != range.second; ++it) {
			shared_ptr<ForkContext> context = it->second;
			if (context->onNewRegister(ct)){
				LOGD("Found a pending context for contact %s: %p",
				     ec->mSipUri.c_str(), context.get());
				auto stlpath=Record::route_to_stl(context->getEvent()->getMsgSip()->getHome(), path);
				dispatch(context->getEvent(), ct, stlpath, context);
			}
		}
	}
}


void ModuleRouter::routeRequest(shared_ptr<RequestSipEvent> &ev, Record *aor, const url_t *sipUri) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
	char sipUriRef[256]={0};
	std::list<std::shared_ptr<ExtendedContact>> contacts;
	
	if (!aor && mGeneratedContactRoute.empty()) {
		LOGD("This user isn't registered (no aor).");
		sendReply(ev,SIP_404_NOT_FOUND);
		return;
	}

	// _Copy_ list of extended contacts
	if (aor)
		contacts = aor->getExtendedContacts();

	time_t now = getCurrentTime();

	// Generate a fake contact for a proxy
	if (!mGeneratedContactRoute.empty() && (!aor || mGenerateContactEvenOnFilledAor)) {
		const url_t *to = ms->getSip()->sip_to->a_url;
		const std::shared_ptr<ExtendedContact> gwECt(make_shared<ExtendedContact>(to, mGeneratedContactRoute.c_str()));

		// This contact is a proxy which will challenge us with a known Realm
		const char *nextProxyRealm = mExpectedRealm.empty() ? to->url_host : mExpectedRealm.c_str();
		if (ms->getSip()->sip_request->rq_method == sip_method_invite && !ModuleToolbox::findAuthorizationForRealm(ms->getHome(), sip->sip_proxy_authorization, nextProxyRealm)) {
			LOGD("No authorization header %s found in request, forwarding request only to proxy", nextProxyRealm);
			if (rewriteContactUrl(ms, to, mGeneratedContactRoute.c_str())) {
				shared_ptr<OutgoingTransaction> transaction = ev->createOutgoingTransaction();
				shared_ptr<string> thisProxyRealm(make_shared<string>(to->url_host));
				transaction->setProperty("this_proxy_realm", thisProxyRealm);
				ev->restartProcessing();
				return;
			}
		} else {
			LOGD("Authorization header %s found", nextProxyRealm);
		}
		contacts.push_back(gwECt);
		LOGD("Added generated contact to %s@%s through %s", to->url_user, to->url_host, mGeneratedContactRoute.c_str());
	}

	if (contacts.size() <= 0) {
		LOGD("This user isn't registered (no contact at all).");
		sendReply(ev,SIP_404_NOT_FOUND);
		return;
	}

	
	int handled = 0;
	
	if (!mFork) {
		mStats.mCountNonForks->incr();
	} else {
		mStats.mCountForks->incrStart();
	}

	// Init context if needed
	shared_ptr<ForkContext> context;
	if (mFork) {
		if (sip->sip_request->rq_method == sip_method_invite) {
			context = make_shared<ForkCallContext>(getAgent(), ev, mForkCfg, this);
		} else if (sip->sip_request->rq_method == sip_method_message) {
			context = make_shared<ForkMessageContext>(getAgent(), ev, mMessageForkCfg, this);
		} else {
			context = make_shared<ForkBasicContext>(getAgent(),ev,mOtherForkCfg,this);
		}
		if (context) {
			if (context->getConfig()->mForkLate){
				const string key(routingKey(sipUri));
				mForks.insert(make_pair(key, context));
				SLOGD << "Add fork " << context.get() << " to store with key '" << key << "'";
			}
			auto inTr = ev->createIncomingTransaction();
			inTr->setProperty<ForkContext>(ModuleRouter::sInfo.getModuleName(), context);
			context->onNew(inTr);
		}
	}

	for (auto it = contacts.begin(); it != contacts.end(); ++it) {
		const shared_ptr<ExtendedContact> ec = *it;
		sip_contact_t *ct = NULL;
		if (ec)
			ct = Record::extendedContactToSofia(ms->getHome(), *ec, now);
		if (!ec->mAlias) {
			if (ct) {
				if (dispatch(ev, ct, ec->mCommon.mPath, context)) {
					handled++;
					if (!mFork) break;
				}
			} else {
				SLOGW << "Can't create sip_contact of " << ec->mSipUri;
			}
		} else {
			if (mFork && context->getConfig()->mForkLate && isManagedDomain(ct->m_url)) {
				sip_contact_t *temp_ctt=sip_contact_make(ms->getHome(),ec->mSipUri.c_str());
				
				if (mUseGlobalDomain){
					temp_ctt->m_url->url_host="merged";
					temp_ctt->m_url->url_port=NULL;
				}
				url_e(sipUriRef,sizeof(sipUriRef)-1,temp_ctt->m_url);
				mForks.insert(make_pair(sipUriRef, context));
				LOGD("Add fork %p to store with key '%s' because it is an alias", context.get(), sipUriRef);
			}else{
				if (dispatch(ev, ct, ec->mCommon.mPath, context)) {
					handled++;
					if (!mFork) break;
				}
			}
		}
	}

	if (handled <= 0) {
		LOGD("This user isn't registered (no valid contact).");
		sendReply(ev,SIP_404_NOT_FOUND);
		return;
	}

	// Handled via a fork
	if (mFork) {
		sendReply(ev, SIP_100_TRYING);
		return;
	}

	// Let flow non forked handled message
}


// Listener class NEED to copy the shared pointer
class OnBindForRoutingListener: public RegistrarDbListener {
	friend class ModuleRouter;
	ModuleRouter *mModule;
	shared_ptr<RequestSipEvent> mEv;
	url_t *mSipUri;
public:
	OnBindForRoutingListener(ModuleRouter *module, shared_ptr<RequestSipEvent> ev, const url_t *sipuri) :
			mModule(module), mEv(ev) {
		ev->suspendProcessing();
		mSipUri=url_hdup(mEv->getMsgSip()->getHome(),sipuri);
		sip_t *sip=ev->getMsgSip()->getSip();
		if (sip->sip_request->rq_method==sip_method_invite){
			ev->setEventLog(make_shared<CallLog>(sip->sip_from,sip->sip_to));
		}else if (sip->sip_request->rq_method==sip_method_message){
			ev->setEventLog(make_shared<MessageLog>(MessageLog::Reception,sip->sip_from,sip->sip_to,sip->sip_call_id->i_hash));
		}
	}
	;
	void onRecordFound(Record *r) {
		mModule->routeRequest(mEv, r, mSipUri);
	}
	void onError() {
		mModule->sendReply(mEv,SIP_500_INTERNAL_SERVER_ERROR);
	}
};

void ModuleRouter::onRequest(shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();

	// Handle SipEvent associated with a Stateful transaction
	shared_ptr<IncomingTransaction> transaction = dynamic_pointer_cast<IncomingTransaction>(ev->getIncomingAgent());
	if (transaction != NULL) {
		shared_ptr<ForkContext> ptr = transaction->getProperty<ForkContext>(getModuleName());
		if (ptr != NULL) {
			ptr->onRequest(transaction, ev);
			if (ev->isTerminated()) return;
		}
	}

	// Don't route registers
	if (sip->sip_request->rq_method == sip_method_register) return;


	/*see if we can route other requests */
	/*acks shall not have their request uri rewritten:
		- they can be for us (in response to a 407 for invite)
		- they can be for the a remote peer, in which case they will have the correct contact address in the request uri
		*/
	/* When we accept * as domain we need to test ip4/ipv6 */
	if (sip->sip_request->rq_method != sip_method_ack && sip->sip_to != NULL && sip->sip_to->a_tag == NULL) {
		url_t *sipurl = sip->sip_request->rq_url;
		if (sipurl->url_host  && isManagedDomain(sipurl)) {
			LOGD("Fetch for url %s.", url_as_string(ms->getHome(), sipurl));
			RegistrarDb::get(mAgent)->fetch(sipurl, make_shared<OnBindForRoutingListener>(this, ev, sipurl), true);
		}
	}
	if (sip->sip_request->rq_method == sip_method_ack) {
		//Seems very complex: maybe it could be simpler.
		sip_route_t *route = sip->sip_route;
		bool routeAck=false;
		while (route) {
			if (!mAgent->isUs(route->r_url, true)) {
				routeAck=true;
				break;
			}
			route=route->r_next;
		}
		const char *req_host = sip->sip_request->rq_url->url_host;
		if (!routeAck && !ModuleToolbox::isNumeric(req_host)) {
			LOGD("We are the destination of this ACK, stopped.");
			ev->terminateProcessing();
			return;
		}
	}
}

void ModuleRouter::onResponse(shared_ptr<ResponseSipEvent> &ev) {
	// Handle SipEvent associated with a Stateful transaction
	shared_ptr<OutgoingTransaction> transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
	if (transaction != NULL) {
		shared_ptr<ForkContext> ptr = transaction->getProperty<ForkContext>(getModuleName());
		if (ptr != NULL) {
			ptr->onResponse(transaction, ev);
		}
	}
}

void ModuleRouter::onTransactionEvent(shared_ptr<TransactionEvent> ev) {
	shared_ptr<ForkContext> forkContext = ev->transaction->getProperty<ForkContext>(getModuleName());
	if (forkContext != NULL) {
		shared_ptr<OutgoingTransaction> ot = dynamic_pointer_cast<OutgoingTransaction>(ev->transaction);
		if (ot != NULL) {
			switch (ev->kind) {
				case TransactionEvent::Type::Destroy:
				forkContext->onDestroy(ot);
				mStats.mCountForkTransactions->incrFinish();
				break;

				case TransactionEvent::Type::Create:
				forkContext->onNew(ot);
				mStats.mCountForkTransactions->incrStart();
				break;
			}
		}
		shared_ptr<IncomingTransaction> it = dynamic_pointer_cast<IncomingTransaction>(ev->transaction);
		if (it != NULL) {
			switch (ev->kind) {
				case TransactionEvent::Type::Destroy:
					forkContext->onDestroy(it);
					break;
				case TransactionEvent::Type::Create: 
					SLOGW << "Can't happen because property is set after this event";
					break;
			}
		}
		
	}
}

void ModuleRouter::onForkContextFinished(shared_ptr<ForkContext> ctx){
	if (!ctx->getConfig()->mForkLate) return;
	for (auto it = mForks.begin(); it != mForks.end();) {
		if (it->second == ctx) {
			LOGD("Remove fork %s from store", it->first.c_str());
			mStats.mCountForks->incrFinish();
			auto cur_it=it;
			++it;
			//for some reason the multimap erase does not return the next iterator !
			mForks.erase(cur_it);
			//do not break, because a single fork context might appear several time in the map because of aliases.
		}else ++it;
	}
	
}

ModuleInfo<ModuleRouter> ModuleRouter::sInfo("Router",
		"The ModuleRouter module routes requests for domains it manages.",
		ModuleInfoBase::ModuleOid::Router);

