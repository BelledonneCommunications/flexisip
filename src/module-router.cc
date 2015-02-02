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
	friend struct LateForkApplier;
	RouterStats mStats;
	bool rewriteContactUrl(const shared_ptr<MsgSip> &ms, const url_t *ct_url, const char *route);
public:
	void sendReply(shared_ptr<RequestSipEvent> &ev, int code, const char *reason, int warn_code=0, const char *warning=NULL);
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
			{ Integer, "call-push-response-timeout", "Optional timer to detect lack of push response, in seconds.","0"},
			{ Integer , "message-delivery-timeout", "Maximum duration for delivering a text message","3600"},
			{ Integer , "message-accept-timeout", "Maximum duration for accepting a text message if no response is received from any recipients.","15"},
			{ String, "generated-contact-route" , "Generate a contact from the TO header and route it to the above destination. [sip:host:port]", ""},
			{ String, "generated-contact-expected-realm" , "Require presence of authorization header for specified realm. [Realm]", ""},
			{ Boolean, "generate-contact-even-on-filled-aor", "Generate a contact route even on filled AOR.", "false"},
			{ Boolean, "fork-one-response", "Only forward one response of forked invite to the caller", "true" },
			{ Boolean, "remove-to-tag", "Remove to tag from 183, 180, and 101 responses to workaround buggy gateways", "false" },
			{ String, "preroute" , "rewrite username with given value.", ""},
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
		mForkCfg->mPushResponseTimeout = mc->get<ConfigInt>("call-push-response-timeout")->read();
		mForkCfg->mDeliveryTimeout = mc->get<ConfigInt>("call-fork-timeout")->read();
		mForkCfg->mTreatDeclineAsUrgent = mc->get<ConfigBoolean>("treat-decline-as-urgent")->read();
		mForkCfg->mRemoveToTag = mc->get<ConfigBoolean>("remove-to-tag")->read();

		mMessageForkCfg->mForkLate=mForkCfg->mForkLate = mc->get<ConfigBoolean>("fork-late")->read();
		mMessageForkCfg->mDeliveryTimeout = mc->get<ConfigInt>("message-delivery-timeout")->read();
		mMessageForkCfg->mUrgentTimeout = mc->get<ConfigInt>("message-accept-timeout")->read();
		mOtherForkCfg=make_shared<ForkContextConfig>();
		mOtherForkCfg->mForkOneResponse=true;
		mOtherForkCfg->mForkLate=false;
		mOtherForkCfg->mDeliveryTimeout=30;

		mUseGlobalDomain=mc->get<ConfigBoolean>("use-global-domain")->read();

		mPreroute = mc->get<ConfigString>("preroute")->read();
	}

	virtual void onUnload() {
	}

	virtual void onRequest(shared_ptr<RequestSipEvent> &ev);

	virtual void onResponse(shared_ptr<ResponseSipEvent> &ev);

	virtual void onForkContextFinished(shared_ptr<ForkContext> ctx);

private:
	bool isManagedDomain(const url_t *url) {
		return ModuleToolbox::isManagedDomain(getAgent(), mDomains, url);
	}
	bool dispatch(const shared_ptr<RequestSipEvent> &ev, const url_t *dest, const string &uid, const list<string> &path, shared_ptr<ForkContext> context = shared_ptr<ForkContext>());
	string routingKey(const url_t* sipUri) {
		ostringstream oss;
		if (sipUri->url_user) {
			if (!mPreroute.empty() && strcmp(sipUri->url_user, mPreroute.c_str()) != 0) {
				oss << "merged" << "@"; // all users but preroute are merged
			} else {
				oss << sipUri->url_user << "@";
			}
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
	string mPreroute;
};


void ModuleRouter::sendReply(shared_ptr<RequestSipEvent> &ev, int code, const char *reason, int warn_code, const char *warning) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip=ms->getSip();
	sip_warning_t *warn=NULL;

	if (sip->sip_request->rq_method==sip_method_invite){
		shared_ptr<CallLog> calllog=ev->getEventLog<CallLog>();
		if (calllog){
			calllog->setStatusCode(code,reason);
			calllog->setCompleted();
		}
	}else if (sip->sip_request->rq_method==sip_method_message){
		shared_ptr<MessageLog> mlog=ev->getEventLog<MessageLog>();
		if (mlog){
			mlog->setStatusCode(code,reason);
			mlog->setCompleted();
		}
	}
	if (warn_code!=0){
		warn=sip_warning_format(ev->getHome(), "%i %s \"%s\"", warn_code, mAgent->getPublicIp().c_str(), warning);
	}
	if (warn){
		ev->reply(code, reason, SIPTAG_SERVER_STR(getAgent()->getServerString()),
			SIPTAG_WARNING(warn), TAG_END());
	}else{
		ev->reply(code, reason, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	}
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

bool ModuleRouter::dispatch(const shared_ptr< RequestSipEvent >& ev, const url_t* dest, const string &uid, const list< string >& path, shared_ptr< ForkContext > context) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();

	/*sanity check on the contact address: might be '*' or whatever useless information*/
	if (dest->url_host == NULL || dest->url_host[0] == '\0') {
		LOGW("Unrouted request because of incorrect address of contact");
		return false;
	}

#if ENABLE_BOOST_LOG && not(__GNUC__ == 4 && __GNUC_MINOR__ < 5 )
	sip_t *sip = ms->getSip();
	auto lambdaContactUrlInVia = [=]() {
		return contactUrlInVia(dest, sip->sip_via);
	};
	static auto lambdaMsg = [](flexisip_record_type &strm) {
		strm << "Contact url in vias, the message will be routed backward";
	};
	LOGDFN(lambdaContactUrlInVia, lambdaMsg);
#endif

	char *contact_url_string = url_as_string(ms->getHome(), dest);
	shared_ptr<RequestSipEvent> new_ev;
	if (context){
		//duplicate the SIP event
		new_ev=make_shared<RequestSipEvent>(ev);
	}else{
		new_ev=ev;
	}
	auto new_msgsip = new_ev->getMsgSip();
	msg_t *new_msg = new_msgsip->getMsg();
	sip_t *new_sip = new_msgsip->getSip();

	/* Rewrite request-uri */
	new_sip->sip_request->rq_url[0] = *url_hdup(msg_home(new_msg), dest);
	// the cleaning of push notif params will be done just before forward

	// Convert path to routes
	new_sip->sip_route=NULL;
	cleanAndPrependRoutable(msg_home(new_msg),getAgent(), new_msg, new_sip, path);

	if (context) {
		context->addBranch(new_ev,uid);
		SLOGD << "Fork to " << contact_url_string;
	} else {
		LOGD("Dispatch to %s", contact_url_string);
	}

	/* Back to work */
	getAgent()->injectRequestEvent(new_ev);
	return true;
}


void LateForkApplier::onContactRegistered(const Agent *agent, const sip_contact_t *ct, const sip_path_t *path, Record *aor, const url_t * sipUri) {
	ModuleRouter *module=dynamic_cast<ModuleRouter*> (agent->findModule(ModuleRouter::sInfo.getModuleName()));
	if (module && module->isEnabled()) module->onContactRegistered(ct, path, aor, sipUri);
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
		string uid=Record::extractUniqueId(ct);
		if (context->onNewRegister(ct->m_url,uid)){
			SLOGD << "Found a pending context for key " << key << ": " << context.get();
			auto stlpath=Record::route_to_stl(context->getEvent()->getMsgSip()->getHome(), path);
			dispatch( context->getEvent(), ct->m_url, uid, stlpath, context);
		}else LOGD("Found a pending context but not interested in this new register.");
	}

	// If not found find in aliases
	const auto contacts = aor->getExtendedContacts();
	for (auto it = contacts.begin(); it != contacts.end(); ++it) {
		const shared_ptr<ExtendedContact> ec = *it;
		if (!ec || !ec->mAlias) continue;

		// Find all contexts
		auto rang = mForks.equal_range(ec->mSipUri);
		for(auto ite = rang.first; ite != rang.second; ++ite) {
			shared_ptr<ForkContext> context = ite->second;
			string uid=Record::extractUniqueId(ct);
			if (context->onNewRegister(ct->m_url,uid)){
				LOGD("Found a pending context for contact %s: %p",
				     ec->mSipUri.c_str(), context.get());
				auto stlpath=Record::route_to_stl(context->getEvent()->getMsgSip()->getHome(), path);
				dispatch(context->getEvent(), ct->m_url, uid, stlpath, context);
			}
		}
	}
}


void ModuleRouter::routeRequest(shared_ptr<RequestSipEvent> &ev, Record *aor, const url_t *sipUri) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
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
				shared_ptr<RequestSipEvent> new_ev = make_shared<RequestSipEvent>(ev);
				getAgent()->injectRequestEvent(new_ev);
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
		} else if ((sip->sip_request->rq_method == sip_method_message)
			&& !(sip->sip_content_type != NULL
				&& strcasecmp(sip->sip_content_type->c_type, "application/im-iscomposing+xml") == 0)) {
			// Use the basic fork context for "im-iscomposing+xml" messages to prevent storing useless messages
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
		}
	}
	bool nonSipsFound=false;
	for (auto it = contacts.begin(); it != contacts.end(); ++it) {
		const shared_ptr<ExtendedContact> ec = *it;
		sip_contact_t *ct = ec->toSofia(ms->getHome(), now);
		if (!ct) {
			SLOGE << "Can't create sip_contact of " << ec->mSipUri;
			continue;
		}
		if (sip->sip_request->rq_url->url_type==url_sips && ct->m_url->url_type!=url_sips){
			/* https://tools.ietf.org/html/rfc5630 */
			nonSipsFound=true;
			LOGD("Not dispatching request to non-sips target.");
			continue;
		}
		if (!ec->mAlias) {
			if (dispatch(ev, ct->m_url, ec->mUniqueId, ec->mPath, context)) {
				handled++;
				if (!mFork) break;
			}
		} else {
			if (mFork && context->getConfig()->mForkLate && isManagedDomain(ct->m_url)) {
				sip_contact_t *temp_ctt=sip_contact_make(ms->getHome(),ec->mSipUri.c_str());

				if (mUseGlobalDomain){
					temp_ctt->m_url->url_host="merged";
					temp_ctt->m_url->url_port=NULL;
				}
				const string key(routingKey(temp_ctt->m_url));
				mForks.insert(make_pair(key, context));
				LOGD("Add fork %p to store with key '%s' because it is an alias", context.get(), key.c_str());
			}else{
				if (dispatch(ev, ct->m_url, ec->mUniqueId, ec->mPath, context)) {
					handled++;
					if (!mFork) break;
				}
			}
		}
	}

	if (handled <= 0) {
		if (!nonSipsFound){
			/*rfc5630 5.3*/
			sendReply(ev, SIP_480_TEMPORARILY_UNAVAILABLE, 380, "SIPS not allowed");
		}else{
			LOGD("This user isn't registered (no valid contact).");
			sendReply(ev,SIP_404_NOT_FOUND);
		}
	}

	// Let flow non forked handled message
}


class PreroutingFetcher:
public RegistrarDbListener,
public enable_shared_from_this<PreroutingFetcher>,
private ModuleToolbox {
	friend class ModuleRouter;
	ModuleRouter *mModule;
	shared_ptr<RequestSipEvent> mEv;
	shared_ptr<RegistrarDbListener> listerner;
	vector< string > mPreroutes;
	int pending;
	bool error;
	Record *m_record;
public:
	PreroutingFetcher(ModuleRouter *module, shared_ptr<RequestSipEvent> ev,
					  const shared_ptr<RegistrarDbListener> &listener, const vector<string> &preroutes) :
	mModule(module), mEv(ev), listerner(listener), mPreroutes(preroutes) {
		pending = 0;
		error = false;
		m_record= new Record("virtual_record");
	}

	~PreroutingFetcher() {
		delete (m_record);
	}

	void fetch() {
		const char *domain = mEv->getSip()->sip_to->a_url->url_host;
		if (isNumeric(domain)) SLOGE << "Not handled: to is ip at " << __LINE__;

		pending += mPreroutes.size();
		for (auto it = mPreroutes.cbegin(); it != mPreroutes.cend(); ++it) {
			url_t *target = url_format(mEv->getHome(), "sip:%s@%s", it->c_str(), domain);
			RegistrarDb::get(mModule->getAgent())->fetch(target, this->shared_from_this(), true);
		}
	}

	void onRecordFound(Record *r) {
		--pending;
		if (r != NULL) {
			const auto &ctlist = r->getExtendedContacts();
			for (auto it = ctlist.begin(); it != ctlist.end(); ++it)
				m_record->pushContact(*it);
		}
		checkFinished();
	}
	void onError() {
		--pending;
		error = true;
		checkFinished();
	}

	void checkFinished() {
		if (pending != 0) return;
		if (error) listerner->onError();
		else listerner->onRecordFound(m_record);
	}
};


class OnFetchForRoutingListener: public RegistrarDbListener {
	friend class ModuleRouter;
	ModuleRouter *mModule;
	shared_ptr<RequestSipEvent> mEv;
	url_t *mSipUri;
public:
	OnFetchForRoutingListener(ModuleRouter *module, shared_ptr<RequestSipEvent> ev, const url_t *sipuri) :
			mModule(module), mEv(ev) {
		ev->suspendProcessing();
		mSipUri=url_hdup(mEv->getMsgSip()->getHome(),sipuri);
		sip_t *sip=ev->getMsgSip()->getSip();
		if (sip->sip_request->rq_method==sip_method_invite){
			ev->setEventLog(make_shared<CallLog>(sip->sip_from,sip->sip_to));
		}
	}
	void onRecordFound(Record *r) {
		mModule->routeRequest(mEv, r, mSipUri);
	}
	void onError() {
		mModule->sendReply(mEv,SIP_500_INTERNAL_SERVER_ERROR);
	}
};

static vector<string> split(const char *data, const char *delim) {
	const char* p;
	vector<string> res;
	char *s = strdup(data);
	char *saveptr=NULL;
	for (p = strtok_r( s, delim, &saveptr );  p;  p = strtok_r( NULL, delim, &saveptr )) {
		res.push_back(p);
	}
	free(s);
	return res;
}

void ModuleRouter::onRequest(shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();

	// Handle SipEvent associated with a Stateful transaction
	if (sip->sip_request->rq_method==sip_method_cancel){
		ForkContext::processCancel(ev);
		return;
	}

	if (sip->sip_route != NULL && !getAgent()->isUs(sip->sip_route->r_url)) {
		SLOGD << "Route header found " << url_as_string(ms->getHome(), sip->sip_route->r_url) << " but not us, skipping";
		return;
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
			// Go stateful to stop retransmissions
			ev->createIncomingTransaction();
			sendReply(ev, SIP_100_TRYING);
			auto onRoutingListener = make_shared<OnFetchForRoutingListener>(this, ev, sipurl);
			if (mPreroute.empty()) {
				RegistrarDb::get(mAgent)->fetch(sipurl, onRoutingListener, true);
			} else {
				char preroute_param[20];
				if (url_param(sipurl->url_params, "preroute", preroute_param, sizeof(preroute_param))) {
					if (strchr(preroute_param, '@')) {
						SLOGE << "Prerouting contains at symbol" << preroute_param;
						return;
					}
					SLOGD << "Prerouting to provided " << preroute_param;
					vector<string> tokens = split(preroute_param, ":");
					auto prFetcher = make_shared<PreroutingFetcher>(this, ev, onRoutingListener, tokens);
					prFetcher->fetch();
				} else {
					SLOGD << "Prerouting to " << mPreroute;
					url_t *prerouteUrl = url_format(ev->getHome(), "sip:%s@%s",
													mPreroute.c_str(), sipurl->url_host);
					RegistrarDb::get(mAgent)->fetch(prerouteUrl, onRoutingListener, true);
				}
			}
		}
	}
}

void ModuleRouter::onResponse(shared_ptr<ResponseSipEvent> &ev) {
	ForkContext::processResponse(ev);
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

