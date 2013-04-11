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

#include <sofia-sip/sip_status.h>
#include <fstream>
#include <csignal>

using namespace ::std;

class Registrar;
static Registrar *sRegistrarInstanceForSigAction=NULL;

class FakeFetchListener: public RegistrarDbListener {
	friend class Registrar;
public:
	FakeFetchListener() {
	}
	void onRecordFound(Record *r) {
		if (r!=NULL) {
			r->print();
		} else {
			LOGD("No record found");
		}
	}
	void onError() {
	}
};

class Registrar: public Module, public ModuleToolbox, public ForkContextListener{
	friend class OnBindListener;
	StatCounter64 *mCountBind;
	StatCounter64 *mCountBindFinished;
	StatCounter64 *mCountForks;
	StatCounter64 *mCountForkTransactions;
	StatCounter64 *mCountForkTransactionsFinished;
	StatCounter64 *mCountForksFinished;
	StatCounter64 *mCountNonForks;
	StatCounter64 *mCountClear;
	StatCounter64 *mCountClearFinished;
	StatCounter64 *mCountLocalActives;
	bool rewriteContactUrl(const shared_ptr<MsgSip> &ms, const url_t *ct_url, const char *route);
	static void staticRoutesRereadTimerfunc(su_root_magic_t *magic, su_timer_t *t, void *data){
		Registrar *r=(Registrar *)data;
		r->readStaticRecords();
	}
public:
	void sendReply(shared_ptr<RequestSipEvent> &ev, int code, const char *reason, const sip_contact_t *contacts=NULL);
	void routeRequest(shared_ptr<RequestSipEvent> &ev, Record *aorb, const url_t *sipUri);
	void onRegister(shared_ptr<RequestSipEvent> &ev, sip_contact_t *ct, Record *aorb, const url_t* sipUri);

	Registrar(Agent *ag) : Module(ag),mStaticRecordsTimer(NULL) {
		sRegistrarInstanceForSigAction=this;
		memset(&mSigaction, 0, sizeof(mSigaction));
	}

	~Registrar() {
	}

	virtual void onDeclare(GenericStruct *mc) {
		ConfigItemDescriptor configs[] = { { StringList, "reg-domains", "List of whitelist separated domain names to be managed by the registrar.", "localhost" },
				{ Integer, "max-contacts-by-aor", "Maximum number of registered contacts of an address of record.", "15" },
				{ StringList, "unique-id-parameters", "List of contact uri parameters that can be used to identify a user's device. "
						"The contact parameters are searched in the order of the list, the first matching parameter is used and the others ignored.", "line" },
				{ Integer, "max-expires"	, "Maximum expire time for a REGISTER, in seconds.", "86400" },
				{ Integer, "min-expires"	, "Minimum expire time for a REGISTER, in seconds.", "60" },
				{ String, "static-records-file", "File containing the static records to add to database at startup. "
				"Format: one 'sip_uri contact_header' by line. Example:\n"
				"<sip:contact@domain> <sip:127.0.0.1:5460>,<sip:192.168.0.1:5160>", "" },
				{ Integer, "static-records-timeout", "Timeout in seconds after which the static records file is re-read and the contacts updated.", "600" },

				{	String , "db-implementation", "Implementation used for storing address of records contact uris. [redis-async, redis-sync, internal]","internal"},
				{	Boolean , "use-global-domain", "Store and retrieve contacts without using the domain.","false"},
#ifdef ENABLE_REDIS
				{	String , "redis-server-domain", "Domain of the redis server. ","localhost"},
				{	Integer , "redis-server-port", "Port of the redis server.","6379"},
				{	String , "redis-auth-password", "Authentication password for redis. Empty to disable.",""},
				{	Integer , "redis-server-timeout", "Timeout in milliseconds of the redis connection.","1500"},
				{	String , "redis-record-serializer", "Implementation of the contact serialiser to use. [C, protobuf]","protobuf"},
#endif
				{ Boolean, "fork", "Fork messages to all registered devices", "true" },
				{ Boolean, "stateful", "Force forking and thus the creation of an outgoing transaction even when only one contact found", "true" },
				{ Boolean, "fork-late", "Fork invites to late registers", "false" },
				{ Boolean, "fork-one-response", "Only forward one response of forked invite to the caller", "true" },
				{ Boolean, "fork-no-global-decline", "All the forked have to decline in order to decline the caller invite", "false" },
				{ Boolean, "treat-decline-as-urgent", "Treat 603 Declined answers as urgent. Only relevant if fork-no-global-decline is set to true.", "false"}, 
				{ Integer, "call-fork-timeout", "Maximum time for a call fork to try to reach a callee, in seconds.","90"},
				{ Integer, "call-fork-urgent-timeout", "Maximum time before delivering urgent responses during a call fork, in seconds. "
					"The typical fork process requires to wait the best response from all branches before transmitting it to the client. "
					"However some error responses are retryable immediately (like 415 unsupported media, 401, 407) thus it is painful for the client to need to wait the end of the transaction time (32 seconds) for these error codes.", "5" },
				{ Integer , "message-delivery-timeout", "Maximum duration for delivering a message (text)","3600"},
				{	String, "generated-contact-route" , "Generate a contact from the TO header and route it to the above destination. [sip:host:port]", ""},
				{	String, "generated-contact-expected-realm" , "Require presence of authorization header for specified realm. [Realm]", ""},
				config_item_end };
		mc->addChildrenValues(configs);

		auto p = mc->createStatPair("count-clear", "Number of cleared registrations.");
		mCountClear = p.first;
		mCountClearFinished = p.second;

		p = mc->createStatPair("count-bind", "Number of registers.");
		mCountBind = p.first;
		mCountBindFinished = p.second;

		p = mc->createStatPair("count-forks", "Number of forks");
		mCountForks = p.first;
		mCountForksFinished = p.second;

		p = mc->createStatPair("count-fork-transactions", "Number of outgoing transaction created for forking");
		mCountForkTransactions = p.first;
		mCountForkTransactionsFinished = p.second;

		mCountNonForks = mc->createStat("count-non-forked", "Number of non forked invites.");
		mCountLocalActives = mc->createStat("count-local-registered-users", "Number of users currently registered through this server.");
	}

	virtual void onLoad(const GenericStruct *mc) {
		list<string>::const_iterator it;
		mDomains = mc->get<ConfigStringList>("reg-domains")->read();
		for (it = mDomains.begin(); it != mDomains.end(); ++it) {
			LOGD("Found registrar domain: %s", (*it).c_str());
		}
		mStateful=mc->get<ConfigBoolean>("stateful");
		mFork = mc->get<ConfigBoolean>("fork")->read();
		if (mStateful && !mFork) {
			LOGI("Stateful registrar imply fork=true");
			mFork=true;
		}
		mMaxExpires = mc->get<ConfigInt>("max-expires")->read();
		mMinExpires = mc->get<ConfigInt>("min-expires")->read();
		mGeneratedContactRoute = mc->get<ConfigString>("generated-contact-route")->read();
		mExpectedRealm = mc->get<ConfigString>("generated-contact-expected-realm")->read();
		mStaticRecordsFile = mc->get<ConfigString>("static-records-file")->read();
		mStaticRecordsTimeout = mc->get<ConfigInt>("static-records-timeout")->read();
		mForkCfg=make_shared<ForkContextConfig>();
		mMessageForkCfg=make_shared<ForkContextConfig>();
		mForkCfg->mForkOneResponse = mc->get<ConfigBoolean>("fork-one-response")->read();
		mForkCfg->mForkNoGlobalDecline = mc->get<ConfigBoolean>("fork-no-global-decline")->read();
		mForkCfg->mUrgentTimeout = mc->get<ConfigInt>("call-fork-urgent-timeout")->read();
		mForkCfg->mDeliveryTimeout = mc->get<ConfigInt>("call-fork-timeout")->read();
		mForkCfg->mTreatDeclineAsUrgent = mc->get<ConfigBoolean>("treat-decline-as-urgent")->read();
		
		mMessageForkCfg->mForkLate=mForkCfg->mForkLate = mc->get<ConfigBoolean>("fork-late")->read();
		mMessageForkCfg->mDeliveryTimeout = mc->get<ConfigInt>("message-delivery-timeout")->read();
		mUseGlobalDomain=mc->get<ConfigBoolean>("use-global-domain")->read();
		RegistrarDb::get(mAgent)->useGlobalDomain(mUseGlobalDomain);

		if (!mStaticRecordsFile.empty()) {
			readStaticRecords(); // read static records from configuration file
			mStaticRecordsTimer=mAgent->createTimer(mStaticRecordsTimeout*1000, &staticRoutesRereadTimerfunc,this);
		}
		mSigaction.sa_sigaction = Registrar::sighandler;
		mSigaction.sa_flags = SA_SIGINFO;
		sigaction(SIGUSR1, &mSigaction, NULL);
		sigaction(SIGUSR2, &mSigaction, NULL);
	}

	virtual void onUnload() {
		if (mStaticRecordsTimer) {
			su_timer_destroy(mStaticRecordsTimer);
		}
		Record::setStaticRecordsVersion(0);
	}

	// Delta from expires header, normalized with custom rules.
	unsigned int getMainDelta(sip_expires_t *expires) {
		unsigned int delta = mMaxExpires;
		if (expires) {
			delta = expires->ex_delta;
			if (delta < mMinExpires && delta > 0) {
				delta = mMinExpires;
			} else if (delta > mMaxExpires) {
				delta = mMaxExpires;
			}
		}
		return delta;
	}

	// Check star rules.
	// If *, it must be the only contact.
	// If *, associated expire must be 0.
	static bool checkStarUse(const sip_contact_t *contact, int expires) {
		bool starFound = false;
		int count = 0;
		do {
			if (starFound) {
				return false;
			}

			++count;
			if ('*' == contact->m_url[0].url_scheme[0]) {
				if (count > 1 || 0 != expires)
					return false;
				starFound = true;
			}
		} while (NULL != (contact = contact->m_next));
		return true;
	}

	virtual void onRequest(shared_ptr<RequestSipEvent> &ev);

	virtual void onResponse(shared_ptr<ResponseSipEvent> &ev);

	virtual void onTransactionEvent(const shared_ptr<Transaction> &transaction, Transaction::Event event);

	void idle() { updateLocalRegExpire(); }
	
	virtual void onForkContextFinished(shared_ptr<ForkContext> ctx);

private:
	void updateLocalRegExpire() {
		RegistrarDb *db = RegistrarDb::get(mAgent);
		db->mLocalRegExpire->removeExpiredBefore(getCurrentTime());
		mCountLocalActives->set(db->mLocalRegExpire->countActives());
	}
	bool isManagedDomain(const url_t *url) {
		bool check=ModuleToolbox::matchesOneOf(url->url_host, mDomains);
		if (check){
			//additional check: if the domain is an ip address that is not this proxy, then it is not considered as a managed domain for the registrar.
			//we need this to distinguish requests that needs registrar routing from already routed requests.
			if (ModuleToolbox::isNumeric(url->url_host) && !getAgent()->isUs(url,true)){
				check=false;
			}
		}
		return check;
	}
	void readStaticRecords();
	bool contactUrlInVia(const url_t *ct_url, sip_via_t * via);
	bool dispatch(const shared_ptr<RequestSipEvent> &ev, sip_contact_t *ct, const char *route, shared_ptr<ForkContext> context = shared_ptr<ForkContext>());
	list<string> mDomains;
	bool mFork;
	shared_ptr<ForkContextConfig> mForkCfg;
	shared_ptr<ForkContextConfig> mMessageForkCfg;
	typedef multimap<string, shared_ptr<ForkContext>> ForkMap;
	ForkMap mForks;
	unsigned int mMaxExpires, mMinExpires;
	string mGeneratedContactRoute;
	string mExpectedRealm;
	string mStaticRecordsFile;
	su_timer_t *mStaticRecordsTimer;
	int mStaticRecordsTimeout;
	struct sigaction mSigaction;
	bool mUseGlobalDomain;
	bool mStateful;
	static void sighandler(int signum, siginfo_t *info, void *ptr) {
		if (signum == SIGUSR1) {
			LOGI("Received signal triggering static records file re-read");
			sRegistrarInstanceForSigAction->readStaticRecords();
		} else if (signum == SIGUSR2) {
			LOGI("Received signal triggering fake fetch");
			su_home_t home;
			su_home_init(&home);
			url_t *url=url_make(&home, "sip:contact@domain");

			auto listener=make_shared<FakeFetchListener>();
			RegistrarDb::get(sRegistrarInstanceForSigAction->getAgent())->fetch(url, listener, false);
		}
	}

	static ModuleInfo<Registrar> sInfo;
};

// Listener class NEED to copy the shared pointer
class OnStaticBindListener: public RegistrarDbListener {
	friend class Registrar;
	Agent *agent;
	string line;
public:
	OnStaticBindListener(Agent *agent, const string& line) :
			agent(agent), line(line) {
	}
	void onRecordFound(Record *r) {
		LOGD("Static route added: %s", line.c_str());
	}
	void onError() {
		LOGE("Can't add static route: %s", line.c_str());
	}
};

void Registrar::readStaticRecords() {
	static int version=0;
	if (mStaticRecordsFile.empty()) return;
	LOGD("Reading static records file");

	su_home_t home;

	stringstream ss;
	ss.exceptions(ifstream::failbit | ifstream::badbit);

	string line;
	string from;
	string contact_header;

	ifstream file;
	file.open(mStaticRecordsFile);
	if (file.is_open()) {
		su_home_init(&home);
		++version;
		const char *fakeCallId=su_sprintf(&home,"static-record-v%d",version);
		Record::setStaticRecordsVersion(version);
		while (file.good() && getline(file, line).good()) {
			size_t i;
			bool is_a_comment=false;
			for(i=0;i<line.size();++i){
				//skip spaces or comments
				if (isblank(line[i])) continue;
				if (line[i]=='#') is_a_comment=true;
				else break;
			}
			if (is_a_comment) continue;
			if (i==line.size()) continue; //blank line
			size_t cttpos = line.find_first_of(' ',i);
			if (cttpos != string::npos && cttpos < line.size()) {
				// Read uri
				from = line.substr(0, cttpos);

				// Read contacts
				contact_header = line.substr(cttpos+1, line.length() - cttpos+1);

				// Create
				sip_contact_t *url = sip_contact_make(&home, from.c_str());
				sip_contact_t *contact = sip_contact_make(&home, contact_header.c_str());
				int expire=mStaticRecordsTimeout+5; // 5s to avoid race conditions

				if (url != NULL && contact != NULL) {
					auto listener=make_shared<OnStaticBindListener>(getAgent(), line);
					bool alias=isManagedDomain(contact->m_url);
					RegistrarDb::get(mAgent)->bind(url->m_url, contact, fakeCallId, version, NULL, expire, alias, listener);
					continue;
				}
			}
			LOGW("Incorrect line format: %s", line.c_str());
		}
		su_home_deinit(&home);
	} else {
		LOGE("Can't open file %s", mStaticRecordsFile.c_str());
	}

}

void Registrar::sendReply(shared_ptr<RequestSipEvent> &ev, int code, const char *reason, const sip_contact_t *contacts) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip=ms->getSip();
	
	if (sip->sip_request->rq_method==sip_method_invite){
		shared_ptr<CallLog> clog=ev->getEventLog<CallLog>();
		if (clog){
			clog->setStatusCode(code,reason);
			clog->setCompleted();
		}
	}
	
	if (contacts != NULL) {
		ev->reply(ms, code, reason, SIPTAG_CONTACT(contacts), SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	} else {
		ev->reply(ms, code, reason, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	}
}

/**
 * Check if the contact is in one via.
 * Avoid to check a contact information that already known
 */
bool Registrar::contactUrlInVia(const url_t *url, sip_via_t * via) {

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

bool Registrar::rewriteContactUrl(const shared_ptr<MsgSip> &ms, const url_t *ct_url, const char *route) {
	sip_t *sip=ms->getSip();
	su_home_t *home=ms->getHome();

	if (!contactUrlInVia(ct_url, sip->sip_via)) {
		/*sanity check on the contact address: might be '*' or whatever useless information*/
		if (ct_url->url_host != NULL && ct_url->url_host[0] != '\0') {
			LOGD("Registrar: found contact information in database, rewriting request uri");
			/*rewrite request-uri */
			sip->sip_request->rq_url[0] = *url_hdup(home, ct_url);
			if (route && 0 != strcmp(mAgent->getPreferredRoute().c_str(), route)) {
				LOGD("This flexisip instance is not responsible for contact %s:%s:%s -> %s",
						ct_url->url_user?ct_url->url_user:"",
						ct_url->url_host?ct_url->url_host:"",
						ct_url->url_params?ct_url->url_params:"",
						route);
				prependRoute(home, mAgent, ms->getMsg(), sip, route);
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

bool Registrar::dispatch(const shared_ptr<RequestSipEvent> &ev, sip_contact_t *ct, const char *route, shared_ptr<ForkContext> context) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
	/*sanity check on the contact address: might be '*' or whatever useless information*/
	if (ct->m_url[0].url_host != NULL && ct->m_url[0].url_host[0] != '\0') {
		if (IS_LOGD && contactUrlInVia(ct->m_url, sip->sip_via)) {
			LOGD("Contact url in vias, the message will be routed backward");
		}
		char *contact_url_string = url_as_string(ms->getHome(), ct->m_url);
		shared_ptr<MsgSip> new_msgsip;
		if (context) {
			new_msgsip = make_shared<MsgSip>(*ms);
		} else {
			new_msgsip = ms;
		}
		msg_t *new_msg = new_msgsip->getMsg();
		sip_t *new_sip = new_msgsip->getSip();

		/* Rewrite request-uri */
		new_sip->sip_request->rq_url[0] = *url_hdup(msg_home(new_msg), ct->m_url);
		if (route != NULL) {
			LOGD("This flexisip instance is not responsible for contact %s -> %s",contact_url_string, route);
			prependRoute(msg_home(new_msg),getAgent(), new_msg, new_sip, route);
		}

		shared_ptr<RequestSipEvent> new_ev;
		if (context) {
			shared_ptr<RequestSipEvent> req_ev = make_shared<RequestSipEvent>(ev);
			req_ev->setMsgSip(new_msgsip);
			shared_ptr<OutgoingTransaction> transaction = req_ev->createOutgoingTransaction();
			transaction->setProperty(Registrar::sInfo.getModuleName(), context);

			new_ev = req_ev;
			LOGD("Fork to %s", contact_url_string);
		} else {
			new_ev = ev;
			LOGD("Dispatch to %s", contact_url_string);
		}

		/* Back to work */
		getAgent()->injectRequestEvent(new_ev);
		return true;
	} else {
		LOGW("Unrouted request because of incorrect address of contact");
	}
	return false;
}

void Registrar::onRegister(shared_ptr<RequestSipEvent> &ev, sip_contact_t *ct, Record *aor, const url_t * sipUri) {
	sip_expires_t *expires=ev->getMsgSip()->getSip()->sip_expires;
	if ((mForkCfg->mForkLate || mMessageForkCfg->mForkLate) && expires && expires->ex_delta>0
		&& ct && sipUri) {
		char sipUriRef[256]={0};
		url_t urlcopy=*sipUri;
		
		if (mUseGlobalDomain){
			urlcopy.url_host="merged";
		}
		url_e(sipUriRef,sizeof(sipUriRef)-1,&urlcopy);
		
		// Find all contexts
		pair<ForkMap::iterator, ForkMap::iterator> range = mForks.equal_range(sipUriRef);

		// First use sipURI
		for(auto it = range.first; it != range.second; ++it) {
			shared_ptr<ForkContext> context = it->second;
			if (context->onNewRegister(ct)){
				LOGD("Found a pending context for user %s: %p", sipUriRef, context.get());
				dispatch( context->getEvent(), ct, NULL, context);
			}else LOGD("Found a pending context but not interested in this new register.");
		}

		// If not found find in aliases
		if (aor != NULL) {
			const auto contacts = aor->getExtendedContacts();
			for (auto it = contacts.begin(); it != contacts.end(); ++it) {
				const shared_ptr<ExtendedContact> ec = *it;
				if (ec) {
					if (ec->mAlias) {
						const std::string uri = ec->mSipUri;
						// Find all contexts
						pair<ForkMap::iterator, ForkMap::iterator> range = mForks.equal_range(uri);
						for(auto it = range.first; it != range.second; ++it) {
							shared_ptr<ForkContext> context = it->second;
							if (context->onNewRegister(ct)){
								LOGD("Found a pending context for contact %s: %p", uri.c_str(), context.get());
								dispatch(context->getEvent(), ct, NULL, context);
							}
						}
					}
				}
			}
		}
	}
}

void Registrar::routeRequest(shared_ptr<RequestSipEvent> &ev, Record *aor, const url_t *sipUri) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
	char sipUriRef[256]={0};
	std::list<std::shared_ptr<ExtendedContact>> contacts;
	std::list<std::shared_ptr<ExtendedContact>> contact;
	
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
	if (!mGeneratedContactRoute.empty()) {
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
				getAgent()->injectRequestEvent(ev);
				return;
			}
		} else {
			LOGD("Authorization header %s found", nextProxyRealm);
		}
		contacts.push_back(gwECt);
		LOGD("Added generated contact to %s@%s through %s", to->url_user, to->url_host, mGeneratedContactRoute.c_str());
	}

	if (contacts.size() > 0) {
		int handled = 0;
		bool dontfork = !mFork // forking disabled
				|| (contacts.size() <= 1 && !mForkCfg->mForkLate && !mStateful) // not forced
				|| !(
				ms->getSip()->sip_request->rq_method == sip_method_invite ||
				ms->getSip()->sip_request->rq_method == sip_method_message
				); // method is not correct
		if (dontfork) {
			++*mCountNonForks;
		} else {
			++*mCountForks;
		}

		// Init context if needed
		shared_ptr<ForkContext> context;
		shared_ptr<IncomingTransaction> incoming_transaction;
		if (!dontfork) {
			if (sip->sip_request->rq_method == sip_method_invite) {
				context = make_shared<ForkCallContext>(getAgent(), ev, mForkCfg, this);
			} else if (sip->sip_request->rq_method == sip_method_message) {
				context = make_shared<ForkMessageContext>(getAgent(), ev, mMessageForkCfg, this);
			}
			if (context) {
				url_t modified_uri=*sipUri;
				
				if (mUseGlobalDomain){
					modified_uri.url_host="merged";
				}
				url_e(sipUriRef,sizeof(sipUriRef)-1,&modified_uri);
				mForks.insert(make_pair(sipUriRef, context));
				LOGD("Add fork %p to store with key '%s'", context.get(), sipUriRef);
				incoming_transaction = ev->createIncomingTransaction();
				incoming_transaction->setProperty<ForkContext>(Registrar::sInfo.getModuleName(), context);
				context->onNew(incoming_transaction);
			} else {
				LOGW("Can't create fork for method %s", sip->sip_request->rq_method_name);
				dontfork = true;
			}
		}

		for (auto it = contacts.begin(); it != contacts.end(); ++it) {
			const shared_ptr<ExtendedContact> ec = *it;
			sip_contact_t *ct = NULL;
			if (ec)
				ct = Record::extendedContactToSofia(ms->getHome(), *ec, now);
			if (!ec->mAlias) {
				if (ct) {
					if (ec->mRoute != NULL && 0 != strcmp(getAgent()->getPreferredRoute().c_str(), ec->mRoute)) {
						if (dispatch(ev, ct, ec->mRoute, context)) {
							handled++;
							if (dontfork) break;
						}
					} else {
						if (dispatch(ev, ct, NULL, context)) {
							handled++;
							if (dontfork) break;
						}
					}
				} else {
					LOGW("Can't create sip_contact of %s.", ec->mSipUri);
				}
			} else {
				if (isManagedDomain(ct->m_url)) {
					if (!dontfork) {
						sip_contact_t *temp_ctt=sip_contact_make(ms->getHome(),ec->mSipUri);
						
						if (mUseGlobalDomain){
							temp_ctt->m_url->url_host="merged";
							temp_ctt->m_url->url_port=NULL;
						}
						url_e(sipUriRef,sizeof(sipUriRef)-1,temp_ctt->m_url);
						mForks.insert(make_pair(sipUriRef, context));
						LOGD("Add fork %p to store with key '%s' because it is an alias", context.get(), sipUriRef);
					}
				}else{
					if (dispatch(ev, ct, NULL, context)) {
						handled++;
						if (dontfork) break;
					}
				}
			}
		}

		if (handled > 0) {
			if (!dontfork) {
				shared_ptr<ResponseSipEvent> new_ev(make_shared<ResponseSipEvent>(ev->getOutgoingAgent(), incoming_transaction->createResponse(SIP_100_TRYING)));
				new_ev->setIncomingAgent(incoming_transaction);
				getAgent()->sendResponseEvent(new_ev);
				ev->terminateProcessing();
			}
			return;
		} else {
			LOGD("This user isn't registered (no valid contact).");
		}
	} else {
		LOGD("This user isn't registered (no contact at all).");
	}
	sendReply(ev,SIP_404_NOT_FOUND);
}

// Listener class NEED to copy the shared pointer
class OnBindListener: public RegistrarDbListener {
	Registrar *mModule;
	shared_ptr<RequestSipEvent> mEv;
	sip_from_t * mSipFrom;
	su_home_t mHome;
	sip_contact_t *mContact;
public:
	OnBindListener(Registrar *module, shared_ptr<RequestSipEvent> ev, const sip_from_t* sipuri = NULL, sip_contact_t *contact = NULL) :
			mModule(module), mEv(ev), mSipFrom(NULL), mContact(NULL) {
		ev->suspendProcessing();
		su_home_init(&mHome);
		if (contact)
			mContact = sip_contact_copy(&mHome, contact);
		if (sipuri){
			mSipFrom=sip_from_dup(&mHome,sipuri);
		}
	}
	~OnBindListener() {
		su_home_deinit(&mHome);
	}
	void onRecordFound(Record *r) {
		const shared_ptr<MsgSip> &ms = mEv->getMsgSip();
		time_t now = getCurrentTime();
		if (r){
			mModule->sendReply(mEv, 200, "Registration successful", r->getContacts(ms->getHome(), now));
			mModule->onRegister(mEv, mContact, r, mSipFrom->a_url);
			RegistrationLog::Type type;
			if (ms->getSip()->sip_expires && ms->getSip()->sip_expires->ex_delta==0) type=RegistrationLog::Unregister; //REVISIT not 100% exact.
			else type=RegistrationLog::Register;
			auto evlog=make_shared<RegistrationLog>(type,mSipFrom,Record::extractUniqueId(mContact),mContact);
			if (ms->getSip()->sip_user_agent) evlog->setUserAgent(ms->getSip()->sip_user_agent);
			evlog->setCompleted();
			mEv->setEventLog(evlog);
		}else{
			LOGE("OnBindListener::onRecordFound(): Record is null");
			mModule->sendReply(mEv,SIP_480_TEMPORARILY_UNAVAILABLE);
		}
	}
	void onError() {
		mModule->sendReply(mEv, SIP_500_INTERNAL_SERVER_ERROR);
	}
};

// Listener class NEED to copy the shared pointer
class OnBindForRoutingListener: public RegistrarDbListener {
	friend class Registrar;
	Registrar *mModule;
	shared_ptr<RequestSipEvent> mEv;
	url_t *mSipUri;
public:
	OnBindForRoutingListener(Registrar *module, shared_ptr<RequestSipEvent> ev, const url_t *sipuri) :
			mModule(module), mEv(ev) {
		ev->suspendProcessing();
		mSipUri=url_hdup(mEv->getMsgSip()->getHome(),sipuri);
		sip_t *sip=ev->getMsgSip()->getSip();
		if (sip->sip_request->rq_method==sip_method_invite){
			ev->setEventLog(make_shared<CallLog>(sip->sip_from,sip->sip_to));
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

void Registrar::onRequest(shared_ptr<RequestSipEvent> &ev) {
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

	if (sip->sip_request->rq_method == sip_method_register) {
		url_t *sipurl = sip->sip_from->a_url;
		if (sipurl->url_host && isManagedDomain(sipurl)) {
			sip_expires_t *expires = sip->sip_expires;
			int maindelta = getMainDelta(expires);
			if (sip->sip_contact != NULL) {
				if (!checkStarUse(sip->sip_contact, maindelta)) {
					LOGD("The star rules are not respected.");
					sendReply(ev,400, "Invalid Request");
					return;
				}
				if ('*' == sip->sip_contact->m_url[0].url_scheme[0]) {
					shared_ptr<OnBindListener> listener(make_shared<OnBindListener>(this, ev));
					++*mCountClear;
					LOGD("Clearing bindings");
					listener->addStatCounter(mCountClearFinished);
					RegistrarDb::get(mAgent)->clear(sip, listener);
					return;
				} else {
					shared_ptr<OnBindListener> listener(make_shared<OnBindListener>(this, ev, sip->sip_from, sip->sip_contact));
					++*mCountBind;
					LOGD("Updating binding");
					listener->addStatCounter(mCountBindFinished);
					RegistrarDb::get(mAgent)->bind(sip, mAgent->getPreferredRoute().c_str(), maindelta, false, listener);
					;
					return;
				}
				LOGD("Records binded to registrar database.");
			} else {
				LOGD("No sip contact, it is a fetch only request for %s.", url_as_string(ms->getHome(), sipurl));
				RegistrarDb::get(mAgent)->fetch(sipurl, make_shared<OnBindListener>(this, ev));
				return;
			}
		}
	} else {
		/*see if we can route other requests */
		/*acks shall not have their request uri rewritten:
		 - they can be for us (in response to a 407 for invite)
		 - they can be for the a remote peer, in which case they will have the correct contact address in the request uri
		 */
		/* When we accept * as domain we need to test ip4/ipv6 */
		if (sip->sip_request->rq_method != sip_method_ack && sip->sip_to != NULL && sip->sip_to->a_tag == NULL) {
			url_t *sipurl = sip->sip_request->rq_url;
			if (sipurl->url_host  && isManagedDomain(sipurl)) {
				char *url = url_as_string(ms->getHome(), sipurl);
				LOGD("Fetch %s.", url);
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
}

void Registrar::onResponse(shared_ptr<ResponseSipEvent> &ev) {
	// Handle SipEvent associated with a Stateful transaction
	shared_ptr<OutgoingTransaction> transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
	if (transaction != NULL) {
		shared_ptr<ForkContext> ptr = transaction->getProperty<ForkContext>(getModuleName());
		if (ptr != NULL) {
			ptr->onResponse(transaction, ev);
		}
	}
}

void Registrar::onTransactionEvent(const shared_ptr<Transaction> &transaction, Transaction::Event event) {
	shared_ptr<ForkContext> forkContext = transaction->getProperty<ForkContext>(getModuleName());
	if (forkContext != NULL) {
		shared_ptr<OutgoingTransaction> ot = dynamic_pointer_cast<OutgoingTransaction>(transaction);
		if (ot != NULL) {
			switch (event) {
			case Transaction::Destroy:
				forkContext->onDestroy(ot);
				++*mCountForkTransactionsFinished;
				break;

			case Transaction::Create:
				forkContext->onNew(ot);
				++*mCountForkTransactions;
				break;
			}
		}
		shared_ptr<IncomingTransaction> it = dynamic_pointer_cast<IncomingTransaction>(transaction);
		if (it != NULL) {
			switch (event) {
			case Transaction::Destroy:
				forkContext->onDestroy(it);
				break;

			case Transaction::Create: // Can't happen because property is set after this event
				break;
			}
		}
		
	}
}

void Registrar::onForkContextFinished(shared_ptr<ForkContext> ctx){
	for (auto it = mForks.begin(); it != mForks.end();) {
		if (it->second == ctx) {
			LOGD("Remove fork %s from store", it->first.c_str());
			++*mCountForksFinished;
			auto cur_it=it;
			++it;
			//for some reason the multimap erase does not return the next iterator !
			mForks.erase(cur_it);
			//do not break, because a single fork context might appear several time in the map because of aliases.
		}else ++it;
	}
	
}

ModuleInfo<Registrar> Registrar::sInfo("Registrar", "The Registrar module accepts REGISTERs for domains it manages, and store the address of record "
		"in order to route other requests destinated to the client who registered.",
		ModuleInfoBase::ModuleOid::Registrar);

