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
	static void send480KO(Agent *agent, shared_ptr<RequestSipEvent> &ev);
	static void send200Ok(Agent *agent, shared_ptr<RequestSipEvent> &ev, const sip_contact_t *contacts);
	void routeRequest(Agent *agent, shared_ptr<RequestSipEvent> &ev, Record *aorb, const string &sipUri);
	void onRegister(Agent *agent, shared_ptr<RequestSipEvent> &ev, sip_contact_t *ct, Record *aorb, const string &sipUri);

	Registrar(Agent *ag) : Module(ag),mStaticRecordsTimer(NULL) {
		sRegistrarInstanceForSigAction=this;
		memset(&mSigaction, 0, sizeof(mSigaction));
	}

	~Registrar() {
	}

	virtual void onDeclare(GenericStruct *mc) {
		ConfigItemDescriptor configs[] = { { StringList, "reg-domains", "List of whitelist separated domain names to be managed by the registrar.", "localhost" },
				{ Integer, "max-contacts-by-aor", "Maximum number of registered contacts of an address of record.", "15" },
				{ String, "line-field-name", "Name of the contact uri parameter used for identifying user's device. ", "line" },
				{ String, "static-records-file", "File containing the static records to add to database at startup. "
				"Format: one 'sip_uri contact_header' by line. "
				"Ex1: <sip:contact@domain> <sip:127.0.0.1:5460>,<sip:192.168.0.1:5160>", "" },
				{ Integer, "static-records-timeout", "Timeout in seconds after which the static records file is re-read and the contacts updated.", "600" },

				{	String , "db-implementation", "Implementation used for storing address of records contact uris. [redis-async, redis-sync, internal]","internal"},
#ifdef ENABLE_REDIS
				{	String , "redis-server-domain", "Domain of the redis server. ","localhost"},
				{	Integer , "redis-server-port", "Port of the redis server.","6379"},
				{	String , "redis-auth-password", "Authentication password for redis. Empty to disable.",""},
				{	Integer , "redis-server-timeout", "Timeout in milliseconds of the redis connection.","1500"},
				{	String , "redis-record-serializer", "Implementation of the contact serialiser to use. [C, protobuf]","protobuf"},
#endif
				{ Boolean, "fork", "Fork messages to all registered devices", "true" },
				{ Boolean, "fork-late", "Fork invites to late registers", "false" },
				{ Boolean, "fork-one-response", "Only forward one response of forked invite to the caller", "true" },
				{ Boolean, "fork-no-global-decline", "All the forked have to decline in order to decline the caller invite", "false" },
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

		mCountNonForks = mc->createStat("count-non-forked", "Number of non forked invites.");
		mCountLocalActives = mc->createStat("count-local-registered-users", "Number of users currently registered through this server.");
	}

	virtual void onLoad(const GenericStruct *mc) {
		list<string>::const_iterator it;
		mDomains = mc->get<ConfigStringList>("reg-domains")->read();
		for (it = mDomains.begin(); it != mDomains.end(); ++it) {
			LOGD("Found registrar domain: %s", (*it).c_str());
		}
		mFork = mc->get<ConfigBoolean>("fork")->read();
		mGeneratedContactRoute = mc->get<ConfigString>("generated-contact-route")->read();
		mExpectedRealm = mc->get<ConfigString>("generated-contact-expected-realm")->read();
		mStaticRecordsFile = mc->get<ConfigString>("static-records-file")->read();
		mStaticRecordsTimeout = mc->get<ConfigInt>("static-records-timeout")->read();
		mForkCfg=make_shared<ForkContextConfig>();
		mForkCfg->mForkOneResponse = mc->get<ConfigBoolean>("fork-one-response")->read();
		mForkCfg->mForkNoGlobalDecline = mc->get<ConfigBoolean>("fork-no-global-decline")->read();
		mForkCfg->mForkLate = mc->get<ConfigBoolean>("fork-late")->read();
		if (!mStaticRecordsFile.empty()) {
			readStaticRecords();
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
	static int getMainDelta(sip_expires_t *expires) {
		int delta = 3600;
		if (expires) {
			delta = expires->ex_delta;
			if (delta < 30 && delta > 0) {
				delta = 30;
			} else if (delta > 3600 * 24) {
				delta = 3600 * 24;
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
		db->mLocalRegExpire->removeExpiredBefore(time(NULL));
		mCountLocalActives->set(db->mLocalRegExpire->countActives());
	}
	bool isManagedDomain(const char *domain) {
		return ModuleToolbox::matchesOneOf(domain, mDomains);
	}
	void readStaticRecords();
	bool contactUrlInVia(const url_t *ct_url, sip_via_t * via);
	bool dispatch(Agent *agent, const shared_ptr<RequestSipEvent> &ev, sip_contact_t *ct, const char *route, shared_ptr<ForkContext> context = shared_ptr<ForkContext>());
	list<string> mDomains;
	bool mFork;
	shared_ptr<ForkContextConfig> mForkCfg;
	typedef multimap<string, shared_ptr<ForkContext>> ForkMap;
	ForkMap mForks;
	string mGeneratedContactRoute;
	string mExpectedRealm;
	string mStaticRecordsFile;
	su_timer_t *mStaticRecordsTimer;
	int mStaticRecordsTimeout;
	struct sigaction mSigaction;
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
			size_t start = line.find_first_of('<');
			size_t pos = line.find_first_of('>');
			if (start != string::npos && pos != string::npos && start < pos) {
				if (line[pos + 1] == ' ') {
					// Read from
					from = line.substr(start + 1, pos - (start + 1));

					// Read contacts
					pos++;
					contact_header = line.substr(pos, line.length() - pos);

					// Create
					url_t *url = url_make(&home, from.c_str());
					sip_contact_t *contact = sip_contact_make(&home, contact_header.c_str());
					int expire=mStaticRecordsTimeout+5; // 5s to avoid race conditions

					if (url != NULL && contact != NULL) {
						auto listener=make_shared<OnStaticBindListener>(getAgent(), line);
						bool alias=isManagedDomain(url->url_host);
						RegistrarDb::get(mAgent)->bind(url, contact, fakeCallId, version, NULL, expire, alias, listener);
						continue;
					}
				}
			}
			LOGW("Incorrect line format: %s", line.c_str());
		}
		su_home_deinit(&home);
	} else {
		LOGE("Can't open file %s", mStaticRecordsFile.c_str());
	}

}

void Registrar::send480KO(Agent *agent, shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	ev->reply(ms, 480, "Temporarily Unavailable", SIPTAG_SERVER_STR(agent->getServerString()), TAG_END());
}

void Registrar::send200Ok(Agent *agent, shared_ptr<RequestSipEvent> &ev, const sip_contact_t *contacts) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	if (contacts != NULL) {
		ev->reply(ms, 200, "Registration successful", SIPTAG_CONTACT(contacts), SIPTAG_SERVER_STR(agent->getServerString()), TAG_END());
	} else {
		ev->reply(ms, 200, "Registration successful", SIPTAG_SERVER_STR(agent->getServerString()), TAG_END());
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

bool Registrar::dispatch(Agent *agent, const shared_ptr<RequestSipEvent> &ev, sip_contact_t *ct, const char *route, shared_ptr<ForkContext> context) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
	/*sanity check on the contact address: might be '*' or whatever useless information*/
	if (ct->m_url[0].url_host != NULL && ct->m_url[0].url_host[0] != '\0') {
		char *contact_url_string = url_as_string(ms->getHome(), ct->m_url);
		if (!contactUrlInVia(ct->m_url, sip->sip_via)) {
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
				prependRoute(msg_home(new_msg), agent, new_msg, new_sip, route);
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
			agent->injectRequestEvent(new_ev);
			return true;
		} else {
			LOGW("Contact %s is already routed", contact_url_string);
		}
	} else {
		LOGW("Unrouted request because of incorrect address of contact");
	}
	return false;
}

void Registrar::onRegister(Agent *agent, shared_ptr<RequestSipEvent> &ev, sip_contact_t *ct, Record *aor, const string &sipUri) {
	if (mForkCfg->mForkLate) {
		// Find all contexts
		pair<ForkMap::iterator, ForkMap::iterator> range = mForks.equal_range(sipUri);

		// First use sipURI
		for(auto it = range.first; it != range.second; ++it) {
			shared_ptr<ForkContext> context = it->second;
			if (!context->hasFinalResponse()){
				LOGD("Found a pending context for contact %s: %p", sipUri.c_str(), context.get());
				dispatch(agent, context->getEvent(), ct, NULL, context);
			}
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
							if (!context->hasFinalResponse()){
								LOGD("Found a pending context for contact %s: %p", uri.c_str(), context.get());
								dispatch(agent, context->getEvent(), ct, NULL, context);
							}
						}
					}
				}
			}
		}
	}
}

void Registrar::routeRequest(Agent *agent, shared_ptr<RequestSipEvent> &ev, Record *aor, const string &sipUri) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();

	std::list<std::shared_ptr<ExtendedContact>> contacts;

	if (!aor && mGeneratedContactRoute.empty()) {
		LOGD("This user isn't registered (no aor).");
		ev->reply(ms, SIP_404_NOT_FOUND, SIPTAG_SERVER_STR(agent->getServerString()), TAG_END());
		return;
	}

	// _Copy_ list of extended contacts
	if (aor)
		contacts = aor->getExtendedContacts();

	time_t now = time(NULL);

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
				agent->injectRequestEvent(ev);
				return;
			}
		} else {
			LOGD("Authorization header %s found", nextProxyRealm);
		}
		contacts.push_back(gwECt);
		LOGD("Added generated contact to %s@%s through %s", to->url_user, to->url_host, mGeneratedContactRoute.c_str());
	}

	if (contacts.size() > 0) {
		bool handled = false;
		bool fork = !(!mFork || (contacts.size() <= 1 && !mForkCfg->mForkLate) || (
				ms->getSip()->sip_request->rq_method != sip_method_invite &&
				ms->getSip()->sip_request->rq_method != sip_method_message
				));
		if (fork) {
			++*mCountForks;
		} else {
			++*mCountNonForks;
		}

		// Init context if needed
		shared_ptr<ForkContext> context;
		shared_ptr<IncomingTransaction> incoming_transaction;
		if (fork) {
			if (sip->sip_request->rq_method == sip_method_invite) {
				context = make_shared<ForkCallContext>(agent, ev, mForkCfg, this);
			} else if (sip->sip_request->rq_method == sip_method_message) {
				context = make_shared<ForkMessageContext>(agent, ev, mForkCfg, this);
			}
			if (context.get() != NULL) {
				mForks.insert(pair<string, shared_ptr<ForkContext>>(sipUri, context));
				LOGD("Add fork %p to store %s", context.get(), sipUri.c_str());
				incoming_transaction = ev->createIncomingTransaction();
				incoming_transaction->setProperty<ForkContext>(Registrar::sInfo.getModuleName(), context);
				context->onNew(incoming_transaction);
			} else {
				LOGW("Can't create fork for method %s", sip->sip_request->rq_method_name);
				fork = false;
			}
		}

		for (auto it = contacts.begin(); it != contacts.end(); ++it) {
			const shared_ptr<ExtendedContact> ec = *it;
			sip_contact_t *ct = NULL;
			if (ec)
				ct = Record::extendedContactToSofia(ms->getHome(), *ec, now);
			if (!ec->mAlias) {
				if (ct) {
					if (ec->mRoute != NULL && 0 != strcmp(agent->getPreferredRoute().c_str(), ec->mRoute)) {
						if (dispatch(agent, ev, ct, ec->mRoute, context)) {
							handled++;
							if (!fork)
								break;
						}
					} else {
						if (dispatch(agent, ev, ct, NULL, context)) {
							handled++;
							if (!fork)
								break;
						}
					}
				} else {
					LOGW("Can't create sip_contact of %s.", ec->mSipUri);
				}
			} else {
				if (fork) {
					mForks.insert(pair<string, shared_ptr<ForkContext>>(ec->mSipUri, context));
					LOGD("Add fork %p to store %s", context.get(), ec->mSipUri);
				}
			}
		}

		if (handled > 0) {
			if (fork) {
				shared_ptr<ResponseSipEvent> new_ev(make_shared<ResponseSipEvent>(ev->getOutgoingAgent(), incoming_transaction->createResponse(SIP_100_TRYING)));
				new_ev->setIncomingAgent(incoming_transaction);
				agent->sendResponseEvent(new_ev);
				ev->terminateProcessing();
			}
			return;
		} else {
			LOGD("This user isn't registered (no valid contact).");
		}
	} else {
		LOGD("This user isn't registered (no contact).");
	}

	ev->reply(ms, SIP_404_NOT_FOUND, SIPTAG_SERVER_STR(agent->getServerString()), TAG_END());
}

// Listener class NEED to copy the shared pointer
class OnBindListener: public RegistrarDbListener {
	Registrar *mModule;
	shared_ptr<RequestSipEvent> mEv;
	string mSipUri;
	su_home_t mHome;
	sip_contact_t *mContact;
public:
	OnBindListener(Registrar *module, shared_ptr<RequestSipEvent> ev, const string &sipuri = string(), sip_contact_t *contact = NULL) :
			mModule(module), mEv(ev), mSipUri(sipuri), mContact(NULL) {
		ev->suspendProcessing();
		su_home_init(&mHome);
		mContact = sip_contact_copy(&mHome, contact);
	}
	~OnBindListener() {
		su_home_deinit(&mHome);
	}
	void onRecordFound(Record *r) {
		const shared_ptr<MsgSip> &ms = mEv->getMsgSip();
		time_t now = time(NULL);
		Registrar::send200Ok(mModule->getAgent(), mEv, r->getContacts(ms->getHome(), now));
		mModule->onRegister(mModule->getAgent(), mEv, mContact, r, mSipUri);
	}
	void onError() {
		Registrar::send480KO(mModule->getAgent(), mEv);
	}
};

// Listener class NEED to copy the shared pointer
class OnBindForRoutingListener: public RegistrarDbListener {
	friend class Registrar;
	Registrar *mModule;
	shared_ptr<RequestSipEvent> mEv;
	string mSipUri;
public:
	OnBindForRoutingListener(Registrar *module, shared_ptr<RequestSipEvent> ev, const string &sipuri) :
			mModule(module), mEv(ev), mSipUri(sipuri) {
		ev->suspendProcessing();
	}
	;
	void onRecordFound(Record *r) {
		mModule->routeRequest(mModule->getAgent(), mEv, r, mSipUri);
	}
	void onError() {
		Registrar::send480KO(mModule->getAgent(), mEv);
	}
};

static bool isIpv6(const char *c) {
	if (!c) return false;
	while (*c != '\0') {
		if (*c == ':' || (*c >= 'a' && *c <= 'f') || (*c >= '0' && *c<='9'))
			++c;
		else
			return false;
	}
	return true;
}

static bool isIpv4(const char *c) {
	if (!c) return false;
	while (*c != '\0') {
		if (*c == '.' || (*c >= '0' && *c<='9'))
			++c;
		else
			return false;
	}
	return true;
}

void Registrar::onRequest(shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();

	// Handle SipEvent associated with a Stateful transaction
	shared_ptr<IncomingTransaction> transaction = dynamic_pointer_cast<IncomingTransaction>(ev->getIncomingAgent());
	if (transaction != NULL) {
		shared_ptr<ForkContext> ptr = transaction->getProperty<ForkContext>(getModuleName());
		if (ptr != NULL) {
			ptr->onRequest(transaction, ev);
		}
	}

	if (sip->sip_request->rq_method == sip_method_register) {
		url_t *sipurl = sip->sip_from->a_url;
		if (sipurl->url_host && isManagedDomain(sipurl->url_host)) {
			sip_expires_t *expires = sip->sip_expires;
			int maindelta = getMainDelta(expires);
			if (sip->sip_contact != NULL) {
				if (!checkStarUse(sip->sip_contact, maindelta)) {
					LOGD("The star rules are not respected.");
					ev->reply(ms, 400, "Invalid Request", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
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
					char *url = url_as_string(ms->getHome(), sipurl);
					shared_ptr<OnBindListener> listener(make_shared<OnBindListener>(this, ev, url, sip->sip_contact));
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
		if (sip->sip_request->rq_method != sip_method_ack && sip->sip_to != NULL && sip->sip_to->a_tag == NULL) {
			url_t *sipurl = sip->sip_request->rq_url;
			if (sipurl->url_host && isManagedDomain(sipurl->url_host)) {
				char *url = url_as_string(ms->getHome(), sipurl);
				LOGD("Fetch %s.", url);
				RegistrarDb::get(mAgent)->fetch(sipurl, make_shared<OnBindForRoutingListener>(this, ev, url), true);
			}
		}
		if (sip->sip_request->rq_method == sip_method_ack) {
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
			if (!routeAck && !isIpv4(req_host) && !isIpv6(req_host)) {
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
	shared_ptr<ForkContext> ptr = transaction->getProperty<ForkContext>(getModuleName());
	if (ptr != NULL) {
		shared_ptr<OutgoingTransaction> ot = dynamic_pointer_cast<OutgoingTransaction>(transaction);
		if (ot != NULL) {
			switch (event) {
			case Transaction::Destroy:
				ptr->onDestroy(ot);
				break;

			case Transaction::Create:
				ptr->onNew(ot);
				break;
			}
		}
		shared_ptr<IncomingTransaction> it = dynamic_pointer_cast<IncomingTransaction>(transaction);
		if (it != NULL) {
			switch (event) {
			case Transaction::Destroy:
				ptr->onDestroy(it);
				break;

			case Transaction::Create: // Can't happen because property is set after this event
				break;
			}
		}
		
	}
}

void Registrar::onForkContextFinished(shared_ptr<ForkContext> ctx){
	for (auto it = mForks.begin(); it != mForks.end(); ++it) {
		if (it->second == ctx) {
			LOGD("Remove fork %s from store", it->first.c_str());
			it=mForks.erase(it);
			break;
		}
	}
	
}

ModuleInfo<Registrar> Registrar::sInfo("Registrar", "The Registrar module accepts REGISTERs for domains it manages, and store the address of record "
		"in order to route other requests destinated to the client who registered.",
		ModuleInfoBase::ModuleOid::Registrar);

