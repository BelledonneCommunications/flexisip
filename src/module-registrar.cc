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

#include <sofia-sip/sip_status.h>
#include <fstream>

using namespace ::std;

class Registrar: public Module, public ModuleToolbox {
	StatCounter64 *mCountBind;
	StatCounter64 *mCountBindFinished;
	StatCounter64 *mCountForks;
	StatCounter64 *mCountForksFinished;
	StatCounter64 *mCountNonForks;
	StatCounter64 *mCountClear;
	StatCounter64 *mCountClearFinished;
	StatCounter64 *mCountLocalActives;
	bool rewriteContactUrl(const shared_ptr<MsgSip> &ms, const url_t *ct_url, const char *route);
public:
	static void send480KO(Agent *agent, shared_ptr<SipEvent> &ev);
	static void send200Ok(Agent *agent, shared_ptr<SipEvent> &ev, const sip_contact_t *contacts);
	void routeRequest(Agent *agent, shared_ptr<SipEvent> &ev, Record *aorb, bool fork);

	Registrar(Agent *ag) :
			Module(ag) {
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
#ifdef ENABLE_REDIS
				{	String , "db-implementation", "Implementation used for storing address of records contact uris. [redis-async, redis-sync, internal]","redis-async"},
				{	String , "redis-server-domain", "Domain of the redis server. ","localhost"},
				{	Integer , "redis-server-port", "Port of the redis server.","6379"},
				{	String , "redis-auth-password", "Authentication password for redis. Empty to disable.",""},
				{	Integer , "redis-server-timeout", "Timeout in milliseconds of the redis connection.","1500"},
				{	String , "redis-record-serializer", "Implementation of the contact serialiser to use. [C, protobuf]","protobuf"},
#else
				{ String, "db-implementation", "Implementation used for storing address of records contact uris. [internal,...]", "internal" },
#endif
				{ Boolean, "fork", "Fork messages to all registered devices", "true" },
				{ Boolean, "fork-one-response", "Only forward one response of forked invite to the caller", "true" },
				{ Boolean, "fork-no-global-decline", "All the forked have to decline in order to decline the caller invite", "false" },
				{	String, "generated-contact-route" , "Generate a contact from the TO header and route it to the above destination. [sip:host:port]", ""},
				{	String, "generated-contact-expected-realm" , "Require presence of authorization header for specified realm. [Realm]", ""},
				config_item_end };
		mc->addChildrenValues(configs);

		auto p=mc->createStatPair("count-clear", "Number of cleared registrations.");
		mCountClear=p.first;
		mCountClearFinished=p.second;

		p=mc->createStatPair("count-bind", "Number of registers.");
		mCountBind=p.first;
		mCountBindFinished=p.second;

		p=mc->createStatPair("count-forks", "Number of forks");
		mCountForks=p.first;
		mCountForksFinished=p.second;

		mCountNonForks=mc->createStat("count-non-forked", "Number of non forked invites.");
		mCountLocalActives=mc->createStat("count-local-registered-users", "Number of users currently registered through this server.");
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
		static_route_file = mc->get<ConfigString>("static-records-file")->read();
		if (!static_route_file.empty())
			readStaticRecord(static_route_file);
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

	virtual void onRequest(shared_ptr<SipEvent> &ev);

	virtual void onResponse(shared_ptr<SipEvent> &ev);

	virtual void onTransactionEvent(const shared_ptr<Transaction> &transaction, Transaction::Event event);

	void idle() { updateLocalRegExpire(); }

private:
	void updateLocalRegExpire() {
		RegistrarDb *db=RegistrarDb::get(mAgent);
		db->mLocalRegExpire->removeExpiredBefore(time(NULL));
		mCountLocalActives->set(db->mLocalRegExpire->countActives());
	}
	bool isManagedDomain(const char *domain) {
		return ModuleToolbox::matchesOneOf(domain, mDomains);
	}
	void readStaticRecord(string file);
	bool contactUrlInVia(const url_t *ct_url, sip_via_t * via);
	list<string> mDomains;
	bool mFork;
	string mGeneratedContactRoute;
	string mExpectedRealm;
	string static_route_file;
	static ModuleInfo<Registrar> sInfo;
};

// Listener class NEED to copy the shared pointer
class OnLogBindListener: public RegistrarDbListener {
	friend class Registrar;
	Agent *agent;
	string line;
public:
	OnLogBindListener(Agent *agent, const string& line) :
			agent(agent), line(line) {
	}
	void onRecordFound(Record *r) {
		LOGD("Static route added: %s", line.c_str());
	}
	void onError() {
		LOGE("Can't add static route: %s", line.c_str());
	}
};

void Registrar::readStaticRecord(string file_path) {
	LOGD("Read static recond file");

	su_home_t home;

	stringstream ss;
	ss.exceptions(ifstream::failbit | ifstream::badbit);

	string line;
	string from;
	string contact_header;

	ifstream file;
	file.open(file_path);
	if (file.is_open()) {
		su_home_init(&home);
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

					if (url != NULL && contact != NULL) {
						RegistrarDb::get(mAgent)->bind(url, contact, "", 0, NULL, -1, isManagedDomain(url->url_host), make_shared<OnLogBindListener>(getAgent(), line));
						continue;
					}
				}
			}
			LOGW("Incorrect line format: %s", line.c_str());
		}
		su_home_deinit(&home);
	} else {
		LOGE("Can't open file %s", file_path.c_str());
	}

}

void Registrar::send480KO(Agent *agent, shared_ptr<SipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	ev->reply(ms, 480, "Temporarily Unavailable", SIPTAG_SERVER_STR(agent->getServerString()), TAG_END());
}

void Registrar::send200Ok(Agent *agent, shared_ptr<SipEvent> &ev, const sip_contact_t *contacts) {
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

void Registrar::routeRequest(Agent *agent, shared_ptr<SipEvent> &ev, Record *aor, bool fork = false) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();

	std::list<std::shared_ptr<ExtendedContact>> contacts;

	if (!aor && mGeneratedContactRoute.empty()) {
		LOGD("This user isn't registered (no aor).");
		ev->reply(ms, SIP_404_NOT_FOUND, SIPTAG_SERVER_STR(agent->getServerString()), TAG_END());
		return;
	}

	// _Copy_ list of extended contacts
	if (aor) contacts = aor->getExtendedContacts();

	time_t now = time(NULL);

	// Generate a fake contact for a proxy
	if (!mGeneratedContactRoute.empty()) {
		const url_t *to=ms->getSip()->sip_to->a_url;
		auto gwECt(make_shared<ExtendedContact>(to, mGeneratedContactRoute.c_str()));

		// This contact is a proxy which will challenge us with a known Realm
		const char *nextProxyRealm=mExpectedRealm.empty()?to->url_host : mExpectedRealm.c_str();
		if (ms->getSip()->sip_request->rq_method == sip_method_invite
				&& !ModuleToolbox::findAuthorizationForRealm(ms->getHome(), sip->sip_proxy_authorization, nextProxyRealm)) {
			LOGD("No authorization header %s found in request, forwarding request only to proxy", nextProxyRealm);
			if (rewriteContactUrl(ms, to, mGeneratedContactRoute.c_str())) {
				shared_ptr<OutgoingTransaction> transaction = ev->createOutgoingTransaction();
				shared_ptr<string>thisProxyRealm(make_shared<string>(to->url_host));
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


	if (contacts.size() == 0) {
		LOGD("This user isn't registered (no contact).");
		ev->reply(ms, SIP_404_NOT_FOUND, SIPTAG_SERVER_STR(agent->getServerString()), TAG_END());
		return;
	}

	if (contacts.size() <= 1 || !fork || ms->getSip()->sip_request->rq_method != sip_method_invite) {
		++*mCountNonForks;
		const shared_ptr<ExtendedContact> &ec = contacts.front();
		sip_contact_t *ct = NULL;
		if (ec)
			ct = Record::extendedContactToSofia(ms->getHome(), *ec, now);

		if (ct && ct->m_url && rewriteContactUrl(ms, ct->m_url, ec->mRoute)) {
			agent->injectRequestEvent(ev);
			return;
		} else {
			LOGW("Can't create sip_contact of %s.", ec->mSipUri);
		}
	} else {
		++*mCountForks;
		int handled = 0;
		shared_ptr<ForkCallContext> context(make_shared<ForkCallContext>(agent));
		shared_ptr<IncomingTransaction> incoming_transaction = ev->createIncomingTransaction();
		context->onNew(incoming_transaction);
		incoming_transaction->setProperty<ForkCallContext>(Registrar::sInfo.getModuleName(), context);

		for (auto it = contacts.begin(); it != contacts.end(); ++it) {
			const shared_ptr<ExtendedContact> ec = *it;
			sip_contact_t *ct = NULL;
			if (ec)
				ct = Record::extendedContactToSofia(ms->getHome(), *ec, now);

			shared_ptr<MsgSip> new_ms = make_shared<MsgSip>(*ms);
			if (ct && ct->m_url && rewriteContactUrl(new_ms, ct->m_url, ec->mRoute)) {
				LOGD("Fork to %s.", ec->mSipUri);
				shared_ptr<SipEvent> new_ev(make_shared<RequestSipEvent>(ev));
				new_ev->setMsgSip(new_ms);
				shared_ptr<OutgoingTransaction> transaction = new_ev->createOutgoingTransaction();
				transaction->setProperty(Registrar::sInfo.getModuleName(), context);

				agent->injectRequestEvent(new_ev);
				handled++;
			} else {
				LOGD("Can't create sip_contact of %s.", ec->mSipUri);
			}
		}

		if (handled > 0) {
			shared_ptr<SipEvent> new_ev(make_shared<ResponseSipEvent>(ev->getOutgoingAgent(), incoming_transaction->createResponse(SIP_100_TRYING)));
			new_ev->setIncomingAgent(incoming_transaction);
			agent->sendResponseEvent(new_ev);
			ev->terminateProcessing();
			return;
		} else {
			LOGD("This user isn't registered (no valid contact).");
		}
	}

	ev->reply(ms, SIP_404_NOT_FOUND, SIPTAG_SERVER_STR(agent->getServerString()), TAG_END());
}

// Listener class NEED to copy the shared pointer
class OnBindListener: public RegistrarDbListener {
	friend class Registrar;
	Agent *agent;
	shared_ptr<SipEvent> ev;
public:
	OnBindListener(Agent *agent, shared_ptr<SipEvent> ev) :
			agent(agent), ev(ev) {
		ev->suspendProcessing();
	}
	;
	void onRecordFound(Record *r) {
		const shared_ptr<MsgSip> &ms = ev->getMsgSip();
		time_t now = time(NULL);
		Registrar::send200Ok(agent, ev, r->getContacts(ms->getHome(), now));
	}
	void onError() {
		Registrar::send480KO(agent, ev);
	}
};

// Listener class NEED to copy the shared pointer
class OnBindForRoutingListener: public RegistrarDbListener {
	friend class Registrar;
	Registrar *mModule;
	Agent *mAgent;
	shared_ptr<SipEvent> mEv;
	bool mFork;
public:
	OnBindForRoutingListener(Registrar *module, Agent *agent, shared_ptr<SipEvent> ev, bool fork) :
			mModule(module), mAgent(agent), mEv(ev), mFork(fork) {
		ev->suspendProcessing();
	}
	;
	void onRecordFound(Record *r) {
		mModule->routeRequest(mAgent, mEv, r, mFork);
	}
	void onError() {
		Registrar::send480KO(mAgent, mEv);
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

void Registrar::onRequest(shared_ptr<SipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();

	// Handle SipEvent associated with a Stateful transaction
	shared_ptr<IncomingTransaction> transaction = dynamic_pointer_cast<IncomingTransaction>(ev->getIncomingAgent());
	if (transaction != NULL) {
		shared_ptr<ForkCallContext> ptr = transaction->getProperty<ForkCallContext>(getModuleName());
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
					shared_ptr<OnBindListener> listener(make_shared<OnBindListener>(getAgent(), ev));
					++*mCountClear;
					LOGD("Clearing bindings");
					listener->addStatCounter(mCountClearFinished);
					RegistrarDb::get(mAgent)->clear(sip, listener);
					return;
				} else {
					shared_ptr<OnBindListener> listener(make_shared<OnBindListener>(getAgent(), ev));
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
				RegistrarDb::get(mAgent)->fetch(sipurl, make_shared<OnBindListener>(getAgent(), ev));
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
				LOGD("Fetch %s.", url_as_string(ms->getHome(), sipurl));
				RegistrarDb::get(mAgent)->fetch(sipurl, make_shared<OnBindForRoutingListener>(this, getAgent(), ev, mFork), true);
			}
		}
		if (sip->sip_request->rq_method == sip_method_ack) {
			const shared_ptr<MsgSip> &ms = ev->getMsgSip();
			sip_route_t *route = ms->getSip()->sip_route;
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

void Registrar::onResponse(shared_ptr<SipEvent> &ev) {
	// Handle SipEvent associated with a Stateful transaction
	shared_ptr<OutgoingTransaction> transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
	if (transaction != NULL) {
		shared_ptr<ForkCallContext> ptr = transaction->getProperty<ForkCallContext>(getModuleName());
		if (ptr != NULL) {
			ptr->onResponse(transaction, ev);
		}
	}
}

void Registrar::onTransactionEvent(const shared_ptr<Transaction> &transaction, Transaction::Event event) {
	shared_ptr<ForkCallContext> ptr = transaction->getProperty<ForkCallContext>(getModuleName());
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

			default:
				break;
			}
		}
	}
}

ModuleInfo<Registrar> Registrar::sInfo("Registrar", "The Registrar module accepts REGISTERs for domains it manages, and store the address of record "
		"in order to route other requests destinated to the client who registered.",
		ModuleInfoBase::ModuleOid::Registrar);

