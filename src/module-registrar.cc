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

#include <fstream>
#include "agent.hh"
#include "registrardb.hh"
#include "forkcallcontext.hh"
#include <sofia-sip/sip_status.h>

using namespace ::std;

class Registrar: public Module, public ModuleToolbox {
public:
	static void send480KO(Agent *agent, std::shared_ptr<SipEvent> &ev);
	static void send200Ok(Agent *agent, std::shared_ptr<SipEvent> &ev, const sip_contact_t *contacts);
	void routeRequest(Agent *agent, std::shared_ptr<SipEvent> &ev, Record *aorb, bool fork);

	Registrar(Agent *ag) :
			Module(ag) {
	}

	~Registrar() {
	}

	virtual void onDeclare(ConfigStruct *module_config) {
		ConfigItemDescriptor items[] = { { StringList, "reg-domains", "List of whitelist separated domain names to be managed by the registrar.", "localhost" }, { Integer, "max-contacts-by-aor", "Maximum number of registered contacts of an address of record.", "15" }, { String,
				"line-field-name", "Name of the contact uri parameter used for identifying user's device. ", "line" }, { String, "static-route-file", "File containing the static route to add to database at startup", "" },
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
				config_item_end };
		module_config->addChildrenValues(items);
	}

	virtual void onLoad(Agent *agent, const ConfigStruct *module_config) {
		list<string>::const_iterator it;
		mDomains = module_config->get<ConfigStringList>("reg-domains")->read();
		for (it = mDomains.begin(); it != mDomains.end(); ++it) {
			LOGD("Found registrar domain: %s", (*it).c_str());
		}
		mFork = module_config->get<ConfigBoolean>("fork")->read();
		static_route_file = module_config->get<ConfigString>("static-route-file")->read();
		if (!static_route_file.empty())
			readStaticRecord(static_route_file);
	}

	// Delta from expires header, normalized with custom rules.
	static int getMainDelta(sip_expires_t *expires) {
		int delta = 3600;
		if (expires) {
			delta = expires->ex_delta;
			if (delta < 30) {
				delta = 30;
			}
			if (delta > 3600 * 24)
				delta = 3600 * 24;
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
			if ('*' == contact->m_url->url_scheme[0]) {
				if (count > 1 || 0 != expires)
					return false;
				starFound = true;
			}
		} while (NULL != (contact = contact->m_next));
		return true;
	}

	virtual void onRequest(std::shared_ptr<SipEvent> &ev);

	virtual void onResponse(std::shared_ptr<SipEvent> &ev);

private:
	bool isManagedDomain(const char *domain) {
		return ModuleToolbox::matchesOneOf(domain, mDomains);
	}
	void readStaticRecord(std::string file);
	bool contactinVia(sip_contact_t *ct, sip_via_t * via);
	list<string> mDomains;
	bool mFork;
	string static_route_file;
	static ModuleInfo<Registrar> sInfo;
};

// Listener class NEED to copy the shared pointer
class OnLogBindListener: public RegistrarDbListener {
	friend class Registrar;
	Agent *agent;
	std::string line;
public:
	OnLogBindListener(Agent *agent, const std::string& line) :
			agent(agent), line(line) {
	}
	void onRecordFound(Record *r) {
		LOGD("Static route added: %s", line.c_str());
		delete this;
	}
	void onError() {
		LOGE("Can't add static route: %s", line.c_str());
		delete this;
	}
};

void Registrar::readStaticRecord(std::string file_path) {
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
			std::size_t start = line.find_first_of('<');
			std::size_t pos = line.find_first_of('>');
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
						OnLogBindListener *listener = new OnLogBindListener(getAgent(), line);
						RegistrarDb::get(mAgent)->bind(url, contact, "", 0, NULL, INT32_MAX, listener);
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

void Registrar::send480KO(Agent *agent, std::shared_ptr<SipEvent> &ev) {
	nta_msg_treply(agent->getSofiaAgent(), ev->getMsg(), 480, "Temporarily Unavailable", SIPTAG_SERVER_STR(agent->getServerString()), TAG_END());
	ev->terminateProcessing();
}

void Registrar::send200Ok(Agent *agent, std::shared_ptr<SipEvent> &ev, const sip_contact_t *contacts) {
	if (contacts != NULL) {
		nta_msg_treply(agent->getSofiaAgent(), ev->getMsg(), 200, "Registration successful", SIPTAG_CONTACT(contacts), SIPTAG_SERVER_STR(agent->getServerString()), TAG_END());
		ev->terminateProcessing();
	} else {
		nta_msg_treply(agent->getSofiaAgent(), ev->getMsg(), 200, "Registration successful", SIPTAG_SERVER_STR(agent->getServerString()), TAG_END());
		ev->terminateProcessing();
	}
}

static extended_contact *getFirstExtendedContact(Record *aor) {
	const list<extended_contact*> contacts = aor->getExtendedContacts();
	list<extended_contact*>::const_iterator it = contacts.begin();
	return it != contacts.end() ? (*it) : NULL;
}

bool Registrar::contactinVia(sip_contact_t *ct, sip_via_t * via) {

	while (via != NULL) {
		if (via->v_host && ct->m_url->url_host && !strcmp(via->v_host, ct->m_url->url_host)) {
			const char *port1 = (via->v_port) ? via->v_port : "5060";
			const char *port2 = (ct->m_url->url_port) ? ct->m_url->url_port : "5060";
			if (!strcmp(port1, port2))
				return true;
		}
		via = via->v_next;
	}

	return false;
}

class RegistrarIncomingTransaction: public IncomingTransaction {
private:
	bool mRinging;
	bool mEarlymedia;

public:
	RegistrarIncomingTransaction(nta_agent_t *agent, msg_t * msg, sip_t *sip, TransactionCallback callback, void *magic) :
			IncomingTransaction(agent, msg, sip, callback, magic), mRinging(false), mEarlymedia(false) {

	}
	virtual void send(StatefulSipEvent * ev) {
		if (ev->getSip()->sip_status) {
			if (ev->getSip()->sip_status->st_status == 180) {
				if (!mRinging) {
					IncomingTransaction::send(ev);
					mRinging = true;
				}
			} else if (ev->getSip()->sip_status->st_status == 183) {
				if (!mEarlymedia) {
					IncomingTransaction::send(ev);
					mEarlymedia = true;
				}
			} else {
				IncomingTransaction::send(ev);
			}
		} else {
			IncomingTransaction::send(ev);
		}
	}

};

void Registrar::routeRequest(Agent *agent, std::shared_ptr<SipEvent> &ev, Record *aor, bool fork = false) {
	sip_t *sip = ev->getSip();

	// here we would implement forking
	time_t now = time(NULL);
	if (aor) {
		const list<extended_contact*> contacts = aor->getExtendedContacts();
		if (contacts.size() <= 1 || !fork || ev->getSip()->sip_request->rq_method != sip_method_invite) {
			extended_contact *ec = getFirstExtendedContact(aor);
			sip_contact_t *ct = NULL;
			if (ec)
				ct = Record::extendedContactToSofia(ev->getHome(), ec, now);

			if (ct && !contactinVia(ct, sip->sip_via)) {
				/*sanity check on the contact address: might be '*' or whatever useless information*/
				if (ct->m_url->url_host != NULL && ct->m_url->url_host[0] != '\0') {
					LOGD("Registrar: found contact information in database, rewriting request uri");
					/*rewrite request-uri */
					ev->getSip()->sip_request->rq_url[0] = *url_hdup(ev->getHome(), ct->m_url);
					if (ec->mRoute != NULL && 0 != strcmp(agent->getPreferredRoute().c_str(), ec->mRoute)) {
						LOGD("This flexisip instance is not responsible for contact %s -> %s", ec->mSipUri, ec->mRoute);
						prependRoute(ev->getHome(), agent, ev->getMsg(), ev->getSip(), ec->mRoute);
					}
					// Back to work
					agent->injectRequestEvent(ev);
					return;
				} else {
					if (ct != NULL) {
						LOGW("Unrouted request because of incorrect address of record.");
					}
				}
			}
		} else {
			ForkCallContext *context = new ForkCallContext(agent, this);
			IncomingTransaction *incoming_transaction = new RegistrarIncomingTransaction(agent->getSofiaAgent(), ev->getMsg(), ev->getSip(), ForkCallContext::incomingCallback, context);
			context->setIncomingTransaction(incoming_transaction);
			for (list<extended_contact*>::const_iterator it = contacts.begin(); it != contacts.end(); ++it) {
				extended_contact *ec = *it;
				sip_contact_t *ct = NULL;
				if (ec)
					ct = Record::extendedContactToSofia(ev->getHome(), ec, now);

				if (ct && !contactinVia(ct, sip->sip_via)) {
					/*sanity check on the contact address: might be '*' or whatever useless information*/
					if (ct->m_url->url_host != NULL && ct->m_url->url_host[0] != '\0') {
						LOGD("Registrar: found contact information in database, rewriting request uri");

						OutgoingTransaction *transaction = new OutgoingTransaction(agent->getSofiaAgent(), ForkCallContext::outgoingCallback, context);
						context->addOutgoingTransaction(transaction);

						shared_ptr<SipEvent> new_ev(transaction->copy(ev.get()));
						msg_t *new_msg = new_ev->getMsg();
						sip_t *new_sip = new_ev->getSip();

						/*rewrite request-uri */
						new_sip->sip_request->rq_url[0] = *url_hdup(msg_home(new_msg), ct->m_url);
						if (ec->mRoute != NULL && 0 != strcmp(agent->getPreferredRoute().c_str(), ec->mRoute)) {
							LOGD("This flexisip instance is not responsible for contact %s -> %s", ec->mSipUri, ec->mRoute);
							prependRoute(msg_home(new_msg), agent, new_msg, new_sip, ec->mRoute);
						}

						LOGD("Fork to %s", ec->mSipUri);
						agent->injectRequestEvent(new_ev);
					} else {
						if (ct != NULL) {
							LOGW("Unrouted request because of incorrect address of record.");
						}
					}
				}
			}

			msg_t *msg = nta_incoming_create_response(incoming_transaction->getIncoming(), SIP_100_TRYING);
			std::shared_ptr<SipEvent> new_ev(incoming_transaction->create(msg, sip_object(msg)));
			agent->sendResponseEvent(new_ev);
			ev->terminateProcessing();
			return;
		}
	}

	LOGD("This user isn't registered.");
	nta_msg_treply(agent->getSofiaAgent(), ev->getMsg(), SIP_404_NOT_FOUND, SIPTAG_SERVER_STR(agent->getServerString()), TAG_END());
	ev->terminateProcessing();
}

// Listener class NEED to copy the shared pointer
class OnBindListener: public RegistrarDbListener {
	friend class Registrar;
	Agent *agent;
	std::shared_ptr<SipEvent> ev;
public:
	OnBindListener(Agent *agent, std::shared_ptr<SipEvent> ev) :
			agent(agent), ev(ev) {
		ev->suspendProcessing();
	}
	;
	void onRecordFound(Record *r) {
		time_t now = time(NULL);
		Registrar::send200Ok(agent, ev, r->getContacts(ev->getHome(), now));
		delete this;
	}
	void onError() {
		Registrar::send480KO(agent, ev);
		delete this;
	}
};

// Listener class NEED to copy the shared pointer
class OnBindForRoutingListener: public RegistrarDbListener {
	friend class Registrar;
	Registrar *mModule;
	Agent *mAgent;
	std::shared_ptr<SipEvent> mEv;
	bool mFork;
public:
	OnBindForRoutingListener(Registrar *module, Agent *agent, std::shared_ptr<SipEvent> ev, bool fork) :
			mModule(module), mAgent(agent), mEv(ev), mFork(fork) {
		ev->suspendProcessing();
	}
	;
	void onRecordFound(Record *r) {
		mModule->routeRequest(mAgent, mEv, r, mFork);
		delete this;
	}
	void onError() {
		Registrar::send480KO(mAgent, mEv);
		delete this;
	}
};

void Registrar::onRequest(shared_ptr<SipEvent> &ev) {
	sip_t *sip = ev->getSip();
	if (sip->sip_request->rq_method == sip_method_register) {
		url_t *sipurl = sip->sip_from->a_url;
		if (sipurl->url_host && isManagedDomain(sipurl->url_host)) {
			sip_expires_t *expires = sip->sip_expires;
			int maindelta = getMainDelta(expires);
			if (sip->sip_contact != NULL) {
				if (!checkStarUse(sip->sip_contact, maindelta)) {
					LOGD("The star rules are not respected.");
					nta_msg_treply(getAgent()->getSofiaAgent(), ev->getMsg(), 400, "Invalid Request", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
					ev->terminateProcessing();
					return;
				}
				if ('*' == sip->sip_contact->m_url->url_scheme[0]) {
					OnBindListener *listener = new OnBindListener(getAgent(), ev);
					LOGD("Clearing bindings");
					RegistrarDb::get(mAgent)->clear(sip, listener);
					return;
				} else {
					OnBindListener *listener = new OnBindListener(getAgent(), ev);
					LOGD("Updating binding");
					RegistrarDb::get(mAgent)->bind(sip, mAgent->getPreferredRoute().c_str(), maindelta, listener);
					return;
				}
				LOGD("Records binded to registrar database.");
			} else {
				OnBindListener *listener = new OnBindListener(getAgent(), ev);
				LOGD("No sip contact, it is a fetch only.");
				RegistrarDb::get(mAgent)->fetch(sipurl, listener);
				return;
			}

			/*we need to answer directly */

			ev->terminateProcessing();
		}
	} else {
		/*see if we can route other requests */
		/*acks shall not have their request uri rewritten:
		 - they can be for us (in response to a 407 for invite)
		 - they can be for the a remote peer, in which case they will have the correct contact address in the request uri
		 */
		if (sip->sip_request->rq_method != sip_method_ack) {
			url_t *sipurl = sip->sip_request->rq_url;
			if (sipurl->url_host && isManagedDomain(sipurl->url_host)) {
				RegistrarDbListener *listener = new OnBindForRoutingListener(this, getAgent(), ev, mFork);
				RegistrarDb::get(mAgent)->fetch(sipurl, listener);
			}
		}
	}
}

void Registrar::onResponse(std::shared_ptr<SipEvent> &ev) {
}

ModuleInfo<Registrar> Registrar::sInfo("Registrar", "The Registrar module accepts REGISTERs for domains it manages, and store the address of record "
		"in order to route other requests destinated to the client who registered.");

