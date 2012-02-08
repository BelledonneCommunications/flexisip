/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2012  Belledonne Communications SARL.
 Author: Yann Diorcet

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
#include "registrardb.hh"
#include "authdb.hh"
#include <sofia-sip/nua.h>

class GatewayRegister {
private:
	Agent *agent;
	su_home_t home;
	nua_handle_t *nh;
	sip_from_t *from;
	sip_to_t *to;
	string password;

public:
	void sendRegister(const string &password = string());
	GatewayRegister(Agent *ag, nua_t * nua, sip_from_t *from, sip_to_t *to);
	~GatewayRegister();
	void onMessage();
	void onError(const string &message);

	void start();
	sip_from_t* getFrom() const {
		return from;
	}
	sip_to_t* getTo() const {
		return to;
	}

	void setPassword(const string &password) {
		this->password = password;
	}

	const string& getPassword() {
		return password;
	}
private:
	// Listener class NEED to copy the shared pointer

	class OnAuthListener: public AuthDbListener {
	private:
		GatewayRegister *gw;

	public:
		OnAuthListener(GatewayRegister * gw) :
				gw(gw) {
		}

		virtual void onAsynchronousPasswordFound(const string &password) {
			LOGD("Found password");
			gw->sendRegister(password);
			delete this;
		}

		virtual void onSynchronousPasswordFound(const string &password) {
			LOGD("Found password");
			gw->sendRegister(password);
			delete this;
		}

		virtual void onError() {
			gw->onError("Error on password retrieval");
			delete this;
		}

	};

	// Listener class NEED to copy the shared pointer
	class OnFetchListener: public RegistrarDbListener {
	private:
		GatewayRegister *gw;

	public:

		OnFetchListener(GatewayRegister * gw) :
				gw(gw) {
		}

		~OnFetchListener() {
		}

		void onRecordFound(Record *r) {
			if (r == NULL) {
				LOGD("Record doesn't exist. Fork");
				OnAuthListener * listener = new OnAuthListener(gw);

				string password;
				AuthDb *mAuthDb = AuthDb::get();
				AuthDbResult result = mAuthDb->password(gw->getFrom()->a_url, gw->getFrom()->a_url->url_user, password, listener);
				if (result != AuthDbResult::PENDING) {
					if (result == AuthDbResult::PASSWORD_FOUND) {
						gw->setPassword(password);
						gw->sendRegister();
					} else {
						LOGE("Can't find user password. Abort.");
					}
					delete listener;
				}
			} else {
				LOGD("Record already exists. Not forked");
			}
			delete this;
		}

		void onError() {
			gw->onError("Fetch error.");
			delete this;
		}
	};
};

class GatewayAdapter: public Module, public ModuleToolbox {

public:
	GatewayAdapter(Agent *ag);

	~GatewayAdapter();

	virtual void onDeclare(ConfigStruct *module_config) {
		ConfigItemDescriptor items[] = { { String, "gateway", "A gateway uri where to send all requests", "" }, { String, "gateway-domain", "Force the domain of send all requests", "" }, config_item_end };
		module_config->addChildrenValues(items);
	}

	virtual void onLoad(Agent *agent, const ConfigStruct *module_config);

	virtual void onRequest(std::shared_ptr<SipEvent> &ev);

	virtual void onResponse(std::shared_ptr<SipEvent> &ev);
private:
	static void nua_callback(nua_event_t event, int status, char const *phrase, nua_t *nua, nua_magic_t *_t, nua_handle_t *nh, nua_hmagic_t *hmagic, sip_t const *sip, tagi_t tags[]);

	static ModuleInfo<GatewayAdapter> sInfo;
	su_home_t *mHome;
	nua_t *mNua;
	url_t *mDomain;
};

GatewayAdapter::GatewayAdapter(Agent *ag) :
		Module(ag), mDomain(NULL) {
	mHome = su_home_create();
}

GatewayAdapter::~GatewayAdapter() {
	su_home_destroy(mHome);
}

void GatewayAdapter::onLoad(Agent *agent, const ConfigStruct *module_config) {
	std::string gateway = module_config->get<ConfigString>("gateway")->read();
	std::string domain = module_config->get<ConfigString>("gateway-domain")->read();
	if (!domain.empty()) {
		mDomain = url_make(mHome, domain.c_str());
	}
	mNua = nua_create(agent->getRoot(), nua_callback, NULL, NUTAG_REGISTRAR(gateway.c_str()), TAG_END());
}

void GatewayAdapter::onRequest(std::shared_ptr<SipEvent> &ev) {
	sip_t *sip = ev->mSip;
	if (sip->sip_request->rq_method == sip_method_register) {
		if (sip->sip_contact != NULL) {
			sip_from_t *from = sip_from_dup(ev->getHome(), sip->sip_from);
			sip_to_t *to = sip_to_dup(ev->getHome(), sip->sip_to);

			// Override domains?
			if (mDomain != NULL) {
				from->a_url->url_host = mDomain->url_host;
				from->a_url->url_port = mDomain->url_port;
				to->a_url->url_host = mDomain->url_host;
				to->a_url->url_port = mDomain->url_port;
			}

			// Patch contacts
			sip_contact_t *contact = sip->sip_contact;
			if (contact == NULL) {
				LOGE("Invalid contact");
				return;
			}
			while (contact->m_next != NULL)
				contact = contact->m_next;
			contact->m_next = nta_agent_contact(getAgent()->getSofiaAgent());

			GatewayRegister *gr = new GatewayRegister(getAgent(), mNua, from, to);
			gr->start();
		}
	}
}

GatewayRegister::GatewayRegister(Agent *ag, nua_t *nua, sip_from_t *from, sip_to_t *to) :
		agent(ag), from(from), to(to) {
	su_home_init(&home);
	nh = nua_handle(nua, NULL, TAG_END());
}

GatewayRegister::~GatewayRegister() {
	su_home_deinit(&home);
}

void GatewayRegister::sendRegister(const string &password) {
	char * digest = su_sprintf(&home, "Digest:\"%s\":%s:%s", from->a_url->url_host, from->a_url->url_user, password.c_str());

	if (password.empty()) {
		nua_register(nh, SIPTAG_FROM(from), SIPTAG_TO(to), TAG_END());
	} else {
		nua_register(nh, NUTAG_AUTH(digest), SIPTAG_FROM(from), SIPTAG_TO(to), TAG_END());
	}
}

void GatewayAdapter::onResponse(std::shared_ptr<SipEvent> &ev) {

}

void GatewayRegister::onMessage() {
}

void GatewayRegister::onError(const string &message) {
	LOGE("%s", message.c_str());
	delete this;
}

void GatewayRegister::start() {
	OnFetchListener *listener = new OnFetchListener(this);
	LOGD("Fetching binding");
	RegistrarDb::get(agent)->fetch(from->a_url, listener);
}

ModuleInfo<GatewayAdapter> GatewayAdapter::sInfo("GatewayAdapter", "...");

void GatewayAdapter::nua_callback(nua_event_t event, int status, char const *phurase, nua_t *nua, nua_magic_t *_t, nua_handle_t *nh, nua_hmagic_t *hmagic, sip_t const *sip, tagi_t tags[]) {
	GatewayRegister * gr = (GatewayRegister *) hmagic;
	gr->onMessage();
}

