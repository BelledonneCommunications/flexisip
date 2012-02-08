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
#include <sofia-sip/sip_status.h>

class GatewayRegister {
private:
	typedef enum {
		INITIAL, REGISTRING, REGISTRED
	} State;
	State state;
	Agent *agent;
	su_home_t home;
	nua_handle_t *nh;
	sip_from_t *from;
	sip_to_t *to;
	string password;

public:
	void sendRegister(bool authentication = false, const char *realm = NULL);
	GatewayRegister(Agent *ag, nua_t * nua, sip_from_t *from, sip_to_t *to);
	~GatewayRegister();
	void onMessage(const sip_t *sip);
	void onError(const char * message, ...);

	void start();
	void end();

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
			gw->setPassword(password);
			gw->sendRegister();
			delete this;
		}

		virtual void onSynchronousPasswordFound(const string &password) {
			LOGD("Found password");
			gw->setPassword(password);
			gw->sendRegister();
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

				// Already a response?
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


GatewayRegister::GatewayRegister(Agent *ag, nua_t *nua, sip_from_t *sip_from, sip_to_t *sip_to) :
		agent(ag) {
	su_home_init(&home);

	url_t *domain = NULL;
	ConfigStruct *cr = ConfigManager::get()->getRoot();
	ConfigStruct *ma = cr->get<ConfigStruct>("module::GatewayAdapter");
	std::string domainString = ma->get<ConfigString>("gateway-domain")->read();
	if (!domainString.empty()) {
		domain = url_make(&home, domainString.c_str());
	}

	from = sip_from_dup(&home, sip_from);
	to = sip_to_dup(&home, sip_to);

	// Override domains?
	if (domain != NULL) {
		from->a_url->url_host = domain->url_host;
		from->a_url->url_port = domain->url_port;
		to->a_url->url_host = domain->url_host;
		to->a_url->url_port = domain->url_port;
	}

	state = State::INITIAL;

	nh = nua_handle(nua, this, SIPTAG_FROM(from), SIPTAG_TO(to), TAG_END());
}

GatewayRegister::~GatewayRegister() {
	nua_handle_destroy(nh);
	su_home_deinit(&home);
}

void GatewayRegister::sendRegister(bool authentication, const char *realm) {
	LOGD("Send REGISTER: auth %i", authentication);
	state = State::REGISTRING;

	if (!authentication) {
		nua_register(nh, TAG_END());
	} else {
		char * digest;
		if (realm != NULL)
			digest = su_sprintf(&home, "Digest:%s:%s:%s", realm, from->a_url->url_user, password.c_str());
		else
			digest = su_sprintf(&home, "Digest:\"%s\":%s:%s", from->a_url->url_host, from->a_url->url_user, password.c_str());

		nua_authenticate(nh, NUTAG_AUTH(digest), TAG_END());
	}
}

void GatewayRegister::onMessage(const sip_t *sip) {
	switch (state) {
	case State::INITIAL:
		onError("Can't receive message in this state");
		break;

	case State::REGISTRING:
		if (sip->sip_status->st_status == 401) {
			sendRegister(true);
		} else if (sip->sip_status->st_status == 407) {
			// Override realm
			const char *realm = NULL;
			if (sip->sip_proxy_authenticate != NULL && sip->sip_proxy_authenticate->au_params != NULL) {
				realm = msg_params_find(sip->sip_proxy_authenticate->au_params, "realm=");
			}
			sendRegister(true, realm);
		} else if (sip->sip_status->st_status == 200) {
			state = State::REGISTRED;
			end(); // TODO: stop the dialog?
		} else {
			LOGD("not handled response:%i", sip->sip_status->st_status);
		}
		break;

	case State::REGISTRED:
		LOGD("new message %i", sip->sip_status->st_status);
		break;
	}
}

void GatewayRegister::onError(const char *message, ...) {
	va_list args;
	va_start(args, message);
	LOGE("%s", message);
	va_end(args);
	end();
}

void GatewayRegister::start() {
	LOGD("GatewayRegister start");
	OnFetchListener *listener = new OnFetchListener(this);
	LOGD("Fetching binding");
	RegistrarDb::get(agent)->fetch(from->a_url, listener);
}

void GatewayRegister::end() {
	LOGD("GatewayRegister end");
	delete this;
}

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
	nua_t *mNua;
};

GatewayAdapter::GatewayAdapter(Agent *ag) :
		Module(ag) {
}

GatewayAdapter::~GatewayAdapter() {
	if(mNua != NULL) {
		nua_shutdown(mNua);
		su_root_run(mAgent->getRoot()); // Correctly wait for nua_destroy
	}
}

void GatewayAdapter::onLoad(Agent *agent, const ConfigStruct *module_config) {
	std::string gateway = module_config->get<ConfigString>("gateway")->read();
	mNua = nua_create(agent->getRoot(), nua_callback, this, NUTAG_OUTBOUND("no-validate no-natify no-options-keepalive"), NUTAG_PROXY(gateway.c_str()), TAG_END());
}

void GatewayAdapter::onRequest(std::shared_ptr<SipEvent> &ev) {
	sip_t *sip = ev->mSip;
	if (sip->sip_request->rq_method == sip_method_register) {
		if (sip->sip_contact != NULL) {

			// Patch contacts
			sip_contact_t *contact = nta_agent_contact(getAgent()->getSofiaAgent());
			if (contact == NULL) {
				LOGE("Can't find a valid contact for the agent");
				return;
			}
			contact = sip_contact_dup(ev->getHome(), contact);
			contact->m_next = sip->sip_contact;
			sip->sip_contact = contact;

			GatewayRegister *gr = new GatewayRegister(getAgent(), mNua, sip->sip_from, sip->sip_to);
			gr->start();
		}
	}
}

void GatewayAdapter::onResponse(std::shared_ptr<SipEvent> &ev) {

}

void GatewayAdapter::nua_callback(nua_event_t event, int status, char const *phurase, nua_t *nua, nua_magic_t *ctx, nua_handle_t *nh, nua_hmagic_t *hmagic, sip_t const *sip, tagi_t tags[]) {
	GatewayRegister *gr = (GatewayRegister *) hmagic;

	if(event == nua_r_shutdown && status >= 200) {
		GatewayAdapter *ga = (GatewayAdapter*)ctx;
		nua_destroy(ga->mNua);
		su_root_break(ga->getAgent()->getRoot());
		return;
	}

	if (sip != NULL) {
		gr->onMessage(sip);
	} else {
		LOGD("nua_callback: No sip message %d -> %s", status, phurase);
	}
}


ModuleInfo<GatewayAdapter> GatewayAdapter::sInfo("GatewayAdapter", "...");

