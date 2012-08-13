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

#include "module.hh"
#include "agent.hh"
#include "authdb.hh"
#include "registrardb.hh"
#include <sofia-sip/nua.h>
#include <sofia-sip/sip_status.h>
#include <limits.h>

using namespace ::std;

class GatewayRegister {
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
	sip_contact_t *contact;
public:
	void sendRegister();
	GatewayRegister(Agent *ag, nua_t * nua, sip_from_t *from, sip_to_t *to, sip_contact_t *contact);
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

		virtual void switchToAsynchronousMode(){LOGE("to implement");}
		virtual void checkPassword(const char *password) {
			LOGD("Found password");
			gw->setPassword(password);
			gw->sendRegister();
		}

		virtual void onAsynchronousResponse(AuthDbResult ret, const char *password) {
			checkPassword(password);
		}

		virtual void onError() {
			gw->onError("Error on password retrieval");
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
				string password;
				AuthDb *mAuthDb = AuthDb::get();
				AuthDbResult result = mAuthDb->password(gw->agent->getRoot(), gw->getFrom()->a_url, gw->getFrom()->a_url->url_user, password, make_shared<OnAuthListener>(gw));

				// Already a response?
				if (result != AuthDbResult::PENDING) {
					if (result == AuthDbResult::PASSWORD_FOUND) {
						gw->setPassword(password);
						gw->sendRegister();
					} else {
						LOGE("Can't find user password. Abort.");
					}
				}
			} else {
				LOGD("Record already exists. Not forked");
			}
		}

		void onError() {
			gw->onError("Fetch error.");
		}
	};
};

GatewayRegister::GatewayRegister(Agent *ag, nua_t *nua, sip_from_t *sip_from, sip_to_t *sip_to, sip_contact_t *sip_contact) :
		agent(ag) {
	su_home_init(&home);

	url_t *domain = NULL;
	GenericStruct *cr = GenericManager::get()->getRoot();
	GenericStruct *ma = cr->get<GenericStruct>("module::GatewayAdapter");
	string domainString = ma->get<ConfigString>("gateway-domain")->read();
	if (!domainString.empty()) {
		domain = url_make(&home, domainString.c_str());
	}

	from = sip_from_dup(&home, sip_from);
	to = sip_to_dup(&home, sip_to);

	// Copy contact
	contact = sip_contact_format(&home, "<sip:%s@%s:%i>;expires=%i", sip_contact->m_url->url_user, ag->getPublicIp().c_str(), ag->getPort(), INT_MAX);

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

void GatewayRegister::sendRegister() {
	LOGD("Send REGISTER");
	state = State::REGISTRING;

	nua_register(nh, SIPTAG_CONTACT(contact), TAG_END());
}

void GatewayRegister::onMessage(const sip_t *sip) {
	switch (state) {
	case State::INITIAL:
		onError("Can't receive message in this state");
		break;

	case State::REGISTRING:
		if (sip->sip_status->st_status == 200) {
			LOGD("REGISTER done");
			state = State::REGISTRED;
			end(); // TODO: stop the dialog?
		} else if (sip->sip_status->st_status == 408) {
			LOGD("REGISTER timeout");
			end();
		} else if (sip->sip_status->st_status == 401){
			LOGD("REGISTER challenged ");
			ostringstream auth;
			auth << "Digest:\"" << getFrom()->a_url->url_host << "\":" << getFrom()->a_url->url_user << ":" << getPassword();
			nua_authenticate(nh, NUTAG_AUTH(auth.str().c_str()),TAG_END());
		} else {
			LOGD("REGISTER not handled response: %i", sip->sip_status->st_status);
			end();
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
	LOGD("Fetching binding");
	RegistrarDb::get(agent)->fetch(from->a_url, make_shared<OnFetchListener>(this));
}

void GatewayRegister::end() {
	LOGD("GatewayRegister end");
}

class GatewayAdapter: public Module {
public:
	GatewayAdapter(Agent *ag);

	~GatewayAdapter();

	virtual void onDeclare(GenericStruct *module_config);

	virtual void onLoad(const GenericStruct *module_config);

	virtual void onRequest(shared_ptr<RequestSipEvent> &ev);

	virtual void onResponse(shared_ptr<ResponseSipEvent> &ev);

	virtual bool isValidNextConfig(const ConfigValue &cv);

private:
	static void nua_callback(nua_event_t event, int status, char const *phrase, nua_t *nua, nua_magic_t *_t, nua_handle_t *nh, nua_hmagic_t *hmagic, sip_t const *sip, tagi_t tags[]);

	static ModuleInfo<GatewayAdapter> sInfo;
	nua_t *nua;
	url_t *gateway_url;
	bool mRegisterOnGateway;
	su_home_t home;
};

GatewayAdapter::GatewayAdapter(Agent *ag) :
		Module(ag), nua(NULL) {
	su_home_init(&home);
}

GatewayAdapter::~GatewayAdapter() {
	if (nua != NULL) {
		nua_shutdown(nua);
		su_root_run(mAgent->getRoot()); // Correctly wait for nua_destroy
	}
	su_home_deinit(&home);
}

void GatewayAdapter::onDeclare(GenericStruct *module_config) {
	module_config->get<ConfigBoolean>("enabled")->setDefault("false");
	ConfigItemDescriptor items[] = {
			{ String, "gateway", "A gateway uri where to send all requests.", "sip:localhost:0" },
			{ String, "gateway-domain", "Force the domain of send all requests", "" },
			{ Boolean, "register-on-gateway", "Register the server on the gateway in order to get incoming calls.", "true" },
			config_item_end
	};
	module_config->addChildrenValues(items);
}

bool GatewayAdapter::isValidNextConfig(const ConfigValue &cv) {
	if (cv.getName() == "gateway") {
		if (cv.getNextValue().empty()) {
			LOGE("Empty value GatewayAdapter::%s=%s", cv.getName().c_str(), cv.getNextValue().c_str());
			return false;
		}
	}
	return true;
}

void GatewayAdapter::onLoad(const GenericStruct *module_config) {
	//sendTrap("Error loading module Gateway adaptor");
	string gateway = module_config->get<ConfigString>("gateway")->read();
	mRegisterOnGateway=module_config->get<ConfigBoolean>("register-on-gateway")->read();
	gateway_url = url_make(&home, gateway.c_str());
	if (mRegisterOnGateway) {
		char *url = su_sprintf(&home, "sip:%s:*", mAgent->getPublicIp().c_str());
		nua = nua_create(mAgent->getRoot(), nua_callback, this, NUTAG_URL(url), NUTAG_OUTBOUND("no-validate no-natify no-options-keepalive"), NUTAG_PROXY(gateway.c_str()), TAG_END());
	}
}

void GatewayAdapter::onRequest(shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();

	if (sip->sip_request->rq_method == sip_method_register) {
		if (sip->sip_contact != NULL) {
			GatewayRegister *gr = NULL;
			if (mRegisterOnGateway) {
				gr=new GatewayRegister(getAgent(), nua, sip->sip_from, sip->sip_to, sip->sip_contact);
			}

			sip_contact_t *contact = sip_contact_format(&home,
					"<sip:%s@%s:%s>;expires=%i",
					sip->sip_contact->m_url->url_user,
					gateway_url->url_host,
					gateway_url->url_port,
					INT_MAX);
			contact->m_next = sip->sip_contact;
			sip->sip_contact = contact;

			if (mRegisterOnGateway) gr->start();
		}
	}
}

void GatewayAdapter::onResponse(shared_ptr<ResponseSipEvent> &ev) {

}

void GatewayAdapter::nua_callback(nua_event_t event, int status, char const *phurase, nua_t *nua, nua_magic_t *ctx, nua_handle_t *nh, nua_hmagic_t *hmagic, sip_t const *sip, tagi_t tags[]) {
	GatewayRegister *gr = (GatewayRegister *) hmagic;

	if (event == nua_r_shutdown && status >= 200) {
		GatewayAdapter *ga = (GatewayAdapter*) ctx;
		if (ga != NULL) {
			nua_destroy(ga->nua);
			su_root_break(ga->getAgent()->getRoot());
		}
		return;
	}

	if (gr != NULL) {
		if (sip != NULL) {
			gr->onMessage(sip);
		}
	}
}

ModuleInfo<GatewayAdapter> GatewayAdapter::sInfo("GatewayAdapter", "...",
		ModuleInfoBase::ModuleOid::GatewayAdapter);

