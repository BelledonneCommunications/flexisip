/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <limits.h>

#include <sofia-sip/nua.h>
#include <sofia-sip/sip_status.h>

#include <flexisip/module.hh>

#include "agent.hh"
#include "authdb.hh"
#include "registrardb.hh"

using namespace std;
using namespace flexisip;

class GatewayAdapter;

class GatewayRegister {
	typedef enum { INITIAL, REGISTRING, REGISTRED } State;
	State state;
	su_home_t home;
	nua_handle_t *nh;
	sip_from_t *from;
	sip_to_t *to;
	string password;
	string routingParam;
	sip_contact_t *contact;

	static StatCounter64 *mCountInitialMsg;
	static StatCounter64 *mCountRegisteringMsg200;
	static StatCounter64 *mCountRegisteringMsg408;
	static StatCounter64 *mCountRegisteringMsg401;
	static StatCounter64 *mCountRegisteringMsg407;
	static StatCounter64 *mCountRegisteringMsgUnknown;
	static StatCounter64 *mCountRegisteredUnknown;
	static StatCounter64 *mCountStart;
	static StatCounter64 *mCountError;
	static StatCounter64 *mCountEnd;
	static StatCounter64 *mCountForkToGateway;
	static StatCounter64 *mCountDomainRewrite;

public:
	void sendRegister();
	GatewayRegister(Agent *ag, nua_t *nua, sip_from_t *from, sip_to_t *to, sip_contact_t *contact,
					const sip_expires_t *global_expire);
	~GatewayRegister();
	void onMessage(const sip_t *sip);
	void onError(const char *message, ...);

	void start();
	void end();
	void authenticate(const msg_param_t *au_params);

	sip_from_t *getFrom() const {
		return from;
	}

	sip_to_t *getTo() const {
		return to;
	}

	void setPassword(const string &ipassword) {
		this->password = ipassword;
	}

	const string &getPassword() {
		return password;
	}
	static void onDeclare(GenericStruct *mc) {
		mCountInitialMsg = mc->createStat("count-gr-initial-msg", "Number of msg received while in initial state");
		mCountRegisteringMsg200 =
			mc->createStat("count-gr-registering-200", "Number of 200 received while in registering state");
		mCountRegisteringMsg408 =
			mc->createStat("count-gr-registering-408", "Number of 408 received while in registering state");
		mCountRegisteringMsg401 =
			mc->createStat("count-gr-registering-401", "Number of 401 received while in registering state");
		mCountRegisteringMsg407 =
			mc->createStat("count-gr-registering-407", "Number of 407 received while in registering state");
		mCountRegisteringMsgUnknown =
			mc->createStat("count-gr-registering-unknown", "Number of unknown received while in registering state");
		mCountRegisteredUnknown =
			mc->createStat("count-gr-registered-unknown", "Number of msg received while in registered state");
		mCountStart = mc->createStat("count-gr-start", "Number of calls to start()");
		mCountError = mc->createStat("count-gr-error", "Number of calls to error()");
		mCountEnd = mc->createStat("count-gr-end", "Number of calls to end()");
	}

private:
	// Listener class NEED to copy the shared pointer
	class OnAuthListener : public AuthDbListener {
	private:
		GatewayRegister *gw;

	public:
		OnAuthListener(GatewayRegister *igw) : gw(igw) {
		}

		void checkPassword(const char *ipassword) {
			LOGD("Found password");
			gw->setPassword(ipassword);
			gw->sendRegister();
		}

		virtual void onResult(AuthDbResult result, const std::string &passwd) {
			if (result == AuthDbResult::PASSWORD_FOUND) {
				checkPassword(passwd.c_str());
			} else {
				LOGE("GatewayRegister onResult(): Can't find user password, give up.");
			}
			delete this;
		}

		virtual void onResult(AuthDbResult result, const vector<passwd_algo_t> &passwd) {
			if (result == AuthDbResult::PASSWORD_FOUND) {
				checkPassword(passwd.front().pass.c_str());
			} else {
				LOGE("GatewayRegister onResult(): Can't find user password, give up.");
			}
			delete this;
		}

		virtual void finishVerifyAlgos([[maybe_unused]] const vector<passwd_algo_t> &pass) {
			return;
		}
	};

	// Listener class NEED to copy the shared pointer
	class OnFetchListener : public ContactUpdateListener {
	private:
		GatewayRegister *gw;

	public:
		OnFetchListener(GatewayRegister *igw) : gw(igw) {
		}

		~OnFetchListener() {
		}

		void onInvalid() override{
			LOGD("GATEWAY: invalid");
		}

		void onRecordFound(const shared_ptr<Record> &r) override {
			if (r == NULL) {
				LOGD("Record doesn't exist. Fork");
				url_t *url = gw->getFrom()->a_url;
				AuthDbBackend::get().getPassword(url->url_user, url->url_host, url->url_user, new OnAuthListener(gw));
			} else {
				LOGD("Record already exists. Not forked");
			}
		}

		void onError() override{
			gw->onError("Fetch error.");
		}

		void onContactUpdated([[maybe_unused]] const shared_ptr<ExtendedContact> &ec) override {}
	};
};

StatCounter64 *GatewayRegister::mCountInitialMsg = NULL;
StatCounter64 *GatewayRegister::mCountRegisteringMsg200 = NULL;
StatCounter64 *GatewayRegister::mCountRegisteringMsg408 = NULL;
StatCounter64 *GatewayRegister::mCountRegisteringMsg401 = NULL;
StatCounter64 *GatewayRegister::mCountRegisteringMsg407 = NULL;
StatCounter64 *GatewayRegister::mCountRegisteringMsgUnknown = NULL;
StatCounter64 *GatewayRegister::mCountRegisteredUnknown = NULL;
StatCounter64 *GatewayRegister::mCountStart = NULL;
StatCounter64 *GatewayRegister::mCountError = NULL;
StatCounter64 *GatewayRegister::mCountEnd = NULL;
StatCounter64 *GatewayRegister::mCountForkToGateway = NULL;
StatCounter64 *GatewayRegister::mCountDomainRewrite = NULL;

GatewayRegister::GatewayRegister(Agent *ag, nua_t *nua, sip_from_t *sip_from, sip_to_t *sip_to,
								sip_contact_t *sip_contact, const sip_expires_t *global_expire) {
	su_home_init(&home);

	url_t *domain = NULL;
	GenericStruct *cr = GenericManager::get()->getRoot();
	GenericStruct *ma = cr->get<GenericStruct>("module::GatewayAdapter");
	string domainString = ma->get<ConfigString>("gateway-domain")->read();
	int forcedExpireValue = ma->get<ConfigInt>("forced-expire")->read();
	routingParam = ma->get<ConfigString>("routing-param")->read();
	if (!domainString.empty()) {
		domain = url_make(&home, domainString.c_str());
	}

	from = sip_from_dup(&home, sip_from);
	to = sip_to_dup(&home, sip_to);

	// Copy contact
	const url_t *url = ag->getPreferredRouteUrl();
	const char *port = url->url_port;
	const char *user = sip_contact->m_url->url_user;
	int expire = forcedExpireValue != -1
					? forcedExpireValue
					: ExtendedContact::resolveExpire(sip_contact->m_expires,
													global_expire != NULL ? global_expire->ex_delta : -1);
	if (port) {
		contact =
			sip_contact_format(&home, "<%s:%s@%s:%s>;expires=%i", url->url_scheme, user, url->url_host, port, expire);
	} else {
		contact = sip_contact_format(&home, "<%s:%s@%s>;expires=%i", url->url_scheme, user, url->url_host, expire);
	}

	// Override domains?
	if (domain != NULL) {
		from->a_url->url_host = domain->url_host;
		to->a_url->url_host = domain->url_host;
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

	// Add a parameter with the domain so that when the gateway sends an INVITE
	// to us we know where to route it.
	ostringstream oss;
	oss << routingParam << "=" << from->a_url->url_host;
	string routing_param(oss.str());
	url_param_add(&home, contact->m_url, routing_param.c_str());
	nua_register(nh, SIPTAG_CONTACT(contact), TAG_END());
}

void GatewayRegister::authenticate(const msg_param_t *au_params) {
	ostringstream digest;
	digest << "Digest:";

	const char *realm = msg_params_find(au_params, "realm=");
	if (realm[0] != '"')
		digest << "\"";
	digest << realm;
	if (realm[strlen(realm) - 1] != '"')
		digest << "\"";

	string user(getFrom()->a_url->url_user);

	digest << ":" << user << ":" << password;

	string digeststr(digest.str());
	// LOGD("GR authentication with %s", digeststr.c_str()); // expose password
	nua_authenticate(nh, NUTAG_AUTH(digeststr.c_str()), TAG_END());
}

void GatewayRegister::onMessage(const sip_t *sip) {
	switch (state) {
		case State::INITIAL:
			onError("Can't receive message in this state");
			++*mCountInitialMsg;
			break;

		case State::REGISTRING:
			switch (sip->sip_status->st_status) {
				case 200:
					++*mCountRegisteringMsg200;
					LOGD("REGISTER done");
					state = State::REGISTRED;
					end(); // TODO: stop the dialog?
					break;
				case 408:
					++*mCountRegisteringMsg408;
					LOGD("REGISTER timeout");
					end();
					break;
				case 401:
					++*mCountRegisteringMsg401;
					LOGD("REGISTER challenged 401");
					authenticate(sip->sip_www_authenticate->au_params);
					break;
				case 407:
					++*mCountRegisteringMsg407;
					LOGD("REGISTER challenged 407");
					authenticate(sip->sip_proxy_authenticate->au_params);
					break;
				default:
					++*mCountRegisteringMsgUnknown;
					LOGD("REGISTER not handled response: %i", sip->sip_status->st_status);
					end();
					break;
			}
			break;

		case State::REGISTRED:
			++*mCountRegisteredUnknown;
			LOGD("new message %i", sip->sip_status->st_status);
			break;
	}
}

void GatewayRegister::onError(const char *message, ...) {
	++*mCountError;
	va_list args;
	va_start(args, message);
	LOGE("%s", message);
	va_end(args);
	end();
}

void GatewayRegister::start() {
	LOGD("GatewayRegister start");
	SipUri fromUri(from->a_url);
	LOGD("Fetching binding");
	++*mCountStart;
	RegistrarDb::get()->fetch(fromUri, make_shared<OnFetchListener>(this));
}

void GatewayRegister::end() {
	++*mCountEnd;
	LOGD("GatewayRegister end");
}

class GatewayAdapter : public Module {
	StatCounter64 *mCountForkToGateway;
	StatCounter64 *mCountDomainRewrite;

public:
	GatewayAdapter(Agent *ag);

	~GatewayAdapter();

	virtual void onDeclare(GenericStruct *mc);

	virtual void onLoad(const GenericStruct *module_config);

	virtual void onRequest(shared_ptr<RequestSipEvent> &ev);

	virtual void onResponse(shared_ptr<ResponseSipEvent> &ev);

	virtual bool isValidNextConfig(const ConfigValue &cv);

private:
	static void nua_callback(nua_event_t event, int status, char const *phrase, nua_t *nua, nua_magic_t *_t,
							nua_handle_t *nh, nua_hmagic_t *hmagic, sip_t const *sip, tagi_t tags[]);

	static ModuleInfo<GatewayAdapter> sInfo;
	nua_t *nua;
	url_t *gateway_url;
	bool mRegisterOnGateway, mForkToGateway;
	string mRoutingParam;
	su_home_t home;
};

GatewayAdapter::GatewayAdapter(Agent *ag) : Module(ag), nua(NULL) {
	su_home_init(&home);
}

GatewayAdapter::~GatewayAdapter() {
	if (nua != NULL) {
		nua_shutdown(nua);
		mAgent->getRoot()->run(); // Correctly wait for nua_destroy
	}
	su_home_deinit(&home);
}

void GatewayAdapter::onDeclare(GenericStruct *mc) {
	mc->get<ConfigBoolean>("enabled")->setDefault("false");
	ConfigItemDescriptor items[] = {
		{Integer, "forced-expire",
		"Force expire of gw register to a value. -1 to use expire provided in received register.", "-1"},
		{String, "gateway", "A gateway uri where to send all requests, as a SIP url (eg 'sip:gateway.example.net')",
		""},
		{String, "gateway-domain", "Modify the from and to domains of incoming register", ""},
		{Boolean, "fork-to-gateway", "The gateway will be added to the incoming register contacts.", "true"},
		{Boolean, "register-on-gateway",
		"Send a REGISTER to the gateway using "
		"this server as a contact in order to be notified on incoming calls by the gateway.",
		"true"},
		{String, "routing-param",
		"Parameter name hosting the incoming domain that will be sent in the register to the gateway.",
		"routing-domain"},
		config_item_end};
	mc->addChildrenValues(items);
	GatewayRegister::onDeclare(mc);
	mCountForkToGateway = mc->createStat("count-fork-to-gateway", "Number of forks to gateway.");
	mCountDomainRewrite = mc->createStat("count-domain-rewrite", "Number of domain rewrite.");
}

bool GatewayAdapter::isValidNextConfig(const ConfigValue &cv) {
	GenericStruct *module_config = dynamic_cast<GenericStruct *>(cv.getParent());
	if (!module_config->get<ConfigBoolean>("enabled")->readNext())
		return true;
	if (cv.getName() == "gateway") {
		if (cv.getNextValue().empty()) {
			LOGE("Empty value GatewayAdapter::%s=%s", cv.getName().c_str(), cv.getNextValue().c_str());
			return false;
		}
	}
	return true;
}

void GatewayAdapter::onLoad(const GenericStruct *module_config) {
	// sendTrap("Error loading module Gateway adaptor");
	string gateway = module_config->get<ConfigString>("gateway")->read();
	mRegisterOnGateway = module_config->get<ConfigBoolean>("register-on-gateway")->read();
	mForkToGateway = module_config->get<ConfigBoolean>("fork-to-gateway")->read();
	mRoutingParam = module_config->get<ConfigString>("routing-param")->read();
	gateway_url = url_make(&home, gateway.c_str());
	if (mRegisterOnGateway) {
		char *url = su_sprintf(&home, "sip:%s:*", mAgent->getPublicIp().c_str());
		nua = nua_create(mAgent->getRoot()->getCPtr(), nua_callback, this, NUTAG_URL(url),
						NUTAG_OUTBOUND("no-validate no-natify no-options-keepalive"), NUTAG_PROXY(gateway.c_str()),
						TAG_END());
	}
}

void GatewayAdapter::onRequest(shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();

	if (sip->sip_request->rq_method == sip_method_register && sip->sip_contact != nullptr) {
		try {
			GatewayRegister *gr = nullptr;
			if (mRegisterOnGateway) {
				gr = new GatewayRegister(getAgent(), nua, sip->sip_from, sip->sip_to, sip->sip_contact, sip->sip_expires);
			}

			if (mForkToGateway) {
				sip_contact_t *contact;
				if (gateway_url->url_port) {
					contact = sip_contact_format(&home, "<sip:%s@%s:%s>;expires=%i", sip->sip_contact->m_url->url_user,
												gateway_url->url_host, gateway_url->url_port, INT_MAX);
				} else {
					contact = sip_contact_format(&home, "<sip:%s@%s>;expires=%i", sip->sip_contact->m_url->url_user,
												gateway_url->url_host, INT_MAX);
				}
				contact->m_next = sip->sip_contact;
				sip->sip_contact = contact;
				++*mCountForkToGateway;
			}

			if (mRegisterOnGateway && gr) {
				gr->start();
			}

		} catch (const sofiasip::InvalidUrlError &e) {
			// Thrown by GatewayRegister::start() when From URI isn't a SIP URI.
			SLOGE << "Invalid 'From' Uri [" << e.what() << "]";
			ev->reply(400, "Bad request", TAG_END());
		}
	} else {
		/* check if request-uri contains a routing-domain parameter, so that we can route back to the client */
		char routing_param[64];
		url_t *dest = sip->sip_request->rq_url;
		if (url_param(dest->url_params, mRoutingParam.c_str(), routing_param, sizeof(routing_param))) {
			++*mCountDomainRewrite;
			LOGD("Rewriting request uri and to with domain %s", routing_param);
			dest->url_host = su_strdup(ms->getHome(), routing_param);
			sip->sip_to->a_url[0].url_host = su_strdup(ms->getHome(), routing_param);
		}
	}
}

void GatewayAdapter::onResponse([[maybe_unused]] shared_ptr<ResponseSipEvent> &ev) {
}

void GatewayAdapter::nua_callback(nua_event_t event, int status, [[maybe_unused]] char const *phrase, [[maybe_unused]] nua_t *nua, nua_magic_t *ctx,
								[[maybe_unused]] nua_handle_t *nh, nua_hmagic_t *hmagic, sip_t const *sip, [[maybe_unused]] tagi_t tags[]) {
	GatewayRegister *gr = (GatewayRegister *)hmagic;

	if (event == nua_r_shutdown && status >= 200) {
		GatewayAdapter *ga = (GatewayAdapter *)ctx;
		if (ga != NULL) {
			nua_destroy(ga->nua);
			ga->getAgent()->getRoot()->quit();
		}
		return;
	}

	if (gr != NULL) {
		if (sip != NULL) {
			gr->onMessage(sip);
		}
	}
}

ModuleInfo<GatewayAdapter> GatewayAdapter::sInfo(
	"GatewayAdapter",
	"No documentation at the moment.",
	{ "RegEvent" },
	ModuleInfoBase::ModuleOid::GatewayAdapter, ModuleClass::Experimental
);
