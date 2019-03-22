/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2018  Belledonne Communications SARL, All rights reserved.

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

#include <algorithm>
#include <sstream>
#include <stdexcept>

#include <sofia-sip/msg_addr.h>
#include <sofia-sip/sip_extra.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/sip_status.h>

#include <flexisip/plugin.hh>

#include "module-external-authentication.hh"

using namespace std;
using namespace flexisip;

std::ostream &operator<<(std::ostream &os, const http_payload_t *httpPayload) {
	const http_payload_t *httpPayloadBase = reinterpret_cast<const http_payload_t *>(httpPayload);
	if (httpPayload->pl_data) {
		os.write(reinterpret_cast<const char *>(httpPayloadBase->pl_data), httpPayloadBase->pl_len);
	}
	return os;
}

ModuleExternalAuthentication::ModuleExternalAuthentication(Agent *agent) : Module(agent) {
	mProxyChallenger.ach_status = 407; /*SIP_407_PROXY_AUTH_REQUIRED*/
	mProxyChallenger.ach_phrase = sip_407_Proxy_auth_required;
	mProxyChallenger.ach_header = sip_proxy_authenticate_class;
	mProxyChallenger.ach_info = sip_proxy_authentication_info_class;

	mRegistrarChallenger.ach_status = 401; /*SIP_401_UNAUTHORIZED*/
	mRegistrarChallenger.ach_phrase = sip_401_Unauthorized;
	mRegistrarChallenger.ach_header = sip_www_authenticate_class;
	mRegistrarChallenger.ach_info = sip_authentication_info_class;
}

void ModuleExternalAuthentication::onDeclare(GenericStruct *mc) {
	ConfigItemDescriptor items[] = {{
			StringList,
			"auth-domains",
			"List of whitespace separated domain names to challenge. Others are denied.",
			"localhost"
		}, {
			String,
			"remote-auth-uri",
			"URI to use to connect on the external HTTP server on each request. Each token preceded by "
			"'$' character will be replaced before sending the HTTP request. The available tokens are:\n"
			"\t* $method: the method of the SIP request that is being challenged. Ex: REGISTER, INVITE, ...\n"
			"\t* $sip-instance: the value of +sip.instance parameter.\n"
			"\t* $from: the value of the request's 'From:' header\n"
			"\t* $domain: the domain name extracted from the From header's URI\n"
			"\t* all the parameters available in the Authorization header. Ex: $realm, $nonce, $username, ...\n"
			"\n"
			"Ex: https://$realm.example.com/auth?from=$from&cnonce=$cnonce&username=$username",
			""
		}, {
			String,
			"realm-regex",
			"",
			""
		}, {
			StringList,
			"available-algorithms",
			"List of algorithms, separated by whitespaces (valid values are MD5 and SHA-256).\n"
			"This feature allows to force the use of wanted algorithm(s).\n"
			"If the value is empty, then it will authorize all implemented algorithms.",
			"MD5"
		}, {
			Boolean,
			"disable-qop-auth",
			"Disable the QOP authentication method. Default is to use it, use this flag to disable it if needed.",
			"false"
		}, {
			Integer,
			"nonce-expires",
			"Expiration time of nonces, in seconds.",
			"3600"
		},
		config_item_end
	};
	mc->addChildrenValues(items);
	mc->get<ConfigBoolean>("enabled")->setDefault("false");
}

void ModuleExternalAuthentication::onLoad(const GenericStruct *mc) {
	list<string> authDomains = mc->get<ConfigStringList>("auth-domains")->read();

	mAlgorithms = mc->get<ConfigStringList>("available-algorithms")->read();
	if (mAlgorithms.empty()) mAlgorithms = {"MD5", "SHA-256"};
	mAlgorithms.unique();

	bool disableQOPAuth = mc->get<ConfigBoolean>("disable-qop-auth")->read();
	int nonceExpires = mc->get<ConfigInt>("nonce-expires")->read();

	for (const string &domain : authDomains) {
		unique_ptr<ExternalAuthModule> am;
		if (disableQOPAuth) {
			am.reset(new ExternalAuthModule(getAgent()->getRoot(), domain, mAlgorithms.front()));
		} else {
			am.reset(new ExternalAuthModule(getAgent()->getRoot(), domain, mAlgorithms.front(), nonceExpires));
		}
		am->getFormater().setTemplate(mc->get<ConfigString>("remote-auth-uri")->read());
		mAuthModules[domain] = move(am);
	}

	mRealmRegexStr = mc->get<ConfigString>("realm-regex")->get();
	if (!mRealmRegexStr.empty()) {
		try {
			mRealmRegex.assign(mRealmRegexStr);
		} catch (const regex_error &e) {
			LOGF("invalid regex in 'realm-regex': %s", e.what());
		}
	}
}

void ModuleExternalAuthentication::onRequest(std::shared_ptr<RequestSipEvent> &ev) {
	try {
		const shared_ptr<MsgSip> &ms = ev->getMsgSip();
		sip_t *sip = ms->getSip();

		// Do it first to make sure no transaction is created which
		// would send an inappropriate 100 trying response.
		if (sip->sip_request->rq_method == sip_method_ack || sip->sip_request->rq_method == sip_method_cancel ||
			sip->sip_request->rq_method == sip_method_bye // same as in the sofia auth modules
		) {
			/*ack and cancel shall never be challenged according to the RFC.*/
			return;
		}

		sip_p_preferred_identity_t *ppi = nullptr;
		const char *fromDomain = sip->sip_from->a_url[0].url_host;
		if (fromDomain && strcmp(fromDomain, "anonymous.invalid") == 0) {
			ppi = sip_p_preferred_identity(sip);
			if (ppi)
				fromDomain = ppi->ppid_url->url_host;
			else
				LOGD("There is no p-preferred-identity");
		}

		ExternalAuthModule *am = findAuthModule(fromDomain);
		if (am == nullptr) {
			SLOGI << "Unknown domain [" << fromDomain << "]";
			SLOGUE << "Registration failure, domain is forbidden: " << fromDomain;
			ev->reply(403, "Domain forbidden", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
			return;
		}

		const url_t *userUri = ppi ? ppi->ppid_url : sip->sip_from->a_url;
		const char *realm = userUri->url_host;
		if (!mRealmRegexStr.empty()) {
			cmatch m;
			const char *userUriStr = url_as_string(ev->getHome(), userUri);
			if (!regex_search(userUriStr, m, mRealmRegex)) {
				SLOGE << "no realm found in '" << userUriStr << "'. Search regex: '" << mRealmRegexStr << "'";
				ev->reply(500, "Internal error", TAG_END());
				return;
			}
			int index = m.size() == 1 ? 0 : 1;
			realm = su_strndup(ev->getHome(), userUriStr + m.position(index), m.length(index));
		}

		auto *as = new _AuthStatus(ev);
		as->method(sip->sip_request->rq_method_name);
		as->source(msg_addrinfo(ms->getMsg()));
		as->userUri(userUri);
		as->realm(realm);
		as->display(sip->sip_from->a_display);
		if (sip->sip_payload) {
			as->body(sip->sip_payload->pl_data);
			as->bodyLen(sip->sip_payload->pl_len);
		}
		as->usedAlgo() = mAlgorithms;
		as->domain(sip->sip_from->a_url->url_host);
		as->fromHeader(sip_header_as_string(as->home(), reinterpret_cast<sip_header_t *>(sip->sip_from)));

		if (sip->sip_contact) {
			const char *sipInstance = msg_header_find_param(
				reinterpret_cast<msg_common_t *>(sip->sip_contact),
				"+sip.instance"
			);
			as->sipInstance(sipInstance ? sipInstance : "");
		}

		if (sip->sip_request->rq_method == sip_method_register) {
			am->verify(*as, sip->sip_authorization, &mRegistrarChallenger);
		} else {
			am->verify(*as, sip->sip_proxy_authorization, &mProxyChallenger);
		}

		processAuthModuleResponse(*as);
	} catch (const runtime_error &e) {
		SLOGE << e.what();
		ev->reply(500, "Internal error", TAG_END());
	}
}

ExternalAuthModule *ModuleExternalAuthentication::findAuthModule(const std::string name) {
	auto it = mAuthModules.find(name);
	if (it == mAuthModules.end())
		it = mAuthModules.find("*");
	if (it == mAuthModules.end()) {
		for (auto it2 = mAuthModules.begin(); it2 != mAuthModules.end(); ++it2) {
			string domainName = it2->first;
			size_t wildcardPosition = domainName.find("*");
			// if domain has a wildcard in it, try to match
			if (wildcardPosition != string::npos) {
				size_t beforeWildcard = name.find(domainName.substr(0, wildcardPosition));
				size_t afterWildcard = name.find(domainName.substr(wildcardPosition + 1));
				if (beforeWildcard != string::npos && afterWildcard != string::npos) {
					return it2->second.get();
				}
			}
		}
	}
	if (it == mAuthModules.end()) {
		return nullptr;
	}
	return it->second.get();
}

void ModuleExternalAuthentication::processAuthModuleResponse(AuthStatus &as) {
	const shared_ptr<RequestSipEvent> &ev = dynamic_cast<const _AuthStatus &>(as).event();
	auto &authStatus = dynamic_cast<_AuthStatus &>(as);
	if (as.status() == 0) {
		const std::shared_ptr<MsgSip> &ms = ev->getMsgSip();
		sip_t *sip = ms->getSip();
		if (sip->sip_request->rq_method == sip_method_register) {
			msg_auth_t *au = ModuleToolbox::findAuthorizationForRealm(
				ms->getHome(),
				sip->sip_authorization,
				as.realm()
			);
			if (au) msg_header_remove(ms->getMsg(), (msg_pub_t *)sip, (msg_header_t *)au);
		} else {
			msg_auth_t *au = ModuleToolbox::findAuthorizationForRealm(
				ms->getHome(),
				sip->sip_proxy_authorization,
				as.realm()
			);
			if (au->au_next) msg_header_remove(ms->getMsg(), (msg_pub_t *)sip, (msg_header_t *)au->au_next);
			if (au) msg_header_remove(ms->getMsg(), (msg_pub_t *)sip, (msg_header_t *)au);
		}
		if (!authStatus.pAssertedIdentity().empty()) {
			msg_header_add_str(ms->getMsg(), reinterpret_cast<msg_pub_t *>(sip), authStatus.pAssertedIdentity().c_str());
		}
		if (ev->isSuspended()) {
			// The event is re-injected
			getAgent()->injectRequestEvent(ev);
		}
	} else if (as.status() == 100) {
		using std::placeholders::_1;
		ev->suspendProcessing();
		as.callback(std::bind(&ModuleExternalAuthentication::processAuthModuleResponse, this, _1));
		return;
	} else if (as.status() >= 400) {
		if (as.status() == 401 || as.status() == 407) {
			auto log = make_shared<AuthLog>(ev->getMsgSip()->getSip(), authStatus.passwordFound());
			log->setStatusCode(as.status(), as.phrase());
			log->setCompleted();
			ev->setEventLog(log);
		}
		ev->reply(as.status(), as.phrase(),
			SIPTAG_HEADER((const sip_header_t *)as.info()),
			SIPTAG_HEADER((const sip_header_t *)as.response()),
			SIPTAG_REASON_STR(authStatus.reason().empty() ? nullptr : authStatus.reason().c_str()),
			SIPTAG_SERVER_STR(getAgent()->getServerString()),
			TAG_END()
		);
	} else {
		ev->reply(500, "Internal error", TAG_END());
	}
	delete &as;
}

ModuleInfo<ModuleExternalAuthentication> ExternalAuthInfo(
	"ExternalAuthentication",
	"This module performs SIP requests authentication by delegating the digest validation to an external HTTP/HTTPS "
	"server. Like Authentication module, this module is in charge of generating the challenge header if no "
	"authentication header has been found in the SIP request. Once a request with an authentication header is "
	"received, all the information required for challenging is transmitted to the HTTP server via a GET request. "
	"Then, the HTTP server MUST returns a '200 OK' response with a list of key-value formatted as 'Key: value'. "
	"Then, the body is parsed in order to know whether the SIP request must be accepted or rejected."
	"\n"
	"Valid key returned by the server:\n"
	"\t* Status: the status code that Flexisip must reply to the user agent. Only 200, 401, 407, 403 are valid."
	"If 200 is returned, then Flexisip will accept the request and will transmit it to the next module.\n"
	"\t* Phrase: the reason phrase to put aside the status code in the SIP response (optional).\n"
	"\t* Reason: enable to add a 'Reason' header (RFC 3326) to the SIP response should the authentication has failed."
	"This key must be followed by the value of the reason header.\n"
	"\t* P-Asserted-Identity: enable to add a 'P-Asserted-Identity' header (RFC 3325) to the SIP request, once it "
	"pass the authentication.\n"
	"\n"
	"Exemple of response from the HTTP server:\n"
	"\n"
	"Status: 403\n"
	"Phrase: Access denied\n"
	"Reason: Linphone; cause=1; text=\"Calls are forbidden\""
	"authentication ",
	{ "Authentication" },
	ModuleInfoBase::ModuleOid::Plugin
);

FLEXISIP_DECLARE_PLUGIN(ExternalAuthInfo, "External authentication plugin", 1);
