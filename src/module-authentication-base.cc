/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2010 Belledonne Communications SARL, All rights reserved.

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

#include <sofia-sip/msg_addr.h>
#include <sofia-sip/sip_extra.h>

#include "agent.hh"
#include "module-authentication-base.hh"

using namespace std;

namespace flexisip {

void ModuleAuthenticationBase::onDeclare(GenericStruct *mc) {
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

void ModuleAuthenticationBase::onLoad(const GenericStruct *mc) {
	list<string> authDomains = mc->get<ConfigStringList>("auth-domains")->read();

	mAlgorithms = mc->get<ConfigStringList>("available-algorithms")->read();
	if (mAlgorithms.empty()) mAlgorithms = {"MD5", "SHA-256"};
	mAlgorithms.unique();

	bool disableQOPAuth = mc->get<ConfigBoolean>("disable-qop-auth")->read();
	int nonceExpires = mc->get<ConfigInt>("nonce-expires")->read();

	for (const string &domain : authDomains) {
		unique_ptr<FlexisipAuthModuleBase> am;
		if (disableQOPAuth) {
			am.reset(createAuthModule(domain, mAlgorithms.front()));
		} else {
			am.reset(createAuthModule(domain, mAlgorithms.front(), nonceExpires));
		}
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

void ModuleAuthenticationBase::onRequest(std::shared_ptr<RequestSipEvent> &ev) {
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

		FlexisipAuthModuleBase *am = findAuthModule(fromDomain);
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

		FlexisipAuthStatus *as = createAuthStatus(ev, userUri);
		processAuthModuleResponse(*as);
	} catch (const runtime_error &e) {
		SLOGE << e.what();
		ev->reply(500, "Internal error", TAG_END());
	}
}

void ModuleAuthenticationBase::processAuthModuleResponse(AuthStatus &as) {
	auto &fAs = dynamic_cast<FlexisipAuthStatus &>(as);
	const shared_ptr<RequestSipEvent> &ev = fAs.event();
// 	auto &authStatus = dynamic_cast<_AuthStatus &>(as);
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
// 		if (!authStatus.pAssertedIdentity().empty()) {
// 			msg_header_add_str(ms->getMsg(), reinterpret_cast<msg_pub_t *>(sip), authStatus.pAssertedIdentity().c_str());
// 		}
		if (ev->isSuspended()) {
			// The event is re-injected
			getAgent()->injectRequestEvent(ev);
		}
	} else if (as.status() == 100) {
		using std::placeholders::_1;
		ev->suspendProcessing();
		as.callback(std::bind(&ModuleAuthenticationBase::processAuthModuleResponse, this, _1));
		return;
	} else if (as.status() >= 400) {
		if (as.status() == 401 || as.status() == 407) {
			auto log = make_shared<AuthLog>(ev->getMsgSip()->getSip(), fAs.passwordFound());
			log->setStatusCode(as.status(), as.phrase());
			log->setCompleted();
			ev->setEventLog(log);
		}
		ev->reply(as.status(), as.phrase(),
				  SIPTAG_HEADER((const sip_header_t *)as.info()),
				  SIPTAG_HEADER((const sip_header_t *)as.response()),
// 				  SIPTAG_REASON_STR(authStatus.reason().empty() ? nullptr : authStatus.reason().c_str()),
				  SIPTAG_SERVER_STR(getAgent()->getServerString()),
				  TAG_END()
		);
	} else {
		ev->reply(500, "Internal error", TAG_END());
	}
	delete &as;
}

FlexisipAuthModuleBase *ModuleAuthenticationBase::findAuthModule(const std::string name) {
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

void ModuleAuthenticationBase::configureAuthStatus(FlexisipAuthStatus &as, const std::shared_ptr<RequestSipEvent> &ev, const url_t *userUri) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();

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

	as.method(sip->sip_request->rq_method_name);
	as.source(msg_addrinfo(ms->getMsg()));
	as.userUri(userUri);
	as.realm(realm);
	as.display(sip->sip_from->a_display);
	if (sip->sip_payload) {
		as.body(sip->sip_payload->pl_data);
		as.bodyLen(sip->sip_payload->pl_len);
	}
// 	as.usedAlgo() = mAlgorithms;
// 	as.domain(sip->sip_from->a_url->url_host);
// 	as.fromHeader(sip_header_as_string(as.home(), reinterpret_cast<sip_header_t *>(sip->sip_from)));

// 	if (sip->sip_contact) {
// 		const char *sipInstance = msg_header_find_param(reinterpret_cast<msg_common_t *>(sip->sip_contact), "+sip.instance");
// 		as.sipInstance(sipInstance ? sipInstance : "");
// 	}
}

}
