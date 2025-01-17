/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "module-authorization.hh"

#include <sofia-sip/sip_extra.h>
#include <sofia-sip/sip_status.h>

#include "agent.hh"

using namespace std;
using namespace std::string_literals;

namespace flexisip {

namespace {

constexpr auth_challenger_t kRegistrarChallenger{401, sip_401_Unauthorized, sip_www_authenticate_class,
                                                 sip_authentication_info_class};
constexpr auth_challenger_t kProxyChallenger{407, sip_407_Proxy_auth_required, sip_proxy_authenticate_class,
                                             sip_proxy_authentication_info_class};

const auto sAuthorizationInfo = ModuleInfo<ModuleAuthorization>(
    "Authorization",
    "The authorization module checks the right of access of SIP requests.\n"
    "It is not in charge of authentication, but works in conjonction with the authentication modules.\n"
    "This module is convenient for proxies serving multiple SIP domains, it ensures that cross-domain requests are "
    "rejected. Two users can only send requests to each other if they belong to the same domain.\n",
    {"Authentication", "AuthTrustedHosts", "AuthOpenIDConnect", "ExternalAuthentication"},
    ModuleInfoBase::ModuleOid::Authorization,
    [](GenericStruct& moduleConfig) {
	    ConfigItemDescriptor items[] = {
	        {
	            StringList,
	            "auth-domains",
	            "List of whitespace separated domains served by the proxy. "
	            "Requests from any other domain are rejected.\n",
	            "localhost",
	        },
	        config_item_end,
	    };
	    moduleConfig.addChildrenValues(items);
	    moduleConfig.get<ConfigBoolean>("enabled")->setDefault("false");
    });

bool isAuthorized(const MsgSip& msgSip) {
	const sip_t* sip = msgSip.getSip();

	if (sip->sip_request->rq_method == sip_method_cancel ||
	    sip->sip_request->rq_method == sip_method_bye // same as in the sofia auth modules
	) {
		/*ack and cancel shall never be challenged according to the RFC 3261-22.1.*/
		return true;
	}
	return false;
}

bool isRequestDomainValid(const string& usrDomain, const string& dstDomain, const list<string>& authorizedDomains) {
	if (find(authorizedDomains.cbegin(), authorizedDomains.cend(), usrDomain) == authorizedDomains.cend()) {
		LOGI_CTX(sAuthorizationInfo.getLogPrefix()) << "Unauthorized domain: '" << usrDomain << "'";
		return false;
	}
	if (usrDomain != dstDomain) {
		LOGI_CTX(sAuthorizationInfo.getLogPrefix()) << "Unauthorized inter domain request: destination domain '"
		                                            << dstDomain << "' doesn't match user domain '" << usrDomain << "'";
		return false;
	}
	return true;
}
} // namespace

ModuleAuthorization::ModuleAuthorization(Agent* ag, const ModuleInfoBase* moduleInfo) : Module(ag, moduleInfo) {
}

void ModuleAuthorization::onLoad(const GenericStruct* mc) {
	mAuthorizedDomains = mc->get<ConfigStringList>("auth-domains")->read();
}

unique_ptr<RequestSipEvent> ModuleAuthorization::onRequest(unique_ptr<RequestSipEvent>&& ev) {
	const auto& authResult = ev->getAuthResult();

	// Accept all requests from a trusted host
	if (authResult.trustedHost) {
		LOGD << "Access granted: trusted host";
		return std::move(ev);
	}

	const auto msgSip = *ev->getMsgSip();
	const sip_t* sip = msgSip.getSip();
	const sip_p_preferred_identity_t* ppi = sip_p_preferred_identity(sip);
	const auto userUri = sofiasip::Url(ppi ? ppi->ppid_url : sip->sip_from->a_url);
	const auto dstUri = sofiasip::Url(sip->sip_to->a_url);

	if (!isRequestDomainValid(userUri.getHost(), dstUri.getHost(), mAuthorizedDomains)) {
		if (sip->sip_request->rq_method == sip_method_ack) {
			ev->terminateProcessing(); // ACK of 403 response should not be processed further
			return {};
		}

		ev->reply(403, "Domain forbidden", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return {};
	}

	if (isAuthorized(msgSip)) return std::move(ev);

	// Stateful transaction state, for example an ACK will be linked to the corresponding INVITE by nta
	ev->createIncomingTransaction();

	LOGD << "Checking asserted identities";

	for (const auto& challenge : authResult.challenges) {
		if (challenge.getResult() == RequestSipEvent::AuthResult::Result::Invalid) continue;
		if (challenge.getType() == RequestSipEvent::AuthResult::Type::Bearer) {
			if (!challenge.getIdentity().rfc3261Compare(userUri.get())) {
				LOGI << "Asserted identity '" << challenge.getIdentity().str() << "' does not match user identity '"
				     << userUri.str() << "'";
				continue;
			}
			LOGI << "Accept authorization";
			return std::move(ev); // on first valid
		}
	}

	AuthStatus as{};
	const auto& challenger =
	    sip->sip_request->rq_method == sip_method_register ? kRegistrarChallenger : kProxyChallenger;

	for (const auto& authModule : mAuthModules) {
		as.status(challenger.ach_status);
		as.phrase(challenger.ach_phrase);
		authModule.second->challenge(as, &challenger);
		break; // stop on first available challenge, see how to get both
	}

	if (as.status() >= 400) {
		ev->reply(as.status(), as.phrase(), SIPTAG_HEADER(reinterpret_cast<sip_header_t*>(as.info())),
		          SIPTAG_HEADER(reinterpret_cast<sip_header_t*>(as.response())),
		          SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return {};
	}
	// when no challenge available
	ev->reply(403, "Forbidden", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	return {};
}

unique_ptr<ResponseSipEvent> ModuleAuthorization::onResponse(unique_ptr<ResponseSipEvent>&& ev) {
	return std::move(ev);
}

} // namespace flexisip