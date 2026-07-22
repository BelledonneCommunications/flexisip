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

#include "modules/module-authorization.hh"

#include <sofia-sip/sip_status.h>

#include "agent.hh"
#include "auth/preferred-identity.hh"

using namespace std;
using namespace std::string_view_literals;
using namespace std::string_literals;

namespace flexisip {

namespace {

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
	            DurationMIN,
	            "accounts-refresh-delay",
	            "The duration in minutes between two refreshes of the dynamic domain cache.",
	            "5",
	        },

	        // Deprecated parameters.
	        {
	            String,
	            "auth-domains-mode",
	            "Defines how the domains are loaded. You can use :\n"
	            " - 'flexiapi': dynamic domain loading from the flexiapi, uses 'global::flexiapi' connection configs.\n"
	            " - 'static': domains are statically loaded from 'auth-domains' config.\n"
	            " - 'legacy': as for Flexisip 2.5 and before, uses account-manager config ('account-manager-host', "
	            "...) if present, 'auth-domains' if not.",
	            "legacy",
	        },
	        {
	            String,
	            "account-manager-host",
	            "The HTTPS URL of the flexisip account manager.\n"
	            "This parameter MUST be set for dynamic domain loading.",
	            "",
	        },
	        {
	            String,
	            "account-manager-port",
	            "The listening port of the flexisip account manager.\n",
	            "443",
	        },
	        {
	            String,
	            "account-manager-api-key",
	            "The token used to connect to the flexisip account manager.\n"
	            "This parameter MUST be set for dynamic domain loading.",
	            "",
	        },
	        {
	            StringList,
	            "auth-domains",
	            "This parameter is used when no account-manager-server is defined.\n"
	            "List of whitespace separated domains served by the proxy. "
	            "Requests from any other domain are rejected.\n",
	            "",
	        },
	        config_item_end,
	    };
	    moduleConfig.addChildrenValues(items);
	    moduleConfig.get<ConfigBoolean>("enabled")->setDefault("false");

	    const GenericEntry::DeprecationInfo info{"2026-07-22", "2.7.0", "Use 'global/domains-configuration' instead"};

	    for (const auto& fieldName : {
	             "auth-domains-mode",
	             "account-manager-host",
	             "account-manager-port",
	             "account-manager-api-key",
	         }) {
		    auto* field = moduleConfig.get<ConfigString>(fieldName);
		    field->setDeprecated(info);
	    }

	    auto* authDomainsField = moduleConfig.get<ConfigStringList>("auth-domains");
	    authDomainsField->setDeprecated(info);
    });

bool isAuthorized(const MsgSip& msgSip) {
	const sip_t* sip = msgSip.getSip();

	if (sip->sip_request->rq_method == sip_method_cancel ||
	    sip->sip_request->rq_method == sip_method_bye // same as in the sofia auth modules
	)
		return true;

	return false;
}

bool isRequestDomainValid(const string& usrDomain,
                          const string& dstDomain,
                          const std::shared_ptr<SpacesStore>& spacesStore) {
	if (!spacesStore || !spacesStore->hasDomain(usrDomain)) {
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

ModuleAuthorization::ModuleAuthorization(Agent* ag, const ModuleInfoBase* moduleInfo)
    : Module(ag, moduleInfo), mSpacesStore(ag->getSpacesStore()) {}

unique_ptr<RequestSipEvent> ModuleAuthorization::onRequest(unique_ptr<RequestSipEvent>&& ev) {
	const auto& authResult = ev->getAuthResult();

	// Accept all requests from a trusted host
	if (authResult.trustedHost) {
		LOGD << "Access granted: trusted host";
		return std::move(ev);
	}

	const auto msgSip = *ev->getMsgSip();
	const sip_t* sip = msgSip.getSip();
	const sip_p_preferred_identity_t* ppi = preferredIdentity(msgSip);
	const auto userUri = sofiasip::Url(ppi ? ppi->ppid_url : sip->sip_from->a_url);
	const auto dstUri = sofiasip::Url(sip->sip_to->a_url);
	const auto method = sip->sip_request->rq_method;

	if (!isRequestDomainValid(userUri.getHost(), dstUri.getHost(), mSpacesStore)) {
		if (method == sip_method_ack) {
			ev->terminateProcessing(); // ACK of 403 response should not be processed further
			return {};
		}

		ev->reply(403, "Domain forbidden", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return {};
	}

	// ACK and CANCEL shall never be challenged according to the RFC 3261-22.1
	if (method == sip_method_ack) {
		// expect an ACK to be authenticated
		// the challenge result is not checked, as a valid credential in the INVITE could become invalid in the ACK
		// (e.g. JWT expiration)
		if (authResult.challenges.empty()) {
			ev->terminateProcessing();
			return {};
		}
		return std::move(ev);
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

	std::shared_ptr<AuthStatus> as{};
	for (const auto& challenger : mAuthChallengers) {
		as = challenger->challenge(method, userUri.getHost());
		if (as) break; // stop on first available challenge
	}

	if (as && as->status() >= 400) {
		ev->reply(as->status(), as->phrase(), SIPTAG_HEADER(reinterpret_cast<sip_header_t*>(as->info())),
		          SIPTAG_HEADER(reinterpret_cast<sip_header_t*>(as->response())),
		          SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return {};
	}
	// when no challenge available
	ev->reply(403, "Forbidden", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	return {};
}

} // namespace flexisip