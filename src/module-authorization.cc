/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "module-authorization.hh"

#include <sofia-sip/sip_extra.h>
#include <sofia-sip/sip_status.h>

#include "agent.hh"

using namespace std;
using namespace flexisip;

// ====================================================================================================================
//  ModuleAuthorization class
// ====================================================================================================================

namespace {

constexpr auth_challenger_t kRegistrarChallenger{401, sip_401_Unauthorized, sip_www_authenticate_class,
                                                 sip_authentication_info_class};
constexpr auth_challenger_t kProxyChallenger{407, sip_407_Proxy_auth_required, sip_proxy_authenticate_class,
                                             sip_proxy_authentication_info_class};

const auto sInfo = ModuleInfo<ModuleAuthorization>(
    "Authorization",
    "The authorization module checks the right of access of SIP requests.\n",
    {"Authentication", "AuthOpenIDConnect", "ExternalAuthentication"},
    ModuleInfoBase::ModuleOid::Authorization,
    [](GenericStruct& moduleConfig) { moduleConfig.get<ConfigBoolean>("enabled")->setDefault("false"); });

// duplicate fromModuleAuthenticationBase ModuleAuthenticationBase
bool validateRequest(const std::shared_ptr<RequestSipEvent>& request) {
	sip_t* sip = request->getMsgSip()->getSip();

	// Do it first to make sure no transaction is created which
	// would send an inappropriate 100 trying response.
	if (sip->sip_request->rq_method == sip_method_ack || sip->sip_request->rq_method == sip_method_cancel ||
	    sip->sip_request->rq_method == sip_method_bye // same as in the sofia auth modules
	) {
		/*ack and cancel shall never be challenged according to the RFC.*/
		return false;
	}

	return true;
}
} // namespace

ModuleAuthorization::ModuleAuthorization(Agent* ag, const ModuleInfoBase* moduleInfo) : Module(ag, moduleInfo) {
}

void ModuleAuthorization::onRequest(shared_ptr<RequestSipEvent>& ev) {
	if (!validateRequest(ev)) return;

	const auto& authResult = ev->getAuthResult();
	if (authResult.trustedHost) {
		LOGD("Access granted: trusted host.");
		return;
	}

	LOGD("Checking asserted identities.");

	sip_t* sip = ev->getMsgSip()->getSip();
	const sip_p_preferred_identity_t* ppi = sip_p_preferred_identity(sip);
	const auto userUri = sofiasip::Url(ppi ? ppi->ppid_url : sip->sip_from->a_url);

	for (const auto& authResult : authResult.challenges) {
		if (authResult.getResult() == RequestSipEvent::AuthResult::Result::Invalid) continue;
		if (authResult.getType() == RequestSipEvent::AuthResult::Type::Bearer) {
			if (!authResult.getIdentity().rfc3261Compare(userUri.get())) {
				LOGD("Asserted identity '%s' doesn't match user identity '%s'.", authResult.getIdentity().str().c_str(),
				     userUri.str().c_str());
				continue;
			}
			LOGD("Accept authorization.");
			return; // on first valid
		}
	}

	AuthStatus as{};
	const auto& challenger =
	    sip->sip_request->rq_method == sip_method_register ? kRegistrarChallenger : kProxyChallenger;

	for (const auto& authModule : mAuthModules) {
		authModule.second->challenge(as, &challenger);
		break; // stop on first available challenge, see how to get both
	}

	if (as.status() >= 400) {
		// log?
		ev->reply(as.status(), as.phrase(), SIPTAG_HEADER(reinterpret_cast<sip_header_t*>(as.info())),
		          SIPTAG_HEADER(reinterpret_cast<sip_header_t*>(as.response())),
		          SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());

	} else ev->reply(500, sip_500_Internal_server_error, TAG_END());
}

void ModuleAuthorization::onResponse(shared_ptr<ResponseSipEvent>&) {
}

// ====================================================================================================================
