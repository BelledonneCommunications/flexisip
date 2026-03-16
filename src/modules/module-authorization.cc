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

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "agent.hh"
#include "auth/preferred-identity.hh"
#include "flexiapi/config.hh"
#include "utils/transport/http/http-message-context.hh"
#include "utils/transport/http/http2client.hh"

using namespace std;
using namespace std::string_view_literals;
using namespace std::string_literals;

namespace flexisip {

namespace {
constexpr auto kDynamicDomainPath = "/api/spaces";

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
	            DurationMIN,
	            "accounts-refresh-delay",
	            "The duration in minutes between two refreshes of the dynamic domain cache.",
	            "5",
	        },
	        {
	            StringList,
	            "auth-domains",
	            "This parameter is used when no account-manager-server is defined.\n"
	            "List of whitespace separated domains served by the proxy. "
	            "Requests from any other domain are rejected.\n",
	            "localhost",
	        },
	        config_item_end,
	    };
	    moduleConfig.addChildrenValues(items);
	    moduleConfig.get<ConfigBoolean>("enabled")->setDefault("false");

	    const auto authDomainsModeString = moduleConfig.get<ConfigString>("auth-domains-mode");
	    authDomainsModeString->setDeprecatedValue(
	        {"2026-02-27", "2.6.0",
	         "Don't use 'auth-domains-mode=legacy' but:\n"
	         " - 'flexiapi' with the global section 'global::flexiapi' for dynamic domain\n"
	         " - 'static' with the parameters 'auth-domains' for static domains",
	         "legacy"});
	    const auto accountManagerHostString = moduleConfig.get<ConfigString>("account-manager-host");
	    accountManagerHostString->setDeprecated({"2026-02-27", "2.6.0",
	                                             "Don't use 'auth-domains-mode=legacy' with 'account-manager-host' but "
	                                             "the global section 'global::flexiapi' for dynamic domain."});
	    const auto accountManagerPortString = moduleConfig.get<ConfigString>("account-manager-port");
	    accountManagerPortString->setDeprecated({"2026-02-27", "2.6.0",
	                                             "Don't use 'auth-domains-mode=legacy' with 'account-manager-port' but "
	                                             "the global section 'global::flexiapi' for dynamic domain."});
	    const auto accountMangerApiKeyString = moduleConfig.get<ConfigString>("account-manager-api-key");
	    accountMangerApiKeyString->setDeprecated(
	        {"2026-02-27", "2.6.0",
	         "Don't use 'auth-domains-mode=legacy' with 'account-manager-api-key' but "
	         "the global section 'global::flexiapi' for dynamic domain."});
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
                          const unordered_set<string>& authorizedDomains) {
	if (authorizedDomains.find(usrDomain) == authorizedDomains.cend()) {
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

ModuleAuthorization::DynamicDomainManager::DynamicDomainManager(const shared_ptr<sofiasip::SuRoot>& root,
                                                                RestClient&& restClient,
                                                                chrono::milliseconds delay)
    : mLogPrefix(sAuthorizationInfo.getLogPrefix()), mFAMClient{std::move(restClient)}, mTimer(root, delay) {
	mTimer.setForEver([this] { askAccountManager(); });
	askAccountManager();
}

void ModuleAuthorization::DynamicDomainManager::askAccountManager() {
	mFAMClient.get(
	    kDynamicDomainPath,
	    [this](const std::shared_ptr<HttpMessage>&, const std::shared_ptr<HttpResponse>& rep) {
		    onAccountManagerResponse(rep);
	    },
	    [](const std::shared_ptr<HttpMessage>&) {
		    LOGE_CTX(sAuthorizationInfo.getLogPrefix(), "onAccountManagerResponseFailure")
		        << "Received an error while connecting to the account manager, please check your "
		        << sAuthorizationInfo.getLogPrefix()
		        << " configuration settings and make sure that the account manager is correctly configured";
	    });
}

void ModuleAuthorization::DynamicDomainManager::onAccountManagerResponse(const std::shared_ptr<HttpResponse>& rep) {
	if (rep->getStatusCode() != 200) {
		LOGE << "Received error " << rep->getStatusCode()
		     << ", please check your api key validity and that the account manager is running "
		        "properly";
		return;
	}

	try {
		const auto spaces = nlohmann::json::parse(string(rep->getBody().data(), rep->getBody().size()));
		if (!spaces.is_array()) {
			LOGE << "Authorized domains not updated, failed to read spaces";
			return;
		}

		constexpr auto domain = "domain"sv;
		unordered_set<string> authDomains{};

		for (auto i = 0; i < (int)spaces.size(); ++i) {
			const auto& space = spaces[i];
			if (!space.contains(domain) || !space[domain].is_string()) {
				LOGE << "Authorized domains not updated, expect to have a domain in each space";
				return;
			}
			authDomains.emplace(space[domain]);
		}

		mAuthorizedDomains = authDomains;
		LOGI << "Authorized domains updated";
		if (mAuthorizedDomains.empty()) LOGW << "Authorized domains are empty, all requests will be rejected";
	} catch (const exception& e) {
		LOGE << "Unexpected error while parsing response: " << e.what();
	}
}

ModuleAuthorization::ModuleAuthorization(Agent* ag, const ModuleInfoBase* moduleInfo) : Module(ag, moduleInfo) {}

void ModuleAuthorization::onLoad(const GenericStruct* mc) {
	const auto refresh = chrono::duration_cast<chrono::milliseconds>(
	    mc->get<ConfigDuration<chrono::minutes>>("accounts-refresh-delay")->read());
	if (mc->get<ConfigString>("auth-domains-mode")->read() == "legacy") {
		auto host = mc->get<ConfigString>("account-manager-host")->read();
		if (host.empty()) {
			mDomainManager = make_unique<StaticDomainManger>(mc->get<ConfigStringList>("auth-domains")->read());
			return;
		}
		auto port = mc->get<ConfigString>("account-manager-port")->read();
		auto apiKey = mc->get<ConfigString>("account-manager-api-key")->read();
		const auto http2Client = Http2Client::make(*getAgent()->getRoot(), host, port);
		mDomainManager = make_unique<DynamicDomainManager>(getAgent()->getRoot(),
		                                                   RestClient{http2Client,
		                                                              HttpHeaders{
		                                                                  {"accept", "application/json"},
		                                                                  {"x-api-key"s, apiKey},
		                                                              }},
		                                                   refresh);
	} else if (mc->get<ConfigString>("auth-domains-mode")->read() == "flexiapi") {
		mDomainManager = make_unique<DynamicDomainManager>(
		    getAgent()->getRoot(),
		    flexiapi::createRestClient(getAgent()->getConfigManager(), getAgent()->getFlexiApiClient()), refresh);
	} else if (mc->get<ConfigString>("auth-domains-mode")->read() == "static") {
		mDomainManager = make_unique<StaticDomainManger>(mc->get<ConfigStringList>("auth-domains")->read());
	} else {
		throw BadConfigurationValue{mc->get<ConfigString>("auth-domains-mode"),
		                            "expected 'flexiapi', 'static' or 'legacy' (deprecated)"};
	}
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
	const sip_p_preferred_identity_t* ppi = preferredIdentity(msgSip);
	const auto userUri = sofiasip::Url(ppi ? ppi->ppid_url : sip->sip_from->a_url);
	const auto dstUri = sofiasip::Url(sip->sip_to->a_url);

	if (!isRequestDomainValid(userUri.getHost(), dstUri.getHost(), mDomainManager->getAuthorizedDomains())) {
		if (sip->sip_request->rq_method == sip_method_ack) {
			ev->terminateProcessing(); // ACK of 403 response should not be processed further
			return {};
		}

		ev->reply(403, "Domain forbidden", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return {};
	}

	// ACK and CANCEL shall never be challenged according to the RFC 3261-22.1
	if (sip->sip_request->rq_method == sip_method_ack) {
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

} // namespace flexisip