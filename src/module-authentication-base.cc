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

#include "flexisip/module-authentication-base.hh"

#include <sofia-sip/msg_addr.h>
#include <sofia-sip/sip_status.h>

#include "agent.hh"
#include "auth/preferred-identity.hh"
#include "auth/realm-extractor.hh"
#include "eventlogs/events/eventlogs.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "exceptions/bad-configuration.hh"
#include "flexisip/flexisip-exception.hh"
#include "module-toolbox.hh"
#include "utils/string-utils.hh"

using namespace std;

namespace flexisip {

void ModuleAuthenticationBase::declareConfig(GenericStruct& moduleConfig) {
	ConfigItemDescriptor items[] = {
	    {
	        StringList,
	        "trusted-hosts",
	        "List of whitespace-separated IP addresses which will be judged as trustful. Messages coming from these "
	        "addresses won't be challenged.",
	        "",
	    },
	    {
	        StringList,
	        "auth-domains",
	        "List of whitespace separated domains to challenge. Others are automatically denied. The wildcard domain "
	        "'*' "
	        "is accepted, "
	        "which means that requests are challenged whatever the originating domain is. This is convenient for a "
	        "proxy "
	        "serving multiple SIP domains. ",
	        "localhost",
	    },
	    {
	        StringList,
	        "available-algorithms",
	        "List of digest algorithms to use for password hashing. Think this setting as filter applied after "
	        "fetching "
	        "the credentials of a user from the user database. For example, if a user has its password hashed by MD5 "
	        "and "
	        "SHA-256 but 'available-algorithms' only has MD5, then only a MD5-based challenged will be submitted to "
	        "the UAC.\n"
	        "Furthermore, should a user have several hashed passwords and these are present in the list, then a "
	        "challenge "
	        "header will be put in the 401 response for each fetched password in the order given by the list.\n"
	        "Supported algorithms are MD5 and SHA-256.",
	        "MD5",
	    },
	    {
	        Boolean,
	        "disable-qop-auth",
	        "Disable the QOP authentication method. Default is to use it, use this flag to disable it if needed.",
	        "false",
	    },
	    {
	        BooleanExpr,
	        "no-403",
	        "Don't reply 403 when authentication fails. Instead, generate a new 401 (or 407) response containing "
	        "a new challenge.",
	        "false",
	    },
	    {
	        DurationS,
	        "nonce-expires",
	        "Expiration time before generating a new nonce.",
	        "3600",
	    },
	    {
	        String,
	        "realm",
	        "The realm to use for digest authentication. It will used whatever the domain of the From-URI.\n"
	        "If the value starts with 'regex:', then this parameter will have the same effect than 'realm-regex', "
	        "using all the remaining string as regular expression.\n"
	        "WARNING: this parameter is exclusive with 'realm-regex'\n"
	        "\n"
	        "Examples:\n"
	        "\trealm=sip.example.org\n"
	        "\trealm=regex:sip:.*@sip\\.(.*)\\.com\n",
	        "",
	    },
	    {
	        String,
	        "realm-regex",
	        "Extraction regex applied on the URI of the 'from' header (or P-Preferred-Identity header if present) in "
	        "order "
	        "to extract the realm. The realm is found out by getting the first slice of the URI that matches the "
	        "regular "
	        "expression. If it has one or more capturing parentheses, the content of the first one is used as realm.\n"
	        "If no regex is specified, then the realm will be the domain part of the URI.\n"
	        "\n"
	        "For instance, given auth-domains=sip.example.com, you might use 'sip:.*@sip\\.(.*)\\.com' in order to "
	        "use 'example' as realm.\n"
	        "\n"
	        "WARNING: this parameter is exclusive with 'realm'",
	        "",
	    },
	    config_item_end,
	};
	moduleConfig.addChildrenValues(items);
	moduleConfig.get<ConfigBoolean>("enabled")->setDefault("false");
};

ModuleAuthenticationBase::ModuleAuthenticationBase(Agent* agent, const ModuleInfoBase* moduleInfo)
    : Module(agent, moduleInfo) {
	mProxyChallenger.ach_status = 407; /*SIP_407_PROXY_AUTH_REQUIRED*/
	mProxyChallenger.ach_phrase = sip_407_Proxy_auth_required;
	mProxyChallenger.ach_header = sip_proxy_authenticate_class;
	mProxyChallenger.ach_info = sip_proxy_authentication_info_class;

	mRegistrarChallenger.ach_status = 401; /*SIP_401_UNAUTHORIZED*/
	mRegistrarChallenger.ach_phrase = sip_401_Unauthorized;
	mRegistrarChallenger.ach_header = sip_www_authenticate_class;
	mRegistrarChallenger.ach_info = sip_authentication_info_class;
}

ModuleAuthenticationBase::~ModuleAuthenticationBase() {
	delete mRealmExtractor;
}

void ModuleAuthenticationBase::onLoad(const GenericStruct* mc) {
	loadTrustedHosts(*mc->get<ConfigStringList>("trusted-hosts"));

	auto authDomains = mc->get<ConfigStringList>("auth-domains")->read();

	mAlgorithms = mc->get<ConfigStringList>("available-algorithms")->read();
	mAlgorithms.unique();
	auto it = find_if(mAlgorithms.cbegin(), mAlgorithms.cend(), [](const string& algo) { return !validAlgo(algo); });
	if (it != mAlgorithms.cend()) {
		ostringstream os;
		os << "invalid algorithm (" << *it << ") set in '" << mc->getName() << "/available-algorithms'. ";
		os << "Available algorithms are " << StringUtils::toString(sValidAlgos);
		throw BadConfiguration{os.str()};
	}
	if (mAlgorithms.empty()) mAlgorithms.assign(sValidAlgos.cbegin(), sValidAlgos.cend());

	auto disableQOPAuth = mc->get<ConfigBoolean>("disable-qop-auth")->read();
	auto nonceExpires =
	    chrono::duration_cast<chrono::seconds>(mc->get<ConfigDuration<chrono::seconds>>("nonce-expires")->read());

	for (const string& domain : authDomains) {
		unique_ptr<FlexisipAuthModuleBase> am(createAuthModule(domain, nonceExpires.count(), !disableQOPAuth));
		mAuthModules[domain] = std::move(am);
	}

	const string regexPrefix{"regex:"};
	const auto* realmCfg = mc->get<ConfigString>("realm");
	const auto* realmRegexCfg = mc->get<ConfigString>("realm-regex");
	auto realm = realmCfg->read();
	auto realmRegex = realmRegexCfg->read();
	if (!realm.empty() && !realmRegex.empty()) {
		throw BadConfiguration{"setting both '" + realmCfg->getCompleteName() + "' and '" +
		                       realmRegexCfg->getCompleteName() + "' is forbidden"};
	}
	if (realmRegex.empty() && StringUtils::startsWith(realm, regexPrefix)) {
		realmRegex = realm.substr(regexPrefix.size());
	}
	if (!realmRegex.empty()) {
		try {
			mRealmExtractor = new RegexRealmExtractor{std::move(realmRegex)};
		} catch (const regex_error& e) {
			throw BadConfiguration{"invalid regex in '" + realmRegexCfg->getCompleteName() + "' (" + e.what()};
		}
	} else if (!realm.empty()) {
		mRealmExtractor = new StaticRealmExtractor{std::move(realm)};
	}

	mNo403Expr = mc->get<ConfigBooleanExpression>("no-403")->read();
}

unique_ptr<RequestSipEvent> ModuleAuthenticationBase::onRequest(unique_ptr<RequestSipEvent>&& ev) {
	sip_t* sip = ev->getMsgSip()->getSip();

	if (!validateRequest(*ev->getMsgSip())) return std::move(ev);

	const char* fromDomain = sip->sip_from->a_url[0].url_host;
	sip_p_preferred_identity_t* ppi = preferredIdentity(*ev->getMsgSip());
	if (ppi) fromDomain = ppi->ppid_url->url_host;
	else LOGD << "There is no p-preferred-identity";

	FlexisipAuthModuleBase* am = findAuthModule(fromDomain);
	if (am == nullptr) {
		LOGI << "Registration failure, domain is forbidden: " << fromDomain;
		ev->reply(403, "Domain forbidden", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return {};
	}

	return processAuthentication(std::move(ev), *am);
}

FlexisipAuthStatus* ModuleAuthenticationBase::createAuthStatus(const shared_ptr<MsgSip>& msgSip) {
	auto as = make_unique<FlexisipAuthStatus>(msgSip);
	LOGD << "New " << as->getStrId();
	ModuleAuthenticationBase::configureAuthStatus(*as);
	return as.release();
}

void ModuleAuthenticationBase::configureAuthStatus(FlexisipAuthStatus& as) {
	const shared_ptr<MsgSip>& ms = as.getMsgSip();
	if (ms == nullptr) return;

	sip_t* sip = ms->getSip();
	const sip_p_preferred_identity_t* ppi = preferredIdentity(*ms);
	const url_t* userUri = ppi ? ppi->ppid_url : sip->sip_from->a_url;
	if (userUri->url_host == nullptr) {
		THROW_LINE(InvalidRequestError, "malformed P-Preferred-Identity");
	}

	string realm{};
	if (mRealmExtractor) {
		auto userUriStr = url_as_string(ms->getHome(), userUri);
		LOGD << as.getStrId() << " - Searching for realm in " << (ppi ? "P-Preferred-Identity" : "From") << " URI ("
		     << userUriStr << ")";

		realm = mRealmExtractor->extract(userUriStr);
		if (realm.empty()) THROW_LINE(InternalError, "couldn't find the realm out");
	} else {
		realm = userUri->url_host;
	}

	LOGD << as.getStrId() << " - '" << realm << "' will be used as realm";

	as.method(sip->sip_request->rq_method_name);
	as.source(msg_addrinfo(ms->getMsg()));
	as.userUri(userUri);
	as.realm(realm);
	as.display(sip->sip_from->a_display);
	if (sip->sip_payload) {
		as.body(sip->sip_payload->pl_data);
		as.bodyLen(sip->sip_payload->pl_len);
	}
	as.usedAlgo() = mAlgorithms;
	as.no403(mNo403Expr->eval(*sip));
}

bool ModuleAuthenticationBase::validateRequest(const MsgSip& ms) {
	const sip_t* sip = ms.getSip();

	// Do it first to make sure no transaction is created which
	// would send an inappropriate 100 trying response.
	if (sip->sip_request->rq_method == sip_method_ack || sip->sip_request->rq_method == sip_method_cancel ||
	    sip->sip_request->rq_method == sip_method_bye // same as in the sofia auth modules
	) {
		/*ack and cancel shall never be challenged according to the RFC.*/
		return false;
	}

	// Check trusted peer
	if (isTrustedPeer(ms)) return false;
	return true;
}

unique_ptr<RequestSipEvent> ModuleAuthenticationBase::processAuthentication(unique_ptr<RequestSipEvent>&& request,
                                                                            FlexisipAuthModuleBase& am) {
	sip_t* sip = request->getMsgSip()->getSip();

	// Create incoming transaction if not already exists
	// Necessary in qop=auth to prevent nonce count chaos
	// with retransmissions.
	request->createIncomingTransaction();

	LOGD << "Start digest authentication";

	FlexisipAuthStatus* as = createAuthStatus(request->getMsgSip());

	// Attention: the auth_mod_verify method should not send by itself any message but
	// return after having set the as status and phrase.
	// Another point in asynchronous mode is that the asynchronous callbacks MUST be called
	// AFTER the nta_msg_treply bellow. Otherwise the as would be already destroyed.
	if (sip->sip_request->rq_method == sip_method_register) {
		am.verify(*as, sip->sip_authorization, &mRegistrarChallenger);
	} else {
		am.verify(*as, sip->sip_proxy_authorization, &mProxyChallenger);
	}

	return processAuthModuleResponse(std::move(request), *as);
}

FlexisipAuthModuleBase* ModuleAuthenticationBase::findAuthModule(const std::string name) {
	auto it = mAuthModules.find(name);
	if (it == mAuthModules.end()) it = mAuthModules.find("*");
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

unique_ptr<RequestSipEvent> ModuleAuthenticationBase::processAuthModuleResponse(unique_ptr<RequestSipEvent>&& ev,
                                                                                AuthStatus& as) {
	auto& fAs = dynamic_cast<FlexisipAuthStatus&>(as);
	if (as.status() == 0) {
		onSuccess(fAs);
		if (ev->isSuspended()) {
			// The event is re-injected
			getAgent()->injectRequestEvent(std::move(ev));
		}
	} else if (as.status() == 100) {
		if (!ev->isSuspended()) ev->suspendProcessing();
		as.callback([this, request = std::move(ev)](AuthStatus& as) mutable {
			return processAuthModuleResponse(std::move(request), as);
		});
		return {};
	} else if (as.status() >= 400) {
		if (as.status() == 401 || as.status() == 407) {
			auto log = make_shared<AuthLog>(ev->getMsgSip()->getSip(), fAs.passwordFound());
			log->setStatusCode(as.status(), as.phrase());
			log->setCompleted();
			ev->setEventLog(log);
		}
		errorReply(*ev, fAs);
	} else {
		ev->reply(500, "Internal error", TAG_END());
	}
	delete &as;
	// event is suspended or has been replied to
	return {};
}

void ModuleAuthenticationBase::onSuccess(const FlexisipAuthStatus& as) {
	msg_auth_t* au;
	const shared_ptr<MsgSip>& ms = as.getMsgSip();
	sip_t* sip = ms->getSip();
	if (sip->sip_request->rq_method == sip_method_register) {
		au = ModuleToolbox::findAuthorizationForRealm(ms->getHome(), sip->sip_authorization, as.realm());
	} else {
		au = ModuleToolbox::findAuthorizationForRealm(ms->getHome(), sip->sip_proxy_authorization, as.realm());
	}
	while (au) {
		msg_auth_t* nextAu = au->au_next;
		msg_header_remove(ms->getMsg(), (msg_pub_t*)sip, (msg_header_t*)au);
		au = nextAu;
	}
}

void ModuleAuthenticationBase::errorReply(RequestSipEvent& ev, const FlexisipAuthStatus& as) {
	ev.reply(as.status(), as.phrase(), SIPTAG_HEADER(reinterpret_cast<sip_header_t*>(as.info())),
	         SIPTAG_HEADER(reinterpret_cast<sip_header_t*>(as.response())),
	         SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
}

void ModuleAuthenticationBase::loadTrustedHosts(const ConfigStringList& trustedHosts) {
	const regex parameterRef{R"re(\$\{([0-9A-Za-z:-]+)/([0-9A-Za-z:-]+)\})re"};
	smatch m{};

	auto hosts = trustedHosts.read();
	for (const auto& host : hosts) {
		if (regex_match(host, m, parameterRef)) {
			auto paramRefValues = getAgent()
			                          ->getConfigManager()
			                          .getRoot()
			                          ->get<GenericStruct>(m.str(1))
			                          ->get<ConfigStringList>(m.str(2))
			                          ->read();
			for (const auto& value : paramRefValues) {
				BinaryIp::emplace(mTrustedHosts, value);
			}
		} else {
			BinaryIp::emplace(mTrustedHosts, host);
		}
	}

	const auto* clusterSection = getAgent()->getConfigManager().getRoot()->get<GenericStruct>("cluster");
	auto clusterEnabled = clusterSection->get<ConfigBoolean>("enabled")->read();
	if (clusterEnabled) {
		auto clusterNodes = clusterSection->get<ConfigStringList>("nodes")->read();
		for (const auto& host : clusterNodes) {
			BinaryIp::emplace(mTrustedHosts, host);
		}
	}

	const auto* presenceSection = getAgent()->getConfigManager().getRoot()->get<GenericStruct>("module::Presence");
	auto presenceServerEnabled = presenceSection->get<ConfigBoolean>("enabled")->read();
	if (presenceServerEnabled) {
		sofiasip::Home home{};
		auto presenceServer = presenceSection->get<ConfigString>("presence-server")->read();
		const auto* contact = sip_contact_make(home.home(), presenceServer.c_str());
		const auto* url = contact ? contact->m_url : nullptr;
		if (url && url->url_host) {
			BinaryIp::emplace(mTrustedHosts, url->url_host);
			LOGI << "Added presence server '" << url->url_host << "' to trusted hosts";
		} else {
			LOGW << "Could not parse presence server URL '" << presenceServer << "', cannot add to trusted hosts";
		}
	}
	for (const auto& trustedHost : mTrustedHosts) {
		LOGI << "IP " << trustedHost << " added to trusted hosts";
	}
}

bool ModuleAuthenticationBase::isTrustedPeer(const MsgSip& ms) {
	const sip_t* sip = ms.getSip();

	// Check for trusted host
	const sip_via_t* via = sip->sip_via;
	const char* printableReceivedHost = !empty(via->v_received) ? via->v_received : via->v_host;

	BinaryIp receivedHost(printableReceivedHost);

	if (mTrustedHosts.find(receivedHost) != mTrustedHosts.end()) {
		LOGD << "Allowing message from trusted host " << printableReceivedHost;
		return true;
	}
	return false;
}

bool ModuleAuthenticationBase::validAlgo(const std::string& algo) {
	auto it = find(sValidAlgos.cbegin(), sValidAlgos.cend(), algo);
	return it != sValidAlgos.cend();
}

const std::array<std::string, 2> ModuleAuthenticationBase::sValidAlgos = {{"MD5", "SHA-256"}};

} // namespace flexisip