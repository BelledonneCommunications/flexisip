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
#include <sofia-sip/sip_status.h>

#include <flexisip/agent.hh>
#include <flexisip/module-authentication-base.hh>

#include "utils/string-utils.hh"
#include "utils/uri-utils.hh"


using namespace std;

namespace flexisip {

ModuleAuthenticationBase::ModuleAuthenticationBase(Agent *agent) : Module(agent) {
}

void ModuleAuthenticationBase::onDeclare(GenericStruct *mc) {
	ConfigItemDescriptor items[] = {{
		StringList,
		"auth-domains",
		"List of whitespace separated domains to challenge. Others are automatically denied.",
		"localhost"
	}, {
		StringList,
		"available-algorithms",
		"List of digest algorithms to use for password hashing. Think this setting as filter applied after fetching "
		"the credentials of a user from the user database. For example, if a user has its password hashed by MD5 and "
		"SHA-256 but 'available-algorithms' only has MD5, then only a MD5-based challenged will be submited to the "
		"UAC.\n"
		"Furthermore, should a user have several hashed passwords and these are present in the list, then a challenge "
		"header will be put in the 401 response for each fetched password in the order given by the list.\n"
		"Supported algorithems are MD5 and SHA-256.",
		"MD5"
	}, {
		Boolean,
		"disable-qop-auth",
		"Disable the QOP authentication method. Default is to use it, use this flag to disable it if needed.",
		"false"
	}, {
		BooleanExpr,
		"no-403",
		"Don't reply 403 when authentication fails. Instead, generate a new 401 (or 407) response containing "
		"a new challenge.",
		"false"
	}, {
		Integer,
		"nonce-expires",
		"Expiration time before generating a new nonce.\n"
		"Unit: second",
		"3600"
	}, {
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
		""
	}, {
		String,
		"realm-regex",
		"Extraction regex applied on the URI of the 'from' header (or P-Prefered-Identity header if present) in order "
		"to extract the realm. The realm is found out by getting the first slice of the URI that matches the regular "
		"expression. If it has one or more capturing parentheses, the content of the first one is used as realm.\n"
		"If no regex is specified, then the realm will be the domain part of the URI.\n"
		"\n"
		"For instance, given auth-domains=sip.example.com, you might use 'sip:.*@sip\\.(.*)\\.com' in order to "
		"use 'example' as realm.\n"
		"\n"
		"WARNING: this parameter is exclusive with 'realm'",
		""
	},
	config_item_end
	};
	mc->addChildrenValues(items);
	mc->get<ConfigBoolean>("enabled")->setDefault("false");
}

void ModuleAuthenticationBase::onLoad(const GenericStruct *mc) {
	auto authDomains = mc->get<ConfigStringList>("auth-domains")->read();
	mAuthDomains.assign(authDomains.cbegin(), authDomains.cend());
	mAlgorithms = loadDigestAlgos(*mc->get<ConfigStringList>("available-algorithms"));

	createAuthModule(*mc);

	const string regexPrefix{"regex:"};
	const auto *realmCfg = mc->get<ConfigString>("realm");
	const auto *realmRegexCfg = mc->get<ConfigString>("realm-regex");
	auto realm = realmCfg->read();
	auto realmRegex = realmRegexCfg->read();
	if (!realm.empty() && !realmRegex.empty()) {
		LOGF("setting both '%s' and '%s' is forbidden", realmCfg->getCompleteName().c_str(), realmRegexCfg->getCompleteName().c_str());
	}
	if (realmRegex.empty() && StringUtils::startsWith(realm, regexPrefix)) {
		realmRegex = realm.substr(regexPrefix.size());
	}
	if (!realmRegex.empty()) {
		try {
			mRealmExtractor = make_unique<RegexRealmExtractor>(move(realmRegex));
		} catch (const regex_error &e) {
			LOGF("invalid regex in 'realm-regex': %s", e.what());
		}
	} else if (!realm.empty()) {
		mRealmExtractor = make_unique<StaticRealmExtractor>(move(realm));
	}

	mNo403Expr = mc->get<ConfigBooleanExpression>("no-403")->read();
}

void ModuleAuthenticationBase::onRequest(std::shared_ptr<RequestSipEvent> &ev) {
	sip_t *sip = ev->getMsgSip()->getSip();

	try {
		validateRequest(ev);
		processAuthentication(ev);
	} catch (const runtime_error &e) {
		SLOGE << e.what();
		ev->reply(500, "Internal error", TAG_END());
	} catch (const StopRequestProcessing &) {}
}

std::unique_ptr<Authentifier::AuthStatus> ModuleAuthenticationBase::createAuthStatus(const std::shared_ptr<RequestSipEvent> &ev) {
	auto as = make_unique<Authentifier::AuthStatus>(ev);
	LOGD("New FlexisipAuthStatus [%p]", as.get());
	ModuleAuthenticationBase::configureAuthStatus(*as, ev);
	return as;
}

void ModuleAuthenticationBase::configureAuthStatus(Authentifier::AuthStatus &as, const std::shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
	const sip_p_preferred_identity_t *ppi = sip_p_preferred_identity(sip);
	const url_t *userUri = ppi ? ppi->ppid_url : sip->sip_from->a_url;

	string realm{};
	if (mRealmExtractor) {
		auto userUriStr = url_as_string(ev->getHome(), userUri);
		LOGD("AuthStatus[%p]: searching for realm in %s URI (%s)",
			&as, ppi ? "P-Prefered-Identity" : "From", userUriStr);

		realm = mRealmExtractor->extract(userUriStr);
		if (realm.empty()) throw runtime_error{"couldn't find the realm out"};
	} else {
		realm = userUri->url_host;
	}

	LOGD("AuthStatus[%p]: '%s' will be used as realm", &as, realm.c_str());

	as.as_method = sip->sip_request->rq_method_name;
	as.as_user_uri = userUri;
	as.as_realm = move(realm);
	if (sip->sip_payload) {
		as.as_body.assign(sip->sip_payload->pl_data, sip->sip_payload->pl_data + sip->sip_payload->pl_len);
	}
	as.as_callback = [this](const std::shared_ptr<Authentifier::AuthStatus> &as, Authentifier::Status status){processAuthModuleResponse(as, status);};
	as.mUsedAlgo = mAlgorithms;
	as.mNo403 = mNo403Expr->eval(*ev->getSip());

	as.mDomain = sip->sip_from->a_url->url_host;
	as.mFromHeader = sip_header_as_string(as.mHome.home(), reinterpret_cast<sip_header_t *>(sip->sip_from));

	if (sip->sip_contact) {
		const char *sipInstance = msg_header_find_param(reinterpret_cast<msg_common_t *>(sip->sip_contact), "+sip.instance");
		as.mSipInstance = sipInstance ? sipInstance : "";

		try {
			auto uuid = UriUtils::getParamValue(sip->sip_contact->m_url->url_params, "gr");
			if (uuid.empty()) uuid = UriUtils::uniqueIdToGr(as.mSipInstance);
			uuid = StringUtils::removePrefix(uuid, "urn:uuid:");
			as.mUUID = move(uuid);
		} catch (const invalid_argument &e) { // raised by removePrefix() when uuid doesn't start by 'urn:uuid:'
			SLOGE << "ExernalAuthentication: error while getting UUID: " << e.what();
		}
	}
}

void ModuleAuthenticationBase::validateRequest(const std::shared_ptr<RequestSipEvent> &request) {
	sip_t *sip = request->getMsgSip()->getSip();

	// Do it first to make sure no transaction is created which
	// would send an inappropriate 100 trying response.
	if (sip->sip_request->rq_method == sip_method_ack || sip->sip_request->rq_method == sip_method_cancel ||
		sip->sip_request->rq_method == sip_method_bye // same as in the sofia auth modules
	) {
		/*ack and cancel shall never be challenged according to the RFC.*/
		throw StopRequestProcessing();
	}
}

void ModuleAuthenticationBase::processAuthentication(const std::shared_ptr<RequestSipEvent> &request) {
	// Create incoming transaction if not already exists
	// Necessary in qop=auth to prevent nonce count chaos
	// with retransmissions.
	request->createIncomingTransaction();

	auto as = static_cast<shared_ptr<Authentifier::AuthStatus>>(createAuthStatus(request));
	mAuthModules->verify(as);
}

void ModuleAuthenticationBase::processAuthModuleResponse(const std::shared_ptr<Authentifier::AuthStatus> &as,
														 Authentifier::Status status) {
	const auto &ev = as->mEvent;

	switch (status) {
		case Authentifier::Status::Pass:
			onSuccess(*as);
			if (ev->isSuspended()) {
				// The event is re-injected
				getAgent()->injectRequestEvent(ev);
			}
			return;

		case Authentifier::Status::Pending:
			if (!ev->isSuspended()) ev->suspendProcessing();
			return;

		case Authentifier::Status::Reject:
		case Authentifier::Status::Challenge:
			if (as->as_status == 401 || as->as_status == 407) {
				auto log = make_shared<AuthLog>(ev->getMsgSip()->getSip(), as->mPasswordFound);
				log->setStatusCode(as->as_status, as->as_phrase);
				log->setCompleted();
				ev->setEventLog(log);
			}
			errorReply(*as);
			return;

		case Authentifier::Status::Error:
			ev->reply(500, "Internal error", TAG_END());
			return;

		case Authentifier::Status::End:
			throw logic_error("Authentifier::Status::End not supported");
	}
}

void ModuleAuthenticationBase::onSuccess(const Authentifier::AuthStatus &as) {
	msg_auth_t *au;
	const shared_ptr<MsgSip> &ms = as.mEvent->getMsgSip();
	sip_t *sip = ms->getSip();
	if (sip->sip_request->rq_method == sip_method_register) {
		au = ModuleToolbox::findAuthorizationForRealm(
			ms->getHome(),
			sip->sip_authorization,
			as.as_realm.c_str()
		);
	} else {
		au = ModuleToolbox::findAuthorizationForRealm(
			ms->getHome(),
			sip->sip_proxy_authorization,
			as.as_realm.c_str()
		);
	}
	while (au) {
		msg_auth_t *nextAu = au->au_next;
		msg_header_remove(ms->getMsg(), (msg_pub_t *)sip, (msg_header_t *)au);
		au = nextAu;
	}
}

void ModuleAuthenticationBase::errorReply(const Authentifier::AuthStatus &as) {
	const std::shared_ptr<RequestSipEvent> &ev = as.mEvent;
	ev->reply(as.as_status, as.as_phrase.c_str(),
			  SIPTAG_HEADER(reinterpret_cast<sip_header_t *>(as.as_info)),
			  SIPTAG_HEADER(reinterpret_cast<sip_header_t *>(as.as_response)),
			  SIPTAG_SERVER_STR(getAgent()->getServerString()),
			  TAG_END()
	);
}

bool ModuleAuthenticationBase::validAlgo(const std::string &algo) {
	auto it = find(sValidAlgos.cbegin(), sValidAlgos.cend(), algo);
	return it != sValidAlgos.cend();
}

std::list<std::string> ModuleAuthenticationBase::loadDigestAlgos(const ConfigStringList& parameter) {
	auto algos = parameter.read();
	algos.unique();
	auto it = find_if(algos.cbegin(), algos.cend(), [](const string &algo){return !validAlgo(algo);});
	if (it != algos.cend()) {
		ostringstream os{};
		os << "invalid algorithm (" << *it << ") set in '" << parameter.getName() << "/available-algorithms'. ";
		os << "Available algorithms are " << StringUtils::toString(sValidAlgos);
		LOGF("%s", os.str().c_str());
	}
	if (algos.empty()) algos.assign(sValidAlgos.cbegin(), sValidAlgos.cend());
	return algos;
}

const std::array<std::string, 2> ModuleAuthenticationBase::sValidAlgos = {{ "MD5", "SHA-256" }};

}
