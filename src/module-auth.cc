/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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
#include <sofia-sip/sip_status.h>

#include "module-auth.hh"
#include "auth/flexisip-auth-module.hh"

using namespace std;
using namespace flexisip;

// ====================================================================================================================
//  Authentication class
// ====================================================================================================================

Authentication::Authentication(Agent *ag) : Module(ag) {
	mProxyChallenger.ach_status = 407; /*SIP_407_PROXY_AUTH_REQUIRED*/
	mProxyChallenger.ach_phrase = sip_407_Proxy_auth_required;
	mProxyChallenger.ach_header = sip_proxy_authenticate_class;
	mProxyChallenger.ach_info = sip_proxy_authentication_info_class;

	mRegistrarChallenger.ach_status = 401; /*SIP_401_UNAUTHORIZED*/
	mRegistrarChallenger.ach_phrase = sip_401_Unauthorized;
	mRegistrarChallenger.ach_header = sip_www_authenticate_class;
	mRegistrarChallenger.ach_info = sip_authentication_info_class;
}

Authentication::~Authentication() {
	if (mRequiredSubjectCheckSet){
		regfree(&mRequiredSubject);
	}
}

void Authentication::onDeclare(GenericStruct *mc) {
	ConfigItemDescriptor items[] = {
		{StringList, "auth-domains",
			"List of whitespace separated domain names to challenge. Others are denied.",
			"localhost"
		},
		{StringList, "trusted-hosts", "List of whitespace separated IP which will not be challenged.", ""},
		{String, "db-implementation",
			"Database backend implementation for digest authentication [odbc,soci,file].",
			"file"
		},
		{String, "datasource",
			"Odbc connection string to use for connecting to database. "
			"ex1: DSN=myodbc3; where 'myodbc3' is the datasource name. "
			"ex2: DRIVER={MySQL};SERVER=host;DATABASE=db;USER=user;PASSWORD=pass;OPTION=3; for a DSN-less connection. "
			"ex3: /etc/flexisip/passwd; for a file containing user credentials in clear-text, md5 or sha256. "
			"The file must start with 'version:1' as the first line, and then contains lines in the form of:\n"
			"user@domain clrtxt:clear-text-password md5:md5-password sha256:sha256-password ;\n"
			"For example: \n"
			"bellesip@sip.linphone.org clrtxt:secret ;\n"
			"bellesip@sip.linphone.org md5:97ffb1c6af18e5687bf26cdf35e45d30 ;\n"
			"bellesip@sip.linphone.org clrtxt:secret md5:97ffb1c6af18e5687bf26cdf35e45d30 sha256:d7580069de562f5c7fd932cc986472669122da91a0f72f30ef1b20ad6e4f61a3 ;",
			""
		},
		{Integer, "nonce-expires", "Expiration time of nonces, in seconds.", "3600"},
		{Integer, "cache-expire", "Duration of the validity of the credentials added to the cache in seconds.", "1800"},
		{Boolean, "hashed-passwords",
			"True if retrieved passwords from the database are hashed. HA1=MD5(A1) = MD5(username:realm:pass).",
			"false"
		},
		{BooleanExpr, "no-403", "Don't reply 403, but 401 or 407 even in case of wrong authentication.", "false"},
		{Boolean, "reject-wrong-client-certificates",
			"If set to true, the module will simply reject with 403 forbidden any request coming from client"
			" who presented a bad TLS certificate (regardless of reason: improper signature, unmatched subjects)."
			" Otherwise, the module will fallback to a digest authentication.\n"
			"This policy applies only for transports configured with 'required-peer-certificate=1' parameter; indeed"
			" no certificate is requested to the client otherwise.",
			"false"
		},
		{String, "tls-client-certificate-required-subject", "An optional regular expression matched against subjects "
			"of presented client certificates. If this regular expression evaluates to false, the request is rejected. "
			"The matched subjects are, in order: subjectAltNames.DNS, subjectAltNames.URI, subjectAltNames.IP and CN.",
			""
		},
		{Boolean, "new-auth-on-407", "When receiving a proxy authenticate challenge, generate a new challenge for "
			"this proxy.", "false"},
		{Boolean, "enable-test-accounts-creation",
			"Enable a feature useful for automatic tests, allowing a client to create a temporary account in the "
			"password database in memory."
			"This MUST not be used for production as it is a real security hole.",
			"false"
		},
		{Boolean, "disable-qop-auth",
			"Disable the QOP authentication method. Default is to use it, use this flag to disable it if needed.",
			"false"
		},
		/* We need this configuration because of old client that do not support multiple Authorization.
			* When a user have a clear text password, it will be hashed into md5 and sha256.
			* This will force the use of only the algorithm supported by them.
			*/
		{StringList, "available-algorithms",
			"List of algorithms, separated by whitespaces (valid values are MD5 and SHA-256).\n"
			"This feature allows to force the use of wanted algorithm(s).\n"
			"If the value is empty, then it will authorize all implemented algorithms.",
			"MD5"
		},
		{StringList, "trusted-client-certificates", "List of whitespace separated username or username@domain CN "
			"which will trusted. If no domain is given it is computed.",
			""
		},
		{Boolean, "trust-domain-certificates",
			"If enabled, all requests which have their request URI containing a trusted domain will be accepted.",
			"false"
		},
		config_item_end
	};

	mc->addChildrenValues(items);
	/* modify the default value for "enabled" */
	mc->get<ConfigBoolean>("enabled")->setDefault("false");
	mc->get<ConfigBoolean>("hashed-passwords")->setDeprecated(true);
	//we deprecate "trusted-client-certificates" because "tls-client-certificate-required-subject" can do more.
	mc->get<ConfigStringList>("trusted-client-certificates")->setDeprecated(true);

	// Call declareConfig for backends
	AuthDbBackend::declareConfig(mc);

	mCountAsyncRetrieve = mc->createStat("count-async-retrieve", "Number of asynchronous retrieves.");
	mCountSyncRetrieve = mc->createStat("count-sync-retrieve", "Number of synchronous retrieves.");
	mCountPassFound = mc->createStat("count-password-found", "Number of passwords found.");
	mCountPassNotFound = mc->createStat("count-password-not-found", "Number of passwords not found.");
}

void Authentication::onLoad(const GenericStruct *mc) {
	mDomains = mc->get<ConfigStringList>("auth-domains")->read();
	loadTrustedHosts(*mc->get<ConfigStringList>("trusted-hosts"));
	mNewAuthOn407 = mc->get<ConfigBoolean>("new-auth-on-407")->read();
	mTrustedClientCertificates = mc->get<ConfigStringList>("trusted-client-certificates")->read();
	mTrustDomainCertificates = mc->get<ConfigBoolean>("trust-domain-certificates")->read();
	mNo403Expr = mc->get<ConfigBooleanExpression>("no-403")->read();
	mTestAccountsEnabled = mc->get<ConfigBoolean>("enable-test-accounts-creation")->read();
	mDisableQOPAuth = mc->get<ConfigBoolean>("disable-qop-auth")->read();
	int nonceExpires = mc->get<ConfigInt>("nonce-expires")->read();
	mAlgorithms = mc->get<ConfigStringList>("available-algorithms")->read();
	mAlgorithms.unique();

	for (auto it = mAlgorithms.begin(); it != mAlgorithms.end();) {
		if ((*it != "MD5") && (*it != "SHA-256")) {
			SLOGW << "Given algorithm '" << *it << "' is not valid. Must be either MD5 or SHA-256.";
			it = mAlgorithms.erase(it);
		} else {
			it++;
		}
	}

	if (mAlgorithms.empty()) {
		mAlgorithms.push_back("MD5");
		mAlgorithms.push_back("SHA-256");
	}

	for (const string &domain : mDomains) {
		FlexisipAuthModule *authModule =
			mDisableQOPAuth ?
			new FlexisipAuthModule(getAgent()->getRoot(), domain, mAlgorithms.front()) :
			new FlexisipAuthModule(getAgent()->getRoot(), domain, mAlgorithms.front(), nonceExpires);

		authModule->setOnPasswordFetchResultCb(
			[this](bool passFound){passFound ? mCountPassFound++ : mCountPassNotFound++;}
		);
		mAuthModules[domain].reset(authModule);
		SLOGI << "Found auth domain: " << domain;
	}

	string requiredSubject = mc->get<ConfigString>("tls-client-certificate-required-subject")->read();
	if (!requiredSubject.empty()){
		int res = regcomp(&mRequiredSubject, requiredSubject.c_str(),  REG_EXTENDED|REG_NOSUB);
		if (res != 0) {
			string err_msg(128,0);
			regerror(res, &mRequiredSubject, &err_msg[0], err_msg.capacity());
			LOGF("Could not compile regex for 'tls-client-certificate-required-subject' '%s': %s",
				 requiredSubject.c_str(),
				 err_msg.c_str()
			);
		}else mRequiredSubjectCheckSet = true;
	}
	mRejectWrongClientCertificates = mc->get<ConfigBoolean>("reject-wrong-client-certificates")->read();
	AuthDbBackend::get();//force instanciation of the AuthDbBackend NOW, to force errors to arrive now if any.
}

AuthModule *Authentication::findAuthModule(const string name) {
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

bool Authentication::containsDomain(const list<string> &d, const char *name) {
	return find(d.cbegin(), d.cend(), "*") != d.end() || find(d.cbegin(), d.cend(), name) != d.end();
}

bool Authentication::handleTestAccountCreationRequests(shared_ptr<RequestSipEvent> &ev) {
	sip_t *sip = ev->getSip();
	if (sip->sip_request->rq_method == sip_method_register) {
		sip_unknown_t *h = ModuleToolbox::getCustomHeaderByName(sip, "X-Create-Account");
		if (h && strcasecmp(h->un_value, "yes") == 0) {
			url_t *url = sip->sip_from->a_url;
			if (url) {
				sip_unknown_t *h2 = ModuleToolbox::getCustomHeaderByName(sip, "X-Phone-Alias");
				const char* phone_alias = h2 ? h2->un_value : NULL;
				phone_alias = phone_alias ? phone_alias : "";
				AuthDbBackend::get().createAccount(url->url_user, url->url_host, url->url_user, url->url_password,
													sip->sip_expires->ex_delta, phone_alias);

				ostringstream os;
				os << "Account created for " << url->url_user << '@' << url->url_host << " with password "
					<< url->url_password << " and expires " << sip->sip_expires->ex_delta;
				if (phone_alias) os << " with phone alias " << phone_alias;
				SLOGD << os.str();
				return true;
			}
		}
	}
	return false;
}

bool Authentication::isTrustedPeer(shared_ptr<RequestSipEvent> &ev) {
	sip_t *sip = ev->getSip();

	// Check for trusted host
	sip_via_t *via = sip->sip_via;
	list<BinaryIp>::const_iterator trustedHostsIt = mTrustedHosts.begin();
	const char *printableReceivedHost = !empty(via->v_received) ? via->v_received : via->v_host;

	BinaryIp receivedHost(printableReceivedHost, true);

	for (; trustedHostsIt != mTrustedHosts.end(); ++trustedHostsIt) {
		if (receivedHost == *trustedHostsIt) {
			LOGD("Allowing message from trusted host %s", printableReceivedHost);
			return true;
		}
	}
	return false;
}

bool Authentication::tlsClientCertificatePostCheck(const shared_ptr<RequestSipEvent> &ev){
	if (mRequiredSubjectCheckSet){
		bool ret = ev->matchIncomingSubject(&mRequiredSubject);
		if (ret){
			SLOGD<<"TLS certificate postcheck successful.";
		}else{
			SLOGUE<<"TLS certificate postcheck failed.";
		}
		return ret;
	}
	return true;
}

/* This function returns
 * true: if the tls authentication is handled (either successful or rejected)
 * false: if we have to fallback to digest
 */
bool Authentication::handleTlsClientAuthentication(shared_ptr<RequestSipEvent> &ev) {
	sip_t *sip = ev->getSip();
	shared_ptr<tport_t> inTport = ev->getIncomingTport();
	unsigned int policy = 0;

	tport_get_params(inTport.get(), TPTAG_TLS_VERIFY_POLICY_REF(policy), NULL);
	// Check TLS certificate
	if ((policy & TPTLS_VERIFY_INCOMING) && tport_is_server(inTport.get())){
		/* tls client certificate is required for this transport*/
		if (tport_is_verified(inTport.get())) {
			/*the certificate looks good, now match subjects*/
			const url_t *from = sip->sip_from->a_url;
			const char *fromDomain = from->url_host;
			const char *res = NULL;
			url_t searched_uri = URL_INIT_AS(sip);
			SofiaAutoHome home;
			char *searched;

			searched_uri.url_host = from->url_host;
			searched_uri.url_user = from->url_user;
			searched = url_as_string(home.home(), &searched_uri);

			if (ev->findIncomingSubject(searched)) {
				SLOGD << "Allowing message from matching TLS certificate";
				goto postcheck;
			} else if (sip->sip_request->rq_method != sip_method_register &&
				(res = findIncomingSubjectInTrusted(ev, fromDomain))) {
				SLOGD << "Found trusted TLS certificate " << res;
			goto postcheck;
				} else {
					/*case where the certificate would work for the entire domain*/
					searched_uri.url_user = NULL;
					searched = url_as_string(home.home(), &searched_uri);
					if (ev->findIncomingSubject(searched)) {
						SLOGD << "Found TLS certificate for entire domain";
						goto postcheck;
					}
				}

				if (sip->sip_request->rq_method != sip_method_register && mTrustDomainCertificates) {
					searched_uri.url_user = NULL;
					searched_uri.url_host = sip->sip_request->rq_url->url_host;
					searched = url_as_string(home.home(), &searched_uri);
					if (ev->findIncomingSubject(searched)) {
						SLOGD << "Found trusted TLS certificate for the request URI domain";
						goto postcheck;
					}
				}

				LOGE("Client is presenting a TLS certificate not matching its identity.");
				SLOGUE << "Registration failure for " << url_as_string(home.home(), from)
					<< ", TLS certificate doesn't match its identity";
				goto bad_certificate;

				postcheck:
				if (tlsClientCertificatePostCheck(ev)){
					/*all is good, return true*/
					return true;
				}else goto bad_certificate;
		}else goto bad_certificate;

		bad_certificate:
		if (mRejectWrongClientCertificates){
			ev->reply(403, "Bad tls client certificate", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
			return true; /*the request is responded, no further processing required*/
		}
		/*fallback to digest*/
		return false;
	}
	/*no client certificate requested, go to digest auth*/
	return false;
}

void Authentication::onRequest(shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
	sip_p_preferred_identity_t *ppi = NULL;

	// Do it first to make sure no transaction is created which
	// would send an unappropriate 100 trying response.
	if (sip->sip_request->rq_method == sip_method_ack || sip->sip_request->rq_method == sip_method_cancel ||
		sip->sip_request->rq_method == sip_method_bye // same as in the sofia auth modules
	) {
		/*ack and cancel shall never be challenged according to the RFC.*/
		return;
	}

	// handle account creation request (test feature only)
	if (mTestAccountsEnabled && handleTestAccountCreationRequests(ev)) {
		ev->reply(
			200,
			"Test account created",
			SIPTAG_SERVER_STR(getAgent()->getServerString()),
			SIPTAG_CONTACT(sip->sip_contact),
			SIPTAG_EXPIRES_STR("0"),
			TAG_END()
		);
		return;
	}

	// Check trusted peer
	if (isTrustedPeer(ev))
		return;

	// Check for auth module for this domain, this will also tell us if this domain is allowed (auth-domains config
	// item)
	const char *fromDomain = sip->sip_from->a_url[0].url_host;
	if (fromDomain && strcmp(fromDomain, "anonymous.invalid") == 0) {
		ppi = sip_p_preferred_identity(sip);
		if (ppi)
			fromDomain = ppi->ppid_url->url_host;
		else
			LOGD("There is no p-preferred-identity");
	}

	AuthModule *am = findAuthModule(fromDomain);
	if (am == NULL) {
		LOGI("Unknown domain [%s]", fromDomain);
		SLOGUE << "Registration failure, domain is forbidden: " << fromDomain;
		ev->reply(403, "Domain forbidden", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return;
	}

	// check if TLS client certificate provides sufficent authentication for this request.
	if (handleTlsClientAuthentication(ev))
		return;

	// Check for the existence of username, which is required for proceeding with digest authentication in flexisip.
	// Reject if absent.
	if (sip->sip_from->a_url->url_user == NULL) {
		LOGI("From has no username, cannot authenticate.");
		SLOGUE << "Registration failure, username not found: " << url_as_string(ms->getHome(), sip->sip_from->a_url);
		ev->reply(403, "Username must be provided", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return;
	}

	// Create incoming transaction if not already exists
	// Necessary in qop=auth to prevent nonce count chaos
	// with retransmissions.
	ev->createIncomingTransaction();

	auto *as = new FlexisipAuthStatus(ev);
	as->method(sip->sip_request->rq_method_name);
	as->source(msg_addrinfo(ms->getMsg()));
	as->userUri(ppi ? ppi->ppid_url : sip->sip_from->a_url);
	as->realm(as->userUri()->url_host);
	as->display(sip->sip_from->a_display);
	if (sip->sip_payload) {
		as->body(sip->sip_payload->pl_data);
		as->bodyLen(sip->sip_payload->pl_len);
	}
	as->no403(mNo403Expr->eval(ev->getSip()));
	as->usedAlgo() = mAlgorithms;

	// Attention: the auth_mod_verify method should not send by itself any message but
	// return after having set the as status and phrase.
	// Another point in asynchronous mode is that the asynchronous callbacks MUST be called
	// AFTER the nta_msg_treply bellow. Otherwise the as would be already destroyed.
	if (sip->sip_request->rq_method == sip_method_register) {
		am->verify(*as, sip->sip_authorization, &mRegistrarChallenger);
	} else {
		am->verify(*as, sip->sip_proxy_authorization, &mProxyChallenger);
	}
	processAuthModuleResponse(*as);
}

void Authentication::onResponse(shared_ptr<ResponseSipEvent> &ev) {
	if (!mNewAuthOn407) return; /*nop*/

	shared_ptr<OutgoingTransaction> transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
	if (transaction == NULL) return;

	shared_ptr<string> proxyRealm = transaction->getProperty<string>("this_proxy_realm");
	if (proxyRealm == NULL) return;

	sip_t *sip = ev->getMsgSip()->getSip();
	if (sip->sip_status->st_status == 407 && sip->sip_proxy_authenticate) {
		auto *as = new FlexisipAuthStatus(nullptr);
		as->realm(proxyRealm.get()->c_str());
		as->userUri(sip->sip_from->a_url);
		AuthModule *am = findAuthModule(as->realm());
		FlexisipAuthModule *fam = dynamic_cast<FlexisipAuthModule *>(am);
		if (fam) {
			fam->challenge(*as, &mProxyChallenger);
			fam->nonceStore().insert(as->response());
			msg_header_insert(ev->getMsgSip()->getMsg(), (msg_pub_t *)sip, (msg_header_t *)as->response());
		} else {
			LOGD("Authentication module for %s not found", as->realm());
		}
	} else {
		LOGD("not handled newauthon401");
	}
}


void Authentication::onIdle() {
	for (auto &it : mAuthModules) {
		AuthModule *am = it.second.get();
		FlexisipAuthModule *fam = dynamic_cast<FlexisipAuthModule *>(am);
		fam->nonceStore().cleanExpired();
	}
}

bool Authentication::doOnConfigStateChanged(const ConfigValue &conf, ConfigState state) {
	if (conf.getName() == "trusted-hosts" && state == ConfigState::Commited) {
		loadTrustedHosts((const ConfigStringList &)conf);
		LOGD("Trusted hosts updated");
		return true;
	} else {
		return Module::doOnConfigStateChanged(conf, state);
	}
}

void Authentication::processAuthModuleResponse(AuthStatus &as) {
	auto &authStatus = dynamic_cast<FlexisipAuthStatus &>(as);
	const shared_ptr<RequestSipEvent> &ev = authStatus.event();
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
		if (ev->isSuspended()) {
			// The event is re-injected
			getAgent()->injectRequestEvent(ev);
		}
	} else if (as.status() == 100) {
		using std::placeholders::_1;
		ev->suspendProcessing();
		as.callback(std::bind(&Authentication::processAuthModuleResponse, this, _1 ));
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
			SIPTAG_SERVER_STR(getAgent()->getServerString()),
			TAG_END()
		);
	} else {
		ev->reply(500, "Internal error", TAG_END());
	}
	delete &as;
}

const char *Authentication::findIncomingSubjectInTrusted(shared_ptr<RequestSipEvent> &ev, const char *fromDomain) {
	if (mTrustedClientCertificates.empty())
		return NULL;
	list<string> toCheck;
	for (auto it = mTrustedClientCertificates.cbegin(); it != mTrustedClientCertificates.cend(); ++it) {
		if (it->find("@") != string::npos)
			toCheck.push_back(*it);
		else
			toCheck.push_back(*it + "@" + string(fromDomain));
	}
	const char *res = ev->findIncomingSubject(toCheck);
	return res;
}

void Authentication::loadTrustedHosts(const ConfigStringList &trustedHosts) {
	list<string> hosts = trustedHosts.read();
	transform(hosts.begin(), hosts.end(), back_inserter(mTrustedHosts), [](string host) {
		return BinaryIp(host.c_str());
	});

	const GenericStruct *clusterSection = GenericManager::get()->getRoot()->get<GenericStruct>("cluster");
	bool clusterEnabled = clusterSection->get<ConfigBoolean>("enabled")->read();
	if (clusterEnabled) {
		list<string> clusterNodes = clusterSection->get<ConfigStringList>("nodes")->read();
		for (list<string>::const_iterator node = clusterNodes.cbegin(); node != clusterNodes.cend(); node++) {
			BinaryIp nodeIp((*node).c_str());

			if (find(mTrustedHosts.cbegin(), mTrustedHosts.cend(), nodeIp) == mTrustedHosts.cend()) {
				mTrustedHosts.push_back(nodeIp);
			}
		}
	}

	const GenericStruct *presenceSection = GenericManager::get()->getRoot()->get<GenericStruct>("module::Presence");
	bool presenceServer = presenceSection->get<ConfigBoolean>("enabled")->read();
	if (presenceServer) {
		SofiaAutoHome home;
		string presenceServer = presenceSection->get<ConfigString>("presence-server")->read();
		sip_contact_t *contact = sip_contact_make(home.home(), presenceServer.c_str());
		url_t *url = contact ? contact->m_url : NULL;
		if (url && url->url_host) {
			BinaryIp host(url->url_host);

			if (find(mTrustedHosts.cbegin(), mTrustedHosts.cend(), host) == mTrustedHosts.cend()) {
				SLOGI << "Adding presence server '" << url->url_host << "' to trusted hosts";
				mTrustedHosts.push_back(host);
			}
		} else {
			SLOGW << "Could not parse presence server URL '" << presenceServer
				<< "', cannot be added to trusted hosts!";
		}
	}
}

ModuleInfo<Authentication> Authentication::sInfo(
	"Authentication",
	"The authentication module challenges and authenticates SIP requests using two possible methods:\n"
	" * if the request is received via a TLS transport and 'require-peer-certificate' is set in transport definition "
	"in [Global] section for this transport, then the From header of the request is matched with the CN claimed by "
	"the client certificate. The CN must contain sip:user@domain or alternate name with URI=sip:user@domain "
	"corresponding to the URI in the from header for the request to be accepted. Optionnaly, the property "
	"tls-client-certificate-required-subject may contain a regular expression for additional checks to execute on "
	"certificate subjects.\n"
	" * if no TLS client based authentication can be performed, or is failed, then a SIP digest authentication is "
	"performed. The password verification is made by querying a database or a password file on disk.",
	{ "NatHelper" },
	ModuleInfoBase::ModuleOid::Authentication
);

// ====================================================================================================================
