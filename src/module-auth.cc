/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include <sofia-sip/msg_addr.h>
#include <sofia-sip/sip_extra.h>
#include <sofia-sip/sip_status.h>

#include <flexisip/module-auth.hh>

#include "auth/flexisip-auth-module.hh"

using namespace std;
using namespace flexisip;

// ====================================================================================================================
//  Authentication class
// ====================================================================================================================

Authentication::Authentication(Agent* ag) : ModuleAuthenticationBase(ag) {
}

Authentication::~Authentication() {
	if (mRequiredSubjectCheckSet) {
		regfree(&mRequiredSubject);
	}
}

void Authentication::onDeclare(GenericStruct* mc) {
	ModuleAuthenticationBase::onDeclare(mc);
	ConfigItemDescriptor items[] = {
	    {Boolean, "reject-wrong-client-certificates",
	     "If set to true, the module will simply reject with \"403 forbidden\" any request coming from clients "
	     "which have presented a bad TLS certificate (regardless of reason: improper signature, unmatched subjects). "
	     "Otherwise, the module will fallback to a digest authentication.\n"
	     "This policy applies only for transports configured which have 'required-peer-certificate=1' parameter; "
	     "indeed "
	     "no certificate is requested to the client otherwise. ",
	     "false"},
	    {String, "tls-client-certificate-required-subject",
	     "An optional regular expression used to accept or deny a request basing on subject fields of the "
	     "client certificate. The request is allowed if one of the subjects matches the regular expression.\n"
	     "The list of subjects to check is built by extracting the following fields, in order:\n"
	     "\tsubjectAltNames.DNS, subjectAltNames.URI, subjectAltNames.IP and CN",
	     ""},
	    {Boolean, "trust-domain-certificates",
	     "Accept requests which the client certificate enables to trust the domaine of its Request-URI.", "false"},
	    {Boolean, "new-auth-on-407",
	     "When receiving a proxy authenticate challenge, generate a new challenge for "
	     "this proxy.",
	     "false"},
	    {String, "db-implementation", "Database backend implementation for digest authentication [soci,file].", "file"},
	    {Integer, "cache-expire", "Duration of the validity of the credentials added to the cache in seconds.", "1800"},

	    // deprecated parameters
	    {StringList, "trusted-client-certificates",
	     "List of whitespace separated username or username@domain CN "
	     "which will trusted. If no domain is given it is computed.",
	     ""},
	    {Boolean, "hashed-passwords",
	     "True if retrieved passwords from the database are hashed. HA1=MD5(A1) = MD5(username:realm:pass).", "false"},
	    {Boolean, "enable-test-accounts-creation",
	     "Enable a feature useful for automatic tests, allowing a client to create a temporary account in the "
	     "password database in memory. This MUST not be used for production as it is a real security hole.",
	     "false"},
	    config_item_end};

	mc->addChildrenValues(items);

	mc->get<ConfigStringList>("trusted-client-certificates")
	    ->setDeprecated({"2018-04-16", "1.0.13", "Use 'tls-client-certificate-required-subject' instead."});
	mc->get<ConfigBoolean>("hashed-passwords")
	    ->setDeprecated({"2020-01-28", "2.0.0",
	                     "This setting has been out of use since the algorithm used to hash the password is "
	                     "stored in the user database and the CLRTXT algorithm can be used to indicate that "
	                     "the password isn't hashed.\n"
	                     "Warning: setting 'true' hasn't any effect anymore."});
	mc->get<ConfigBoolean>("enable-test-accounts-creation")
	    ->setDeprecated({"2020-01-28", "2.0.0",
	                     "This feature was useful for liblinphone's integrity tests and isn't used today anymore. "
	                     "Please remove this setting from your configuration file."});

	// Call declareConfig for backends
	AuthDbBackend::declareConfig(mc);

	mCountAsyncRetrieve = mc->createStat("count-async-retrieve", "Number of asynchronous retrieves.");
	mCountSyncRetrieve = mc->createStat("count-sync-retrieve", "Number of synchronous retrieves.");
	mCountPassFound = mc->createStat("count-password-found", "Number of passwords found.");
	mCountPassNotFound = mc->createStat("count-password-not-found", "Number of passwords not found.");
}

void Authentication::onLoad(const GenericStruct* mc) {
	ModuleAuthenticationBase::onLoad(mc);

	mNewAuthOn407 = mc->get<ConfigBoolean>("new-auth-on-407")->read();
	mTrustedClientCertificates = mc->get<ConfigStringList>("trusted-client-certificates")->read();
	mTrustDomainCertificates = mc->get<ConfigBoolean>("trust-domain-certificates")->read();

	string requiredSubject = mc->get<ConfigString>("tls-client-certificate-required-subject")->read();
	if (!requiredSubject.empty()) {
		int res = regcomp(&mRequiredSubject, requiredSubject.c_str(), REG_EXTENDED | REG_NOSUB);
		if (res != 0) {
			string err_msg(128, '\0');
			regerror(res, &mRequiredSubject, &err_msg[0], err_msg.size());
			LOGF("Could not compile regex for 'tls-client-certificate-required-subject' '%s': %s",
			     requiredSubject.c_str(), err_msg.c_str());
		} else mRequiredSubjectCheckSet = true;
	}
	mRejectWrongClientCertificates = mc->get<ConfigBoolean>("reject-wrong-client-certificates")->read();
	AuthDbBackend::get(); // force instanciation of the AuthDbBackend NOW, to force errors to arrive now if any.
}

bool Authentication::tlsClientCertificatePostCheck(const shared_ptr<RequestSipEvent>& ev) {
	if (mRequiredSubjectCheckSet) {
		bool ret = ev->matchIncomingSubject(&mRequiredSubject);
		if (ret) {
			SLOGD << "TLS certificate postcheck successful.";
		} else {
			SLOGUE << "TLS certificate postcheck failed.";
		}
		return ret;
	}
	return true;
}

/* This function returns
 * true: if the tls authentication is handled (either successful or rejected)
 * false: if we have to fallback to digest
 */
bool Authentication::handleTlsClientAuthentication(const std::shared_ptr<RequestSipEvent>& ev) {
	sip_t* sip = ev->getSip();
	shared_ptr<tport_t> inTport = ev->getIncomingTport();
	unsigned int policy = 0;

	tport_get_params(inTport.get(), TPTAG_TLS_VERIFY_POLICY_REF(policy), NULL);
	// Check TLS certificate
	if ((policy & TPTLS_VERIFY_INCOMING) && tport_is_server(inTport.get())) {
		/* tls client certificate is required for this transport*/
		if (tport_is_verified(inTport.get())) {
			/*the certificate looks good, now match subjects*/
			const url_t* from = sip->sip_from->a_url;
			const char* fromDomain = from->url_host;
			const char* res = NULL;
			url_t searched_uri = URL_INIT_AS(sip);
			sofiasip::Home home;
			char* searched;

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
			if (tlsClientCertificatePostCheck(ev)) {
				/*all is good, return true*/
				return true;
			} else goto bad_certificate;
		} else goto bad_certificate;

	bad_certificate:
		if (mRejectWrongClientCertificates) {
			ev->reply(403, "Bad tls client certificate", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
			return true; /*the request is responded, no further processing required*/
		}
		/*fallback to digest*/
		return false;
	}
	/*no client certificate requested, go to digest auth*/
	return false;
}

void Authentication::onResponse(shared_ptr<ResponseSipEvent>& ev) {
	if (!mNewAuthOn407) return; /*nop*/

	shared_ptr<OutgoingTransaction> transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
	if (transaction == NULL) return;

	shared_ptr<string> proxyRealm = transaction->getProperty<string>("this_proxy_realm");
	if (proxyRealm == NULL) return;

	sip_t* sip = ev->getMsgSip()->getSip();
	if (sip->sip_status->st_status == 407 && sip->sip_proxy_authenticate) {
		auto* as = new FlexisipAuthStatus(nullptr);
		as->realm(proxyRealm.get()->c_str());
		as->userUri(sip->sip_from->a_url);
		AuthModule* am = findAuthModule(as->realm());
		FlexisipAuthModule* fam = dynamic_cast<FlexisipAuthModule*>(am);
		if (fam) {
			fam->challenge(*as, &mProxyChallenger);
			msg_header_insert(ev->getMsgSip()->getMsg(), (msg_pub_t*)sip, (msg_header_t*)as->response());
		} else {
			LOGD("Authentication module for %s not found", as->realm());
		}
	} else {
		LOGD("not handled newauthon401");
	}
}

void Authentication::onIdle() {
	for (auto& it : mAuthModules) {
		AuthModule* am = it.second.get();
		FlexisipAuthModule* fam = dynamic_cast<FlexisipAuthModule*>(am);
		fam->nonceStore().cleanExpired();
	}
}

bool Authentication::doOnConfigStateChanged(const ConfigValue& conf, ConfigState state) {
	if (conf.getName() == "trusted-hosts" && state == ConfigState::Commited) {
		loadTrustedHosts((const ConfigStringList&)conf);
		LOGD("Trusted hosts updated");
		return true;
	} else {
		return Module::doOnConfigStateChanged(conf, state);
	}
}

// ================================================================================================================= //
// Private methods                                                                                                   //
// ================================================================================================================= //

FlexisipAuthModuleBase* Authentication::createAuthModule(const std::string& domain, int nonceExpire, bool qopAuth) {
	FlexisipAuthModule* authModule =
	    new FlexisipAuthModule(getAgent()->getRoot()->getCPtr(), domain, nonceExpire, qopAuth);
	authModule->setOnPasswordFetchResultCb(
	    [this](bool passFound) { passFound ? mCountPassFound++ : mCountPassNotFound++; });
	SLOGI << "Found auth domain: " << domain;
	return authModule;
}

void Authentication::processAuthentication(const std::shared_ptr<RequestSipEvent>& request,
                                           FlexisipAuthModuleBase& am) {
	// check if TLS client certificate provides sufficent authentication for this request.
	if (handleTlsClientAuthentication(request)) throw StopRequestProcessing();

	ModuleAuthenticationBase::processAuthentication(request, am);
}

const char* Authentication::findIncomingSubjectInTrusted(const shared_ptr<RequestSipEvent>& ev,
                                                         const char* fromDomain) {
	if (mTrustedClientCertificates.empty()) return NULL;
	list<string> toCheck;
	for (auto it = mTrustedClientCertificates.cbegin(); it != mTrustedClientCertificates.cend(); ++it) {
		if (it->find("@") != string::npos) toCheck.push_back(*it);
		else toCheck.push_back(*it + "@" + string(fromDomain));
	}
	const char* res = ev->findIncomingSubject(toCheck);
	return res;
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
    " * if no TLS client based authentication can be performed, or has failed, then a SIP digest authentication is "
    "performed. The password verification is made by querying a database or a password file on disk.",
    {"NatHelper"},
    ModuleInfoBase::ModuleOid::Authentication);

// ====================================================================================================================
