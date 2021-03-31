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

#include <flexisip/module-auth.hh>

using namespace std;
using namespace flexisip;

// ====================================================================================================================
//  Authentication class
// ====================================================================================================================

Authentication::Authentication(Agent *ag) : ModuleAuthenticationBase(ag) {}

void Authentication::onDeclare(GenericStruct *mc) {
	ModuleAuthenticationBase::onDeclare(mc);
	ConfigItemDescriptor items[] = {
		{StringList, "trusted-hosts", "List of whitespace-separated IP addresses which will be judged as trustful. "
			"Messages coming from these addresses won't be challenged.", ""},
		{Boolean, "reject-wrong-client-certificates",
			"If set to true, the module will simply reject with \"403 forbidden\" any request coming from clients "
			"which have presented a bad TLS certificate (regardless of reason: improper signature, unmatched subjects). "
			"Otherwise, the module will fallback to a digest authentication.\n"
			"This policy applies only for transports configured which have 'required-peer-certificate=1' parameter; indeed "
			"no certificate is requested to the client otherwise. ",
			"false"
		},
		{String, "tls-client-certificate-required-subject",
			"An optional regular expression used to accept or deny a request basing on subject fields of the "
			"client certificate. The request is allowed if one of the subjects matches the regular expression.\n"
			"The list of subjects to check is built by extracting the following fields, in order:\n"
			"\tsubjectAltNames.DNS, subjectAltNames.URI, subjectAltNames.IP and CN",
			""
		},
		{Boolean, "trust-domain-certificates",
			"Accept requests which the client certificate enables to trust the domaine of its Request-URI.",
			"false"
		},
		{Boolean, "new-auth-on-407", "When receiving a proxy authenticate challenge, generate a new challenge for "
			"this proxy.", "false"},
		{String, "db-implementation",
			"Database backend implementation for digest authentication [soci,file].",
			"file"
		},
		{Integer, "cache-expire", "Duration of the validity of the credentials added to the cache in seconds.", "1800"},

		// deprecated parameters
		{StringList, "trusted-client-certificates", "List of whitespace separated username or username@domain CN "
			"which will trusted. If no domain is given it is computed.",
			""
		},
		{Boolean, "hashed-passwords",
			"True if retrieved passwords from the database are hashed. HA1=MD5(A1) = MD5(username:realm:pass).",
			"false"
		},
		{Boolean, "enable-test-accounts-creation",
			"Enable a feature useful for automatic tests, allowing a client to create a temporary account in the "
			"password database in memory. This MUST not be used for production as it is a real security hole.",
			"false"
		},
		config_item_end
	};

	mc->addChildrenValues(items);

	mc->get<ConfigStringList>("trusted-client-certificates")->setDeprecated(
		{"2018-04-16", "1.0.13", "Use 'tls-client-certificate-required-subject' instead."}
	);
	mc->get<ConfigBoolean>("hashed-passwords")->setDeprecated({
		"2020-01-28", "2.0.0",
		"This setting has been out of use since the algorithm used to hash the password is "
		"stored in the user database and the CLRTXT algorithm can be used to indicate that "
		"the password isn't hashed.\n"
		"Warning: setting 'true' hasn't any effect anymore."
	});
	mc->get<ConfigBoolean>("enable-test-accounts-creation")->setDeprecated({
		"2020-01-28", "2.0.0",
		"This feature was useful for liblinphone's integrity tests and isn't used today anymore. "
		"Please remove this setting from your configuration file."
	});

	// Call declareConfig for backends
	AuthDbBackend::declareConfig(mc);

	mCountAsyncRetrieve = mc->createStat("count-async-retrieve", "Number of asynchronous retrieves.");
	mCountSyncRetrieve = mc->createStat("count-sync-retrieve", "Number of synchronous retrieves.");
	mCountPassFound = mc->createStat("count-password-found", "Number of passwords found.");
	mCountPassNotFound = mc->createStat("count-password-not-found", "Number of passwords not found.");
}

void Authentication::onLoad(const GenericStruct *mc) {
	ModuleAuthenticationBase::onLoad(mc);

	loadTrustedHosts(*mc->get<ConfigStringList>("trusted-hosts"));
	mNewAuthOn407 = mc->get<ConfigBoolean>("new-auth-on-407")->read();
	mTrustedClientCertificates = mc->get<ConfigStringList>("trusted-client-certificates")->read();
	mTrustDomainCertificates = mc->get<ConfigBoolean>("trust-domain-certificates")->read();

	const auto &requiredSubject = mc->get<ConfigString>("tls-client-certificate-required-subject")->read();
	if (!requiredSubject.empty()) {
		try {
			mRequiredSubject.assign(requiredSubject);
			mRequiredSubjectCheckSet = true;
		} catch (const runtime_error &e) {
			LOGF("Could not compile regex for 'tls-client-certificate-required-subject' '%s': %s",
				 requiredSubject.c_str(), e.what()
			);
		}
	}
	mRejectWrongClientCertificates = mc->get<ConfigBoolean>("reject-wrong-client-certificates")->read();
	AuthDbBackend::get(); // force instanciation of the AuthDbBackend NOW, to force errors to arrive now if any.
}

bool Authentication::isTrustedPeer(const shared_ptr<RequestSipEvent> &ev) {
	sip_t *sip = ev->getSip();

	// Check for trusted host
	sip_via_t *via = sip->sip_via;
	const char *printableReceivedHost = !empty(via->v_received) ? via->v_received : via->v_host;

	BinaryIp receivedHost(printableReceivedHost);
	
	if (mTrustedHosts.find(receivedHost) != mTrustedHosts.end()){
		LOGD("Allowing message from trusted host %s", printableReceivedHost);
		return true;
	}
	return false;
}

void Authentication::onResponse(shared_ptr<ResponseSipEvent> &ev) {
	if (!mNewAuthOn407) return; /*nop*/

	auto transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
	if (transaction == nullptr) return;

	auto proxyRealm = transaction->getProperty<string>("this_proxy_realm");
	if (proxyRealm == nullptr) return;

	auto sip = ev->getMsgSip()->getSip();
	if (sip->sip_status->st_status != 407 || !sip->sip_proxy_authenticate) {
		LOGD("not handled newauthon401");
		return;
	}

	auto as = make_shared<Authentifier::AuthStatus>(nullptr);
	as->as_realm = *proxyRealm;
	as->as_user_uri = sip->sip_from->a_url;
	if (!checkDomain(as->as_realm)) {
		LOGD("'%s' not authorized", as->as_realm.c_str());
		return;
	}

	mDigestAuth->challenge(as);
	msg_header_insert(ev->getMsgSip()->getMsg(), (msg_pub_t *)sip, as->as_response);
}

void Authentication::onIdle() {
	mDigestAuth->nonceStore().cleanExpired();
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

// ================================================================================================================= //
// Private methods                                                                                                   //
// ================================================================================================================= //

void Authentication::createAuthModule(int nonceExpire, bool qopAuth) {
	mTrustedHostAuth = make_shared<TrustedHostAuthentifier>(mTrustedHosts);
	mTlsClientAuth = make_shared<TlsClientAuthentifier>(
		vector<string>{mTrustedClientCertificates.cbegin(), mTrustedClientCertificates.cend()}
	);
	mDigestAuth = make_shared<DigestAuthentifier>(getAgent()->getRoot(), nonceExpire, qopAuth);
	mDigestAuth->setOnPasswordFetchResultCb([this](bool passFound){passFound ? mCountPassFound++ : mCountPassNotFound++;});

	mTrustedHostAuth->setNextAuth(mTlsClientAuth)->setNextAuth(mDigestAuth);
	mAuthModules = mTrustedHostAuth;
}

void Authentication::loadTrustedHosts(const ConfigStringList &trustedHosts) {
	list<string> hosts = trustedHosts.read();
	
	for(const auto &host : hosts){
		BinaryIp::emplace(mTrustedHosts, host);
	}

	const GenericStruct *clusterSection = GenericManager::get()->getRoot()->get<GenericStruct>("cluster");
	bool clusterEnabled = clusterSection->get<ConfigBoolean>("enabled")->read();
	if (clusterEnabled) {
		list<string> clusterNodes = clusterSection->get<ConfigStringList>("nodes")->read();
		for(const auto &host : clusterNodes){
			BinaryIp::emplace(mTrustedHosts, host);
		}
	}

	const GenericStruct *presenceSection = GenericManager::get()->getRoot()->get<GenericStruct>("module::Presence");
	bool presenceServer = presenceSection->get<ConfigBoolean>("enabled")->read();
	if (presenceServer) {
		sofiasip::Home home;
		string presenceServer = presenceSection->get<ConfigString>("presence-server")->read();
		sip_contact_t *contact = sip_contact_make(home.home(), presenceServer.c_str());
		url_t *url = contact ? contact->m_url : NULL;
		if (url && url->url_host) {
			BinaryIp::emplace(mTrustedHosts, url->url_host);
			SLOGI << "Added presence server '" << url->url_host << "' to trusted hosts";
		} else {
			SLOGW << "Could not parse presence server URL '" << presenceServer
				<< "', cannot be added to trusted hosts!";
		}
	}
	for (auto trustedHosts :mTrustedHosts) {
		SLOGI << "IP "<< trustedHosts << " added to trusted hosts";
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
	" * if no TLS client based authentication can be performed, or has failed, then a SIP digest authentication is "
	"performed. The password verification is made by querying a database or a password file on disk.",
	{ "NatHelper" },
	ModuleInfoBase::ModuleOid::Authentication
);

// ====================================================================================================================
