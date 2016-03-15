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

#include "module.hh"
#include "agent.hh"
#include <string>
#include <ctime>
#include <map>
#include <list>
#include <vector>
#include "sofia-sip/auth_module.h"
#include "sofia-sip/sip_status.h"
#include "sofia-sip/msg_addr.h"
#include "sofia-sip/auth_plugin.h"
#include "sofia-sip/su_tagarg.h"
#include "sofia-sip/sip_extra.h"

#include "authdb.hh"

using namespace std;
class Authentication;

struct auth_plugin_t {
	su_root_t *mRoot;
	auth_scheme_t *mBase;
	auth_splugin_t *mlist;
	auth_splugin_t **mTail;
	Authentication *mModule;
};
/**
 * to compute auth_mod size with plugin
 */
struct auth_mod_size {
	auth_mod_t mod[1];
	auth_plugin_t plug[1];
};

class NonceStore {
	struct NonceCount {
		NonceCount(int c, time_t ex) : nc(c), expires(ex) {
		}
		int nc;
		time_t expires;
	};
	map<string, NonceCount> mNc;
	mutex mMutex;
	int mNonceExpires;

  public:
	NonceStore() : mNonceExpires(3600) {
	}
	void setNonceExpires(int value) {
		mNonceExpires = value;
	}
	int getNc(const string &nonce) {
		unique_lock<mutex> lck(mMutex);
		auto it = mNc.find(nonce);
		if (it != mNc.end())
			return (*it).second.nc;
		return -1;
	}

	void insert(msg_header_t *response) {
		const char *nonce = msg_header_find_param((msg_common_t const *)response, "nonce");
		string snonce(nonce);
		snonce = snonce.substr(1, snonce.length() - 2);
		LOGD("New nonce %s", snonce.c_str());
		insert(snonce);
	}
	void insert(const string &nonce) {
		unique_lock<mutex> lck(mMutex);
		time_t expiration = getCurrentTime() + mNonceExpires;
		auto it = mNc.find(nonce);
		if (it != mNc.end()) {
			LOGE("Replacing nonce count for %s", nonce.c_str());
			it->second.nc = 0;
			it->second.expires = expiration;
		} else {
			mNc.insert(make_pair(nonce, NonceCount(0, expiration)));
		}
	}

	void updateNc(const string &nonce, int newnc) {
		unique_lock<mutex> lck(mMutex);
		auto it = mNc.find(nonce);
		if (it != mNc.end()) {
			LOGD("Updating nonce %s with nc=%d", nonce.c_str(), newnc);
			(*it).second.nc = newnc;
		} else {
			LOGE("Couldn't update nonce %s: not found", nonce.c_str());
		}
	}

	void erase(const string &nonce) {
		unique_lock<mutex> lck(mMutex);
		LOGD("Erasing nonce %s", nonce.c_str());
		mNc.erase(nonce);
	}

	void cleanExpired() {
		unique_lock<mutex> lck(mMutex);
		int count = 0;
		time_t now = getCurrentTime();
		size_t size = 0;
		for (auto it = mNc.begin(); it != mNc.end();) {
			if (now > it->second.expires) {
				LOGD("Cleaning expired nonce %s", it->first.c_str());
				auto eraseIt = it;
				++it;
				mNc.erase(eraseIt);
				++count;
			} else
				++it;
			size++;
		}
		if (count)
			LOGD("Cleaned %d expired nonces, %zd remaining", count, size);
	}
};

class Authentication : public Module {
  private:
	class AuthenticationListener : public AuthDbListener {
		friend class Authentication;
		Authentication *mModule;
		shared_ptr<RequestSipEvent> mEv;
		auth_mod_t *mAm;
		auth_status_t *mAs;
		auth_challenger_t const *mAch;
		bool mHashedPass;
		bool mPasswordFound;

	  public:
		bool mImmediateRetrievePass;
		bool mNo403;
		auth_response_t mAr;
		AuthenticationListener(Authentication *, shared_ptr<RequestSipEvent>, bool);
		virtual ~AuthenticationListener() {
		}

		void setData(auth_mod_t *am, auth_status_t *as, auth_challenger_t const *ach);
		void checkPassword(const char *password);
		void onResult();
		void onError();
		void finish(); /*the listener is destroyed when calling this, careful*/
		su_root_t *getRoot() {
			return getAgent()->getRoot();
		}
		Agent *getAgent() {
			return mModule->getAgent();
		}
		Authentication *getModule() {
			return mModule;
		}
	};

  private:
	static ModuleInfo<Authentication> sInfo;
	map<string, auth_mod_t *> mAuthModules;
	list<string> mDomains;
	list<string> mTrustedHosts;
	list<string> mTrustedClientCertificates;
	auth_challenger_t mRegistrarChallenger;
	auth_challenger_t mProxyChallenger;
	auth_scheme_t *mOdbcAuthScheme;
	shared_ptr<BooleanExpression> mNo403Expr;
	AuthenticationListener *mCurrentAuthOp;
	bool dbUseHashedPasswords;
	bool mImmediateRetrievePassword;
	bool mNewAuthOn407;
	bool mTestAccountsEnabled;
	bool mDisableQOPAuth;

	static int authPluginInit(auth_mod_t *am, auth_scheme_t *base, su_root_t *root, tag_type_t tag, tag_value_t value,
							  ...) {
		auth_plugin_t *ap = AUTH_PLUGIN(am);
		int retval = -1;
		ta_list ta;
		ta_start(ta, tag, value);

		if (auth_init_default(am, base, root, ta_tags(ta)) != -1) {
			ap->mRoot = root;
			ap->mBase = base;
			ap->mTail = &ap->mlist;
			retval = 0;
		} else {
			LOGE("cannot init odbc plugin");
		}
		auth_readdb_if_needed(am);
		ta_end(ta);
		return retval;
	}
	bool empty(const char *value) {
		return value == NULL || value[0] == '\0';
	}

	void static flexisip_auth_method_digest(auth_mod_t *am, auth_status_t *as, msg_auth_t *au,
											auth_challenger_t const *ach);
	void static flexisip_auth_check_digest(auth_mod_t *am, auth_status_t *as, auth_response_t *ar,
										   auth_challenger_t const *ach);
	const char *findIncomingSubjectInTrusted(shared_ptr<RequestSipEvent> &ev, const char *fromDomain) {
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

	void loadTrustedHosts(const ConfigStringList &trustedHosts) {
		mTrustedHosts = trustedHosts.read();
		const GenericStruct *clusterSection = GenericManager::get()->getRoot()->get<GenericStruct>("cluster");
		bool clusterEnabled = clusterSection->get<ConfigBoolean>("enabled")->read();
		if (clusterEnabled) {
			list<string> clusterNodes = clusterSection->get<ConfigStringList>("nodes")->read();
			for (list<string>::const_iterator node = clusterNodes.cbegin(); node != clusterNodes.cend(); node++) {
				if (find(mTrustedHosts.cbegin(), mTrustedHosts.cend(), *node) == mTrustedHosts.cend()) {
					mTrustedHosts.push_back(*node);
				}
			}
		}
	}

  public:
	StatCounter64 *mCountAsyncRetrieve;
	StatCounter64 *mCountSyncRetrieve;
	StatCounter64 *mCountPassFound;
	StatCounter64 *mCountPassNotFound;
	NonceStore mNonceStore;

	Authentication(Agent *ag) : Module(ag), mCountAsyncRetrieve(NULL), mCountSyncRetrieve(NULL) {
		mNewAuthOn407 = false;
		mProxyChallenger.ach_status = 407; /*SIP_407_PROXY_AUTH_REQUIRED*/
		mProxyChallenger.ach_phrase = sip_407_Proxy_auth_required;
		mProxyChallenger.ach_header = sip_proxy_authenticate_class;
		mProxyChallenger.ach_info = sip_proxy_authentication_info_class;

		mRegistrarChallenger.ach_status = 401; /*SIP_401_UNAUTHORIZED*/
		mRegistrarChallenger.ach_phrase = sip_401_Unauthorized;
		mRegistrarChallenger.ach_header = sip_www_authenticate_class;
		mRegistrarChallenger.ach_info = sip_authentication_info_class;

		auth_scheme *lOdbcAuthScheme = new auth_scheme();
		lOdbcAuthScheme->asch_method = "odbc";
		lOdbcAuthScheme->asch_size = sizeof(struct auth_mod_size);
		lOdbcAuthScheme->asch_init = authPluginInit;
		lOdbcAuthScheme->asch_check = flexisip_auth_method_digest;
		lOdbcAuthScheme->asch_challenge = auth_challenge_digest;
		lOdbcAuthScheme->asch_cancel = auth_cancel_default;
		lOdbcAuthScheme->asch_destroy = auth_destroy_default;
		mOdbcAuthScheme = lOdbcAuthScheme;
		if (auth_mod_register_plugin(mOdbcAuthScheme)) {
			LOGE("Cannot register auth plugin");
		}
		mCurrentAuthOp = NULL;
	}

	~Authentication() {
		for (auto it = mAuthModules.begin(); it != mAuthModules.end(); ++it) {
			auth_mod_destroy(it->second);
		}
		mAuthModules.clear();

		delete mOdbcAuthScheme;
	}

	virtual void onDeclare(GenericStruct *mc) {
		ConfigItemDescriptor items[] = {

			{StringList, "auth-domains", "List of whitespace separated domain names to challenge. Others are denied.",
			 "localhost"},

			{StringList, "trusted-hosts", "List of whitespace separated IP which will not be challenged.", ""},

			{String, "db-implementation", "Database backend implementation [odbc,soci,file,fixed].", "fixed"},

			{String, "datasource",
			 "Odbc connection string to use for connecting to database. "
			 "ex1: DSN=myodbc3; where 'myodbc3' is the datasource name. "
			 "ex2: DRIVER={MySQL};SERVER=host;DATABASE=db;USER=user;PASSWORD=pass;OPTION=3; for a DSN-less connection. "
			 "ex3: /etc/flexisip/passwd; for a file containing one 'user@domain password' by line.",
			 ""},

			{Integer, "nonce-expires", "Expiration time of nonces, in seconds.", "3600"},

			{Integer, "cache-expire", "Duration of the validity of the credentials added to the cache in seconds.",
			 "1800"},

			{Boolean, "hashed-passwords",
			 "True if retrieved passwords from the database are hashed. HA1=MD5(A1) = MD5(username:realm:pass).",
			 "false"},

			{BooleanExpr, "no-403", "Don't reply 403, but 401 or 407 even in case of wrong authentication.", "false"},

			{StringList, "trusted-client-certificates", "List of whitespace separated username or username@domain CN "
														"which will trusted. If no domain is given it is computed.",
			 ""},

			{Boolean, "new-auth-on-407",
			 "When receiving a proxy authenticate challenge, generate a new challenge for this proxy.", "false"},

			{Boolean, "enable-test-accounts-creation",
			 "Enable a feature useful for automatic tests, allowing a client to create a temporary account in the "
			 "password database in memory."
			 "This MUST not be used for production as it is a real security hole.",
			 "false"},

			{Boolean, "disable-qop-auth",
			 "Disable the QOP authentication method. Default is to use it, use this flag to disable it if needed.",
			 "false"},

			config_item_end};
		mc->addChildrenValues(items);
		/* modify the default value for "enabled" */
		mc->get<ConfigBoolean>("enabled")->setDefault("false");

		// Call declareConfig for backends
		AuthDbBackend::declareConfig(mc);

		mCountAsyncRetrieve = mc->createStat("count-async-retrieve", "Number of asynchronous retrieves.");
		mCountSyncRetrieve = mc->createStat("count-sync-retrieve", "Number of synchronous retrieves.");
		mCountPassFound = mc->createStat("count-password-found", "Number of passwords found.");
		mCountPassNotFound = mc->createStat("count-password-not-found", "Number of passwords not found.");
	}

	void onLoad(const GenericStruct *mc) {
		list<string>::const_iterator it;
		int nonceExpires;
		mDomains = mc->get<ConfigStringList>("auth-domains")->read();
		nonceExpires = mc->get<ConfigInt>("nonce-expires")->read();

		loadTrustedHosts(*mc->get<ConfigStringList>("trusted-hosts"));
		dbUseHashedPasswords = mc->get<ConfigBoolean>("hashed-passwords")->read();
		mImmediateRetrievePassword = true;
		mNewAuthOn407 = mc->get<ConfigBoolean>("new-auth-on-407")->read();
		mTrustedClientCertificates = mc->get<ConfigStringList>("trusted-client-certificates")->read();
		mNo403Expr = mc->get<ConfigBooleanExpression>("no-403")->read();
		mTestAccountsEnabled = mc->get<ConfigBoolean>("enable-test-accounts-creation")->read();
		mDisableQOPAuth = mc->get<ConfigBoolean>("disable-qop-auth")->read();
		mNonceStore.setNonceExpires(nonceExpires);

		for (it = mDomains.begin(); it != mDomains.end(); ++it) {
			auto domain = *it;

			mAuthModules[*it] = createAuthModule(domain, nonceExpires);
			auth_plugin_t *ap = AUTH_PLUGIN(mAuthModules[*it]);
			ap->mModule = this;
			LOGI("Found auth domain: %s", (*it).c_str());
			if (mAuthModules[*it] == NULL) {
				LOGE("Cannot create auth module odbc");
			}
		}
	}

	auth_mod_t *findAuthModule(const char *name) {
		auto it = mAuthModules.find(name);
		if (it == mAuthModules.end())
			it = mAuthModules.find("*");
		if (it == mAuthModules.end()) {
			return NULL;
		}
		return it->second;
	}

	auth_mod_t *createAuthModule(const std::string &domain, int nonceExpires) {
		if (mDisableQOPAuth) {
			return auth_mod_create(NULL, AUTHTAG_METHOD("odbc"), AUTHTAG_REALM(domain.c_str()),
								   AUTHTAG_OPAQUE("+GNywA=="), AUTHTAG_FORBIDDEN(1), AUTHTAG_ALLOW("ACK CANCEL BYE"),
								   TAG_END());
		} else {
			return auth_mod_create(NULL, AUTHTAG_METHOD("odbc"), AUTHTAG_REALM(domain.c_str()),
								   AUTHTAG_OPAQUE("+GNywA=="), AUTHTAG_QOP("auth"),
								   AUTHTAG_EXPIRES(nonceExpires),	  // in seconds
								   AUTHTAG_NEXT_EXPIRES(nonceExpires), // in seconds
								   AUTHTAG_FORBIDDEN(1), AUTHTAG_ALLOW("ACK CANCEL BYE"), TAG_END());
		}
	}

	static bool containsDomain(const list<string> &d, const char *name) {
		return find(d.cbegin(), d.cend(), "*") != d.end() || find(d.cbegin(), d.cend(), name) != d.end();
	}

	void handleTestAccountCreationRequests(shared_ptr<RequestSipEvent> &ev) {
		sip_t *sip = ev->getSip();
		if (sip->sip_request->rq_method == sip_method_register) {
			sip_unknown_t *h = ModuleToolbox::getCustomHeaderByName(sip, "X-Create-Account");
			if (h && strcasecmp(h->un_value, "yes") == 0) {
				url_t *url = sip->sip_from->a_url;
				if (url) {
					AuthDbBackend::get()->createAccount(url, url->url_user, url->url_password,
														sip->sip_expires->ex_delta);
					LOGD("Account created for %s@%s with password %s and expires %i", url->url_user, url->url_host,
						 url->url_password, (int)sip->sip_expires->ex_delta);
				}
			}
		}
	}

	bool isTrustedPeer(shared_ptr<RequestSipEvent> &ev) {
		sip_t *sip = ev->getSip();

		// Check for trusted host
		sip_via_t *via = sip->sip_via;
		list<string>::const_iterator trustedHostsIt = mTrustedHosts.begin();
		const char *receivedHost = !empty(via->v_received) ? via->v_received : via->v_host;
		for (; trustedHostsIt != mTrustedHosts.end(); ++trustedHostsIt) {
			if (*trustedHostsIt == receivedHost) {
				LOGD("Allowing message from trusted host %s", receivedHost);
				return true;
			}
		}
		return false;
	}

	bool isTlsClientAuthenticated(shared_ptr<RequestSipEvent> &ev) {
		sip_t *sip = ev->getSip();
		shared_ptr<tport_t> inTport = ev->getIncomingTport();

		// Check TLS certificate
		if (tport_has_tls(inTport.get())) {
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
				return true;
			} else if (sip->sip_request->rq_method != sip_method_register &&
					   (res = findIncomingSubjectInTrusted(ev, fromDomain))) {
				SLOGD << "Allowing message from trusted TLS certificate " << res;
				return true;
			} else {
				/*case where the certificate would work for the entire domain*/
				searched_uri.url_user = NULL;
				searched = url_as_string(home.home(), &searched_uri);
				if (ev->findIncomingSubject(searched)) {
					SLOGD << "Allowing message from matching TLS certificate for entire domain";
					return true;
				}
			}
			LOGE("Client is presenting a TLS certificate not matching its identity.");
		}
		return false;
	}

	void onRequest(shared_ptr<RequestSipEvent> &ev) throw (FlexisipException) {
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
		if (mTestAccountsEnabled)
			handleTestAccountCreationRequests(ev);

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
		auth_mod_t *am = findAuthModule(fromDomain);
		if (am == NULL) {
			LOGI("Unknown domain [%s]", fromDomain);
			ev->reply(403, "Domain forbidden", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
			return;
		}

		// check if TLS client certificate provides sufficent authentication for this request.
		if (isTlsClientAuthenticated(ev))
			return;

		// Check for the existence of username, which is required for proceeding with digest authentication in flexisip.
		// Reject if absent.
		if (sip->sip_from->a_url->url_user == NULL) {
			LOGI("From has no username, cannot authenticate.");
			ev->reply(403, "Username must be provided", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
			return;
		}

		// Create incoming transaction if not already exists
		// Necessary in qop=auth to prevent nonce count chaos
		// with retransmissions.
		ev->createIncomingTransaction();

		auth_status_t *as;
		as = auth_status_new(ms->getHome());
		as->as_method = sip->sip_request->rq_method_name;
		as->as_source = msg_addrinfo(ms->getMsg());
		as->as_user_uri = ppi ? ppi->ppid_url : sip->sip_from->a_url;
		as->as_realm = as->as_user_uri->url_host;
		as->as_display = sip->sip_from->a_display;
		if (sip->sip_payload)
			as->as_body = sip->sip_payload->pl_data, as->as_bodylen = sip->sip_payload->pl_len;

		AuthenticationListener *listener = new AuthenticationListener(this, ev, dbUseHashedPasswords);
		listener->mImmediateRetrievePass = mImmediateRetrievePassword;
		listener->mNo403 = mNo403Expr->eval(ev->getSip());
		as->as_magic = mCurrentAuthOp = listener;

		// Attention: the auth_mod_verify method should not send by itself any message but
		// return after having set the as status and phrase.
		// Another point in asynchronous mode is that the asynchronous callbacks MUST be called
		// AFTER the nta_msg_treply bellow. Otherwise the as would be already destroyed.
		if (sip->sip_request->rq_method == sip_method_register) {
			auth_mod_verify(am, as, sip->sip_authorization, &mRegistrarChallenger);
		} else {
			auth_mod_verify(am, as, sip->sip_proxy_authorization, &mProxyChallenger);
		}
		if (mCurrentAuthOp) {
			/*it has not been cleared by the listener itself, so password checking is still in progress. We need to
			 * suspend the event*/
			// Send pending message, needed data will be kept as long
			// as SipEvent is held in the listener.
			ev->suspendProcessing();
		}
	}
	void onResponse(shared_ptr<ResponseSipEvent> &ev) throw (FlexisipException){
		if (!mNewAuthOn407)
			return; /*nop*/

		shared_ptr<OutgoingTransaction> transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
		if (transaction == NULL)
			return;

		shared_ptr<string> proxyRealm = transaction->getProperty<string>("this_proxy_realm");
		if (proxyRealm == NULL)
			return;

		sip_t *sip = ev->getMsgSip()->getSip();
		if (sip->sip_status->st_status == 407 && sip->sip_proxy_authenticate) {
			auth_status_t *as = auth_status_new(ev->getMsgSip()->getHome());
			as->as_realm = proxyRealm.get()->c_str();
			as->as_user_uri = sip->sip_from->a_url;
			auth_mod_t *am = findAuthModule(as->as_realm);
			if (am) {
				auth_challenge_digest(am, as, &mProxyChallenger);
				mNonceStore.insert(as->as_response);
				msg_header_insert(ev->getMsgSip()->getMsg(), (msg_pub_t *)sip, (msg_header_t *)as->as_response);
			} else {
				LOGD("Authentication module for %s not found", as->as_realm);
			}
		} else {
			LOGD("not handled newauthon401");
		}
	}

	void onIdle() {
		mNonceStore.cleanExpired();
	}

	virtual bool doOnConfigStateChanged(const ConfigValue &conf, ConfigState state) {
		if (conf.getName() == "trusted-hosts" && state == ConfigState::Commited) {
			loadTrustedHosts((const ConfigStringList &)conf);
			LOGD("Trusted hosts updated");
			return true;
		} else {
			return Module::doOnConfigStateChanged(conf, state);
		}
	}
};

ModuleInfo<Authentication> Authentication::sInfo(
	"Authentication",
	"The authentication module challenges and authenticates SIP requests using two possible methods: \n"
	" * if the request is received via a TLS transport and 'require-peer-certificate' is set in transport definition "
	"in [Global] section for this transport, "
	" then the From header of the request is matched with the CN claimed by the client certificate. The CN must "
	"contain sip:user@domain or alternate name with URI=sip:user@domain"
	" corresponding to the URI in the from header for the request to be accepted.\n"
	" * if no TLS client based authentication can be performed, or is failed, then a SIP digest authentication is "
	"performed. The password verification is made by querying"
	" a database or a password file on disk.",
	ModuleInfoBase::ModuleOid::Authentication);

Authentication::AuthenticationListener::AuthenticationListener(Authentication *module, shared_ptr<RequestSipEvent> ev,
															   bool hashedPasswords)
	: mModule(module), mEv(ev), mAm(NULL), mAs(NULL), mAch(NULL), mHashedPass(hashedPasswords), mPasswordFound(false) {
	memset(&mAr, '\0', sizeof(mAr)), mAr.ar_size = sizeof(mAr);
	mNo403 = false;
}

void Authentication::AuthenticationListener::setData(auth_mod_t *am, auth_status_t *as, auth_challenger_t const *ach) {
	this->mAm = am;
	this->mAs = as;
	this->mAch = ach;
}

/**
 * return true if the event is terminated
 */
void Authentication::AuthenticationListener::finish() {
	const shared_ptr<MsgSip> &ms = mEv->getMsgSip();
	sip_t *sip = ms->getSip();
	if (mAs->as_status) {
		if (mAs->as_status != 401 && mAs->as_status != 407) {
			auto log =
				make_shared<AuthLog>(sip->sip_request->rq_method_name, sip->sip_from, sip->sip_to, mPasswordFound);
			log->setStatusCode(mAs->as_status, mAs->as_phrase);
			log->setOrigin(sip->sip_via);
			if (sip->sip_user_agent)
				log->setUserAgent(sip->sip_user_agent);
			log->setCompleted();
			mEv->setEventLog(log);
		}
		mEv->reply(mAs->as_status, mAs->as_phrase, SIPTAG_HEADER((const sip_header_t *)mAs->as_info),
				   SIPTAG_HEADER((const sip_header_t *)mAs->as_response),
				   SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	} else {
		// Success
		if (sip->sip_request->rq_method == sip_method_register) {
			msg_auth_t *au =
				ModuleToolbox::findAuthorizationForRealm(ms->getHome(), sip->sip_authorization, mAs->as_realm);
			if (au)
				msg_header_remove(ms->getMsg(), (msg_pub_t *)sip, (msg_header_t *)au);
		} else {
			msg_auth_t *au =
				ModuleToolbox::findAuthorizationForRealm(ms->getHome(), sip->sip_proxy_authorization, mAs->as_realm);
			if (au)
				msg_header_remove(ms->getMsg(), (msg_pub_t *)sip, (msg_header_t *)au);
		}
		if (mEv->isSuspended()) {
			// The event is re-injected
			getAgent()->injectRequestEvent(mEv);
		}
	}
	if (mModule->mCurrentAuthOp == this) {
		mModule->mCurrentAuthOp = NULL;
	}
	delete this;
}

/**
 * NULL if passwd not found.
 */
void Authentication::AuthenticationListener::checkPassword(const char *passwd) {
	char const *a1;
	auth_hexmd5_t a1buf, response;

	if (passwd && passwd[0] == '\0')
		passwd = NULL;

	if (passwd) {
		mPasswordFound = true;
		++*getModule()->mCountPassFound;
		if (mHashedPass) {
			strncpy(a1buf, passwd, 33); // remove trailing NULL character
			a1 = a1buf;
		} else {
			auth_digest_a1(&mAr, a1buf, passwd), a1 = a1buf;
		}
	} else {
		++*getModule()->mCountPassNotFound;
		auth_digest_a1(&mAr, a1buf, "xyzzy"), a1 = a1buf;
	}

	if (mAr.ar_md5sess)
		auth_digest_a1sess(&mAr, a1buf, a1), a1 = a1buf;

	auth_digest_response(&mAr, response, a1, mAs->as_method, mAs->as_body, mAs->as_bodylen);

	if (!passwd || strcmp(response, mAr.ar_response)) {

		if (mAm->am_forbidden && !mNo403) {
			mAs->as_status = 403, mAs->as_phrase = "Forbidden";
			mAs->as_response = NULL;
			mAs->as_blacklist = mAm->am_blacklist;
		} else {
			auth_challenge_digest(mAm, mAs, mAch);
			getModule()->mNonceStore.insert(mAs->as_response);
			mAs->as_blacklist = mAm->am_blacklist;
		}
		if (passwd) {
			LOGD("auth_method_digest: password '%s' did not match", passwd);
		} else {
			LOGD("auth_method_digest: no password");
		}

		return;
	}

	// assert(apw);
	mAs->as_user = mAr.ar_username;
	mAs->as_anonymous = false;

	if (mAm->am_nextnonce || mAm->am_mutual)
		auth_info_digest(mAm, mAs, mAch);

	if (mAm->am_challenge)
		auth_challenge_digest(mAm, mAs, mAch);

	LOGD("auth_method_digest: successful authentication");

	mAs->as_status = 0; /* Successful authentication! */
	mAs->as_phrase = "";
}

void Authentication::AuthenticationListener::onResult() {
	switch (mResult) {
		case PASSWORD_FOUND:
		case PASSWORD_NOT_FOUND:
			checkPassword(mPassword.c_str());
			finish();
			break;
		case AUTH_ERROR:
			onError();
			break;
		default:
			LOGE("Unhandled asynchronous response %u", mResult);
			onError();
	}
}

void Authentication::AuthenticationListener::onError() {
	if (!mAs->as_status) {
		mAs->as_status = 500, mAs->as_phrase = "Internal error";
		mAs->as_response = NULL;
	}
	finish();
}

#define PA "Authorization missing "

/** Verify digest authentication */
void Authentication::flexisip_auth_check_digest(auth_mod_t *am, auth_status_t *as, auth_response_t *ar,
												auth_challenger_t const *ach) {

	AuthenticationListener *listener = (AuthenticationListener *)as->as_magic;

	if (am == NULL || as == NULL || ar == NULL || ach == NULL) {
		if (as) {
			as->as_status = 500, as->as_phrase = "Internal Server Error";
			as->as_response = NULL;
		}
		listener->finish();
		return;
	}

	char const *phrase = "Bad authorization ";
	if ((!ar->ar_username && (phrase = PA "username")) || (!ar->ar_nonce && (phrase = PA "nonce")) ||
		(!listener->mModule->mDisableQOPAuth && !ar->ar_nc && (phrase = PA "nonce count")) ||
		(!ar->ar_uri && (phrase = PA "URI")) || (!ar->ar_response && (phrase = PA "response")) ||
		/* (!ar->ar_opaque && (phrase = PA "opaque")) || */
		/* Check for qop */
		(ar->ar_qop &&
		 ((ar->ar_auth && !strcasecmp(ar->ar_qop, "auth") && !strcasecmp(ar->ar_qop, "\"auth\"")) ||
		  (ar->ar_auth_int && !strcasecmp(ar->ar_qop, "auth-int") && !strcasecmp(ar->ar_qop, "\"auth-int\""))) &&
		 (phrase = PA "has invalid qop"))) {
		// assert(phrase);
		LOGD("auth_method_digest: 400 %s", phrase);
		as->as_status = 400, as->as_phrase = phrase;
		as->as_response = NULL;
		listener->finish();
		return;
	}

	if (!ar->ar_username || !as->as_user_uri->url_user || !ar->ar_realm || !as->as_user_uri->url_host) {
		as->as_status = 403, as->as_phrase = "Authentication info missing";
		LOGD("from and authentication usernames [%s/%s] or from and authentication hosts [%s/%s] empty",
			 ar->ar_username, as->as_user_uri->url_user, ar->ar_realm, as->as_user_uri->url_host);
		as->as_response = NULL;
		listener->finish();
		return;
	}

	Authentication *module = listener->getModule();
	msg_time_t now = msg_now();
	if (as->as_nonce_issued == 0 /* Already validated nonce */ && auth_validate_digest_nonce(am, as, ar, now) < 0) {
		as->as_blacklist = am->am_blacklist;
		auth_challenge_digest(am, as, ach);
		module->mNonceStore.insert(as->as_response);
		listener->finish();
		return;
	}

	if (as->as_stale) {
		auth_challenge_digest(am, as, ach);
		module->mNonceStore.insert(as->as_response);
		listener->finish();
		return;
	}

	if (!listener->mModule->mDisableQOPAuth) {
		int pnc = module->mNonceStore.getNc(ar->ar_nonce);
		int nnc = (int)strtoul(ar->ar_nc, NULL, 16);
		if (pnc == -1 || pnc >= nnc) {
			LOGE("Bad nonce count %d -> %d for %s", pnc, nnc, ar->ar_nonce);
			as->as_blacklist = am->am_blacklist;
			auth_challenge_digest(am, as, ach);
			module->mNonceStore.insert(as->as_response);
			listener->finish();
			return;
		} else {
			module->mNonceStore.updateNc(ar->ar_nonce, nnc);
		}
	}

	AuthDbBackend::get()->getPassword(listener->getRoot(), as->as_user_uri, ar->ar_username, listener);
}

class DummyListener : public AuthDbListener {
	virtual void onResult() {
		delete this;
	}
};

/** Authenticate a request with @b Digest authentication scheme.
 */
void Authentication::flexisip_auth_method_digest(auth_mod_t *am, auth_status_t *as, msg_auth_t *au,
												 auth_challenger_t const *ach) {
	AuthenticationListener *listener = (AuthenticationListener *)as->as_magic;
	listener->setData(am, as, ach);

	as->as_allow = as->as_allow || auth_allow_check(am, as) == 0;

	if (as->as_realm)
		au = auth_digest_credentials(au, as->as_realm, am->am_opaque);
	else
		au = NULL;

	if (as->as_allow) {
		LOGD("%s: allow unauthenticated %s", __func__, as->as_method);
		as->as_status = 0, as->as_phrase = NULL;
		as->as_match = (msg_header_t *)au;
		return;
	}

	if (au) {
		SLOGD << "Searching for auth digest response for this proxy";
		msg_auth_t *matched_au = ModuleToolbox::findAuthorizationForRealm(as->as_home, au, as->as_realm);
		if (matched_au)
			au = matched_au;
		auth_digest_response_get(as->as_home, &listener->mAr, au->au_params);
		SLOGD << "Using auth digest response for realm " << listener->mAr.ar_realm;
		as->as_match = (msg_header_t *)au;
		flexisip_auth_check_digest(am, as, &listener->mAr, ach);
	} else {
		/* There was no realm or credentials, send challenge */
		SLOGD << __func__ << ": no credentials matched realm or no realm";
		auth_challenge_digest(am, as, ach);
		listener->getModule()->mNonceStore.insert(as->as_response);

		// Retrieve the password in the hope it will be in cache when the remote UAC
		// sends back its request; this time with the expected authentication credentials.
		if (listener->mImmediateRetrievePass) {
			SLOGD << "Searching for " << as->as_user_uri->url_user
				  << " password to have it when the authenticated request comes";
			AuthDbBackend::get()->getPassword(listener->getRoot(), as->as_user_uri, as->as_user_uri->url_user,
											  new DummyListener());
		}
		listener->finish();
		return;
	}
}
