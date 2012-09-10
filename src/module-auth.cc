/*
	Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010  Belledonne Communications SARL.

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

#include "authdb.hh"

using namespace ::std;

const static int NONCE_EXPIRES=100;
const static int NEXT_NONCE_EXPIRES=100;

class Authentication;

struct auth_plugin_t
{
  su_root_t      *mRoot;
  auth_scheme_t  *mBase;
  auth_splugin_t *mlist;
  auth_splugin_t**mTail;
  Authentication *mModule;
};
/**
 * to compute auth_mod size with plugin
 */
struct auth_mod_size { auth_mod_t mod[1]; auth_plugin_t plug[1]; };


class NonceStore {
	map<string,int> nc;
	map<string, time_t> expires;
	mutex mut;
public:
	int getNc(const string &nonce) {
		unique_lock<mutex> lck(mut);
		auto it=nc.find(nonce);
		if (it!=nc.end()) return (*it).second;
		return -1;
	}

	void insert(msg_header_t *response) {
		const char *nonce=msg_header_find_param((msg_common_t const *) response, "nonce");
		string snonce(nonce);
		snonce=snonce.substr(1, snonce.length()-2);
		LOGD("New nonce %s", snonce.c_str());
		insert(snonce);
	}
	void insert(const string &nonce) {
		unique_lock<mutex> lck(mut);
		auto it=nc.find(nonce);
		if (it!=nc.end()) {
			LOGE("Replacing nonce count for %s", nonce.c_str());
			it->second=0;
		} else {
			nc.insert(make_pair(nonce,0));
		}

		auto itE=expires.find(nonce);
		time_t expiration=time(NULL)+NONCE_EXPIRES;
		if (itE!=expires.end()) {
			LOGE("Replacing nonce expiration for %s", nonce.c_str());
			itE->second=expiration;
		} else {
			expires.insert(make_pair(nonce,expiration));
		}
	}

	void updateNc(const string &nonce, int newnc) {
		unique_lock<mutex> lck(mut);
		auto it=nc.find(nonce);
		if (it!=nc.end()) {
			LOGD("Updating nonce %s with nc=%d", nonce.c_str(), newnc);
			(*it).second=newnc;
		} else {
			LOGE("Couldn't update nonce %s: not found", nonce.c_str());
		}
	}

	void erase(const string &nonce) {
		unique_lock<mutex> lck(mut);
		LOGD("Erasing nonce %s", nonce.c_str());
		nc.erase(nonce);
		expires.erase(nonce);
	}

	void cleanExpired() {
		unique_lock<mutex> lck(mut);
		int count=0;
		time_t now =time(NULL);
		for (auto it=expires.begin(); it != expires.end(); ) {
			if (now > it->second) {
				LOGD("Cleaning expired nonce %s", it->first.c_str());
				auto eraseIt=it;
				++it;
				nc.erase(eraseIt->first);
				expires.erase(eraseIt);
				++count;
			} else 	++it;
		}
		if (count) LOGD("Cleaned %d expired nonces, %zd remaining", count, nc.size());
	}
};


class Authentication : public Module {
private:
	class AuthenticationListener : public AuthDbListener {
		Agent *mAgent;
		shared_ptr<RequestSipEvent> mEv;
		bool mHashedPass;
		auth_mod_t *mAm;
		auth_status_t *mAs;
		auth_challenger_t const *mAch;
	public:
		bool mImmediateRetrievePass;
		auth_response_t mAr;
		AuthenticationListener(Agent *, shared_ptr<RequestSipEvent>, bool);
		virtual ~AuthenticationListener(){};

		void setData(auth_mod_t *am, auth_status_t *as, auth_challenger_t const *ach);
		void checkPassword(const char *password);
		void onAsynchronousResponse(AuthDbResult ret, const char *password);
		void switchToAsynchronousMode();
		void onError();
		bool sendReply();
		su_root_t *getRoot() {
			return mAgent->getRoot();
		}
		Authentication *getModule() {
			return static_cast<Authentication *>(mEv->getCurrentModule());
		}
	};
private:
	map<string,auth_mod_t *> mAuthModules;
	list<string> mDomains;
	list<string> mTrustedHosts;
	static ModuleInfo<Authentication> sInfo;
	auth_challenger_t mRegistrarChallenger;
	auth_challenger_t mProxyChallenger;
	auth_scheme_t* mOdbcAuthScheme;
	static int authPluginInit(auth_mod_t *am,
				     auth_scheme_t *base,
				     su_root_t *root,
				     tag_type_t tag, tag_value_t value, ...) {
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
	bool empty(const char *value){
		return value==NULL || value[0]=='\0';
	}
	bool dbUseHashedPasswords;
	bool mImmediateRetrievePassword;
	bool mNewAuthOn407;

	void static flexisip_auth_method_digest(auth_mod_t *am,
				auth_status_t *as, msg_auth_t *au, auth_challenger_t const *ach);
	void static flexisip_auth_check_digest(auth_mod_t *am,
		       auth_status_t *as, auth_response_t *ar, auth_challenger_t const *ach);

public:
	StatCounter64 *mCountAsyncRetrieve;
	StatCounter64 *mCountSyncRetrieve;
	StatCounter64 *mCountPassFound;
	StatCounter64 *mCountPassNotFound;
	NonceStore mNonceStore;

	Authentication(Agent *ag):Module(ag),mCountAsyncRetrieve(NULL),mCountSyncRetrieve(NULL){
		mNewAuthOn407=false;
		mProxyChallenger.ach_status=407;/*SIP_407_PROXY_AUTH_REQUIRED*/
		mProxyChallenger.ach_phrase=sip_407_Proxy_auth_required;
		mProxyChallenger.ach_header=sip_proxy_authenticate_class;
		mProxyChallenger.ach_info=sip_proxy_authentication_info_class;

		mRegistrarChallenger.ach_status=401;/*SIP_401_UNAUTHORIZED*/
		mRegistrarChallenger.ach_phrase=sip_401_Unauthorized;
		mRegistrarChallenger.ach_header=sip_www_authenticate_class;
		mRegistrarChallenger.ach_info=sip_authentication_info_class;

		auth_scheme* lOdbcAuthScheme = new auth_scheme();
		lOdbcAuthScheme->asch_method="odbc";
		lOdbcAuthScheme->asch_size=sizeof (struct auth_mod_size);
		lOdbcAuthScheme->asch_init=authPluginInit;
		lOdbcAuthScheme->asch_check=flexisip_auth_method_digest;
		lOdbcAuthScheme->asch_challenge=auth_challenge_digest;
		lOdbcAuthScheme->asch_cancel=auth_cancel_default;
		lOdbcAuthScheme->asch_destroy=auth_destroy_default;
		mOdbcAuthScheme=lOdbcAuthScheme;
		if (auth_mod_register_plugin(mOdbcAuthScheme)) {
			LOGE("Cannot register auth plugin");
		}
	}

	~Authentication(){
		for(auto it = mAuthModules.begin(); it != mAuthModules.end(); ++it) {
			auth_mod_destroy(it->second);
		}
		mAuthModules.clear();

		delete mOdbcAuthScheme;
	}

	virtual void onDeclare(GenericStruct * mc){
		ConfigItemDescriptor items[]={
			{	StringList	,	"auth-domains"	, 	"List of whitespace separated domain names to challenge. Others are denied.",	""	},
			{	StringList	,	"trusted-hosts"	, 	"List of whitespace separated IP which will not be challenged.",	""	},
			{	String		,	"db-implementation"		,	"Database backend implementation [odbc, file].",		"odbc"	},
			{	String		,	"datasource"		,	"Odbc connection string to use for connecting to database. " \
					"ex1: DSN=myodbc3; where 'myodbc3' is the datasource name. " \
					"ex2: DRIVER={MySQL};SERVER=host;DATABASE=db;USER=user;PASSWORD=pass;OPTION=3; for a DSN-less connection. " \
					"ex3: /etc/flexisip/passwd; for a file containing one 'user@domain password' by line.",		""	},
			{	String		,	"request"				,	"Odbc SQL request to execute to obtain the password \n. "
					"Named parameters are :id (the user found in the from header), :domain (the authorization realm) and :authid (the authorization username). "
					"The use of the :id parameter is mandatory.",
					"select password from accounts where id = :id and domain = :domain and authid=:authid"	},
			{	Integer		,	"max-id-length"	,	"Maximum length of the login column in database.",	"100"	},
			{	Integer		,	"max-password-length"	,	"Maximum length of the password column in database",	"100"	},
			{	Boolean		,	"odbc-pooling"	,	"Use pooling in odbc",	"true"	},
			{	Integer		,	"odbc-display-timings-interval"	,	"Display timing statistics after this count of seconds",	"0"	},
			{	Integer		,	"odbc-display-timings-after-count"	,	"Display timing statistics once the number of samples reach this number.",	"0"	},
			{	Boolean		,	"odbc-asynchronous"	,	"Retrieve passwords asynchronously.",	"false"	},
			{	Integer		,	"cache-expire"	,	"Duration of the validity of the credentials added to the cache in seconds.",	"1800"	},
			{	Boolean		,	"immediate-retrieve-password"	,	"Retrieve password immediately so that it is cached when an authenticated request arrives.",	"true"},
			{	Boolean		,	"hashed-passwords"	,	"True if retrieved passwords from the database are hashed. HA1=MD5(A1) = MD5(username:realm:pass).", "false" },
			{	Boolean		,	"new-auth-on-407"	,	"When receiving a proxy authenticate challenge, generate a new challenge for this proxy.", "false" },
			config_item_end
		};
		mc->addChildrenValues(items);
		/* modify the default value for "enabled" */
		mc->get<ConfigBoolean>("enabled")->setDefault("false");

		mCountAsyncRetrieve=mc->createStat("count-async-retrieve",  "Number of asynchronous retrieves.");
		mCountSyncRetrieve=mc->createStat("count-sync-retrieve",  "Number of synchronous retrieves.");
		mCountPassFound=mc->createStat("count-password-found",   "Number of passwords found.");
		mCountPassNotFound=mc->createStat("count-password-not-found",   "Number of passwords not found.");
	}

	void onLoad(const GenericStruct * mc){
		list<string>::const_iterator it;
		mDomains=mc->get<ConfigStringList>("auth-domains")->read();
		for (it=mDomains.begin();it!=mDomains.end();++it){
			mAuthModules[*it] = auth_mod_create(NULL,
									AUTHTAG_METHOD("odbc"),
									AUTHTAG_REALM((*it).c_str()),
									AUTHTAG_OPAQUE("+GNywA=="),
									AUTHTAG_QOP("auth"),
									AUTHTAG_EXPIRES(NONCE_EXPIRES), // in seconds
									AUTHTAG_NEXT_EXPIRES(NEXT_NONCE_EXPIRES), // in seconds
									AUTHTAG_FORBIDDEN(1),
									TAG_END());
			auth_plugin_t *ap = AUTH_PLUGIN(mAuthModules[*it]);
			ap->mModule = this;
			LOGI("Found auth domain: %s",(*it).c_str());
			if (mAuthModules[*it] == NULL) {
				LOGE("Cannot create auth module odbc");
			}
		}

		mTrustedHosts=mc->get<ConfigStringList>("trusted-hosts")->read();
		dbUseHashedPasswords = mc->get<ConfigBoolean>("hashed-passwords")->read();
		mImmediateRetrievePassword = mc->get<ConfigBoolean>("immediate-retrieve-password")->read();
		mNewAuthOn407 = mc->get<ConfigBoolean>("new-auth-on-407")->read();
	}

	auth_mod_t *findAuthModule(const char *name) {
		auto it = mAuthModules.find(name);
		if (it == mAuthModules.end()) it=mAuthModules.find("*");
		if (it == mAuthModules.end()) {
			return NULL;
		}
		return it->second;
	}

	void onRequest(shared_ptr<RequestSipEvent> &ev) {
		const shared_ptr<MsgSip> &ms = ev->getMsgSip();
		sip_t *sip = ms->getSip();

		// Do it first to make sure no transaction is created which
		// would send an unappropriate 100 trying response.
		if (sip->sip_request->rq_method == sip_method_ack) {
			LOGD("ACK are never challenged");
			return;
		}

		// First check for trusted host
		sip_via_t *via=sip->sip_via;
		list<string>::const_iterator trustedHostsIt=mTrustedHosts.begin();
		const char *receivedHost=!empty(via->v_received) ? via->v_received : via->v_host;
		for (;trustedHostsIt != mTrustedHosts.end(); ++trustedHostsIt) {
			if (*trustedHostsIt == receivedHost) {
				LOGD("Allowing message from trusted host %s", receivedHost);
				return;
			}
		}

		// Then check for auth module for this domain
		auth_mod_t *am=findAuthModule(sip->sip_from->a_url[0].url_host);
		if (am==NULL) {
			LOGI("unknown domain [%s]",sip->sip_from->a_url[0].url_host);
			ev->reply(ms, SIP_488_NOT_ACCEPTABLE,
					SIPTAG_CONTACT(sip->sip_contact),
					SIPTAG_SERVER_STR(getAgent()->getServerString()),
					TAG_END());
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
		as->as_realm = sip->sip_from->a_url[0].url_host;
		as->as_user_uri = sip->sip_from->a_url;
		as->as_display = sip->sip_from->a_display;
		if (sip->sip_payload)
		    as->as_body = sip->sip_payload->pl_data,
		as->as_bodylen = sip->sip_payload->pl_len;

		AuthenticationListener *listener = new AuthenticationListener(getAgent(), ev, dbUseHashedPasswords);
		listener->mImmediateRetrievePass = mImmediateRetrievePassword;
		as->as_magic=listener;


		// Attention: the auth_mod_verify method should not send by itself any message but
		// return after having set the as status and phrase.
		// Another point in asynchronous mode is that the asynchronous callbacks MUST be called
		// AFTER the nta_msg_treply bellow. Otherwise the as would be already destroyed.
		if(sip->sip_request->rq_method == sip_method_register) {
			auth_mod_verify(am, as, sip->sip_authorization,&mRegistrarChallenger);
		} else {
			auth_mod_verify(am, as, sip->sip_proxy_authorization,&mProxyChallenger);
		}
	}
	void onResponse(shared_ptr<ResponseSipEvent> &ev) {
		if (!mNewAuthOn407) return; /*nop*/

		shared_ptr<OutgoingTransaction> transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
		if (transaction == NULL) return;

		shared_ptr<string> proxyRealm = transaction->getProperty<string>("this_proxy_realm");
		if (proxyRealm == NULL) return;

		sip_t *sip=ev->getMsgSip()->getSip();
		if (sip->sip_status->st_status == 407 && sip->sip_proxy_authenticate) {
			auth_status_t *as = auth_status_new(ev->getMsgSip()->getHome());
			as->as_realm = proxyRealm.get()->c_str();
			as->as_user_uri = sip->sip_from->a_url;
			auth_mod_t *am=findAuthModule(as->as_realm);
			if (am) {
				auth_challenge_digest(am, as, &mProxyChallenger);
				mNonceStore.insert(as->as_response);
				msg_header_insert(ev->getMsgSip()->getMsg(), (msg_pub_t*) sip,  (msg_header_t*) as->as_response);
			} else {
				LOGD("Authentication module for %s not found", as->as_realm);
			}
		} else {
			LOGD("not handled newauthon401");
		}
	};

	void onIdle() {
		mNonceStore.cleanExpired();
	}
};

ModuleInfo<Authentication> Authentication::sInfo("Authentication",
	"The authentication module challenges SIP requests according to a user/password database.",
	ModuleInfoBase::ModuleOid::Authentication);


Authentication::AuthenticationListener::AuthenticationListener(Agent *ag, shared_ptr<RequestSipEvent> ev, bool hashedPasswords):
		mAgent(ag),mEv(ev),mHashedPass(hashedPasswords),mAm(NULL),mAs(NULL),mAch(NULL) {
	memset(&mAr, '\0', sizeof(mAr)), mAr.ar_size=sizeof(mAr);
}

void Authentication::AuthenticationListener::setData(auth_mod_t *am, auth_status_t *as,  auth_challenger_t const *ach){
	this->mAm=am;
	this->mAs=as;
	this->mAch=ach;
}

/**
 * return true if the event is terminated
 */
bool Authentication::AuthenticationListener::sendReply(){
	const shared_ptr<MsgSip> &ms = mEv->getMsgSip();
	sip_t *sip = ms->getSip();
	if (mAs->as_status) {
		mEv->reply(ms, mAs->as_status,mAs->as_phrase,
				SIPTAG_CONTACT(sip->sip_contact),
				SIPTAG_HEADER((const sip_header_t*)mAs->as_info),
				SIPTAG_HEADER((const sip_header_t*)mAs->as_response),
				SIPTAG_SERVER_STR(mAgent->getServerString()),
				TAG_END());
		return true;
	}else{
		// Success
		if (sip->sip_request->rq_method == sip_method_register){
			msg_auth_t *au=ModuleToolbox::findAuthorizationForRealm(ms->getHome(), sip->sip_authorization, mAs->as_realm);
			if (au) msg_header_remove(ms->getMsg(), (msg_pub_t*)sip, (msg_header_t *)au);
		} else {
			msg_auth_t *au=ModuleToolbox::findAuthorizationForRealm(ms->getHome(), sip->sip_proxy_authorization, mAs->as_realm);
			if (au) msg_header_remove(ms->getMsg(), (msg_pub_t*)sip, (msg_header_t *)au);
		}
		return false;
	}
}

/**
 * NULL if passwd not found.
 */
void Authentication::AuthenticationListener::checkPassword(const char* passwd) {
	char const *a1;
	auth_hexmd5_t a1buf, response;

	if (passwd) {
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

	auth_digest_response(&mAr, response, a1,
			mAs->as_method, mAs->as_body, mAs->as_bodylen);

	if (!passwd || strcmp(response, mAr.ar_response)) {

		if (mAm->am_forbidden) {
			mAs->as_status = 403, mAs->as_phrase = "Forbidden";
			mAs->as_response = NULL;
			mAs->as_blacklist = mAm->am_blacklist;
		}
		else {
			auth_challenge_digest(mAm, mAs, mAch);
			getModule()->mNonceStore.insert(mAs->as_response);
			mAs->as_blacklist = mAm->am_blacklist;
		}
		if (passwd) {
			LOGD("auth_method_digest: password %s did not match", passwd);
		} else {
			LOGD("auth_method_digest: no password");
		}

		return;
	}

	//assert(apw);
	mAs->as_user = mAr.ar_username;
	mAs->as_anonymous = false;

	if (mAm->am_nextnonce || mAm->am_mutual)
		auth_info_digest(mAm, mAs, mAch);

	if (mAm->am_challenge)
		auth_challenge_digest(mAm, mAs, mAch);

	LOGD("auth_method_digest: successful authentication");

	mAs->as_status = 0;	/* Successful authentication! */
	mAs->as_phrase = "";
}


void Authentication::AuthenticationListener::onAsynchronousResponse(AuthDbResult res, const char *password) {
	switch (res) {
	case PASSWORD_FOUND:
	case PASSWORD_NOT_FOUND:
		checkPassword(password);
		if (!sendReply()) {
			// The event is not terminated
			mAgent->injectRequestEvent(mEv);
		}
		break;
	default:
		LOGE("unhandled asynchronous response %u", res);
		// error
	case AUTH_ERROR:
		onError();
		break;
	}
	delete this;
}

// Called when starting asynchronous retrieving of password
void Authentication::AuthenticationListener::switchToAsynchronousMode() {
	// Send pending message, needed data will be kept as long
	// as SipEvent is held in the listener.
	mEv->suspendProcessing();
}

void Authentication::AuthenticationListener::onError() {
	if (!mAs->as_status) {
		mAs->as_status = 500, mAs->as_phrase = "Internal error";
		mAs->as_response = NULL;
	}

	sendReply();
}







#define PA "Authorization missing "

/** Verify digest authentication */
void Authentication::flexisip_auth_check_digest(auth_mod_t *am,
		auth_status_t *as,
		auth_response_t *ar,
		auth_challenger_t const *ach) {

	shared_ptr<AuthenticationListener> listener((AuthenticationListener*) as->as_magic);

	if (am == NULL || as == NULL || ar == NULL || ach == NULL) {
		if (as) {
			as->as_status = 500, as->as_phrase = "Internal Server Error";
			as->as_response = NULL;
		}
		listener->sendReply();
		return;
	}

	char const *phrase = "Bad authorization ";
	if ((!ar->ar_username && (phrase = PA "username")) ||
			(!ar->ar_nonce && (phrase = PA "nonce")) ||
			(!ar->ar_nc && (phrase = PA "nonce count")) ||
			(!ar->ar_uri && (phrase = PA "URI")) ||
			(!ar->ar_response && (phrase = PA "response")) ||
			/* (!ar->ar_opaque && (phrase = PA "opaque")) || */
			/* Check for qop */
			(ar->ar_qop &&
					((ar->ar_auth &&
							!strcasecmp(ar->ar_qop, "auth") &&
							!strcasecmp(ar->ar_qop, "\"auth\"")) ||
							(ar->ar_auth_int &&
									!strcasecmp(ar->ar_qop, "auth-int") &&
									!strcasecmp(ar->ar_qop, "\"auth-int\"")))
									&& (phrase = PA "has invalid qop"))) {
		//assert(phrase);
		LOGD("auth_method_digest: 400 %s", phrase);
		as->as_status = 400, as->as_phrase = phrase;
		as->as_response = NULL;
		listener->sendReply();
		return;
	}

	if (!ar->ar_username || !as->as_user_uri->url_user || !ar->ar_realm || !as->as_user_uri->url_host) {
		as->as_status = 403, as->as_phrase = "Authentication info missing";
		LOGD("from and authentication usernames [%s/%s] or from and authentication hosts [%s/%s] empty",
				ar->ar_username, as->as_user_uri->url_user,
				ar->ar_realm, as->as_user_uri->url_host);
		as->as_response = NULL;
		listener->sendReply();
		return;
	}

	Authentication *module=listener->getModule();
	msg_time_t now = msg_now();
	if (as->as_nonce_issued == 0 /* Already validated nonce */ &&
			auth_validate_digest_nonce(am, as, ar,  now) < 0) {
		as->as_blacklist = am->am_blacklist;
		auth_challenge_digest(am, as, ach);
		module->mNonceStore.insert(as->as_response);
		listener->sendReply();
		return;
	}

	if (as->as_stale) {
		auth_challenge_digest(am, as, ach);
		module->mNonceStore.insert(as->as_response);
		listener->sendReply();
		return;
	}

	int pnc=module->mNonceStore.getNc(ar->ar_nonce);
	int nnc = (int) strtoul(ar->ar_nc, NULL, 10);
	if (pnc == -1 || pnc >= nnc) {
		LOGE("Bad nonce count %d -> %d for %s", pnc, nnc, ar->ar_nonce);
		as->as_blacklist = am->am_blacklist;
		auth_challenge_digest(am, as, ach);
		module->mNonceStore.insert(as->as_response);
		listener->sendReply();
		return;
	} else {
		module->mNonceStore.updateNc(ar->ar_nonce, nnc);
	}

	// Retrieve password. The result may be either synchronous OR asynchronous,
	// on a case by case basis.
	string foundPassword;
	AuthDbResult res=AuthDb::get()->password(listener->getRoot(), as->as_user_uri, ar->ar_username, foundPassword, listener);
	switch (res) {
		case PENDING:
			// The password couldn't be retrieved synchronously
			// It will be retrieved asynchronously and the listener
			// will be called with it.
			++*module->mCountAsyncRetrieve;
			LOGD("authentication PENDING for %s", ar->ar_username);
			break;
		case PASSWORD_FOUND:
			++*module->mCountSyncRetrieve;
			listener->checkPassword(foundPassword.c_str());
			listener->sendReply();
			break;
		case PASSWORD_NOT_FOUND:
			++*module->mCountSyncRetrieve;
			listener->checkPassword(NULL);
			listener->sendReply();
			break;
		case AUTH_ERROR:
			listener->onError();
			// on error deletes the listener
			break;
	}
}


/** Authenticate a request with @b Digest authentication scheme.
 */
void Authentication::flexisip_auth_method_digest(auth_mod_t *am,
		auth_status_t *as,
		msg_auth_t *au,
		auth_challenger_t const *ach)
{
	AuthenticationListener *listener=(AuthenticationListener*) as->as_magic;
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
		delete listener;
		return;
	}

	if (au) {
		LOGD("Searching for auth digest response for this proxy");
		msg_auth_t *matched_au=ModuleToolbox::findAuthorizationForRealm(as->as_home, au, as->as_realm);
		if (matched_au) au=matched_au;
		auth_digest_response_get(as->as_home, &listener->mAr, au->au_params);
		LOGD("Using auth digest response for realm %s", listener->mAr.ar_realm);
		as->as_match = (msg_header_t *)au;
		flexisip_auth_check_digest(am, as, &listener->mAr, ach);
	}
	else {
		/* There was no realm or credentials, send challenge */
		LOGD("%s: no credentials matched realm or no realm", __func__);
		auth_challenge_digest(am, as, ach);
		listener->getModule()->mNonceStore.insert(as->as_response);

		// Retrieve the password in the hope it will be in cache when the remote UAC
		// sends back its request; this time with the expected authentication credentials.
		if (listener->mImmediateRetrievePass) {
			LOGD("Searching for %s password to have it when the authenticated request comes", as->as_user_uri->url_user);
			string foundPassword;
			AuthDb::get()->password(listener->getRoot(), as->as_user_uri, as->as_user_uri->url_user, foundPassword, shared_ptr<AuthDbListener>());
		}
		listener->sendReply();
		delete listener;
		return;
	}
}
