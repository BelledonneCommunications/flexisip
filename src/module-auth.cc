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

#include "agent.hh"
#include <string>
#include <map>
#include <list>
#include <vector>
#include "sofia-sip/auth_module.h"
#include "sofia-sip/sip_status.h"
#include "sofia-sip/msg_addr.h"
#include "sofia-sip/auth_plugin.h"
#include "sofia-sip/su_tagarg.h"

#include "authdb.hh"

using namespace std;

const static char* countPasswordFound = "count-password-found";
const static char* countPasswordNotFound = "count-password-not-found";
const static char* countAsyncRetrieve = "count-async-retrieve";
const static char* countSyncRetrieve = "count-sync-retrieve";

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




class Authentication : public Module {
private:
	class AuthenticationListener : public AuthDbListener {
		Agent *mAgent;
		shared_ptr<SipEvent> mEv;
		bool mHashedPass;
		auth_mod_t *mAm;
		auth_status_t *mAs;
		auth_challenger_t const *mAch;
	public:
		bool mImmediateRetrievePass;
		auth_response_t mAr;
		AuthenticationListener(Agent *, shared_ptr<SipEvent>, bool);
		~AuthenticationListener(){};

		void setData(auth_mod_t *am, auth_status_t *as, auth_challenger_t const *ach);
		void checkPassword(const char *password);
		void onAsynchronousResponse(AuthDbResult ret, const char *password);
		void switchToAsynchronousMode();
		void onError();
		void sendReplyAndDestroy();
		bool sendReply();
		su_root_t *getRoot() {
			return mAgent->getRoot();
		}
		const Authentication *getModule() {
			return dynamic_cast<const Authentication *>(mEv->getCurrentModule());
		}
	};
private:
	map<string,auth_mod_t *> mAuthModules;
	list<string> mDomains;
	list<string> mTrustedHosts;
	static ModuleInfo<Authentication> sInfo;
	auth_challenger_t mRegistrarChallenger;
	auth_challenger_t mProxyChallenger;
	auth_scheme_t* mOdbcAuthScheme ;
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

	void static flexisip_auth_method_digest(auth_mod_t *am,
				auth_status_t *as, msg_auth_t *au, auth_challenger_t const *ach);
	void static flexisip_auth_check_digest(auth_mod_t *am,
		       auth_status_t *as, auth_response_t *ar, auth_challenger_t const *ach);

public:
	Authentication(Agent *ag):Module(ag){
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

	virtual void onDeclare(GenericStruct * module_config){
		ConfigItemDescriptor items[]={
			{	StringList	,	"auth-domains"	, 	"List of whitespace separated domain names to challenge. Others are denied.",	""	},
			{	StringList	,	"trusted-hosts"	, 	"List of whitespace separated IP which will not be challenged.",	""	},
			{	String		,	"db-implementation"		,	"Database backend implementation [odbc, file].",		"odbc"	},
			{	String		,	"datasource"		,	"Odbc connection string to use for connecting to database. " \
					"ex1: DSN=myodbc3; where 'myodbc3' is the datasource name. " \
					"ex2: DRIVER={MySQL};SERVER=localhost;DATABASE=dbname;USER=username;PASSWORD=passname;OPTION=3; for a DSN-less connection.",		""	},
			{	String		,	"request"				,	"Odbc SQL request to execute to obtain the password. Named parameters are :id, :domain and :authid.'",
					"select password from accounts where id = :id and domain = :domain and authid=:authid"	},
			{	Integer		,	"max-id-length"	,	"Maximum length of the login column in database.",	"100"	},
			{	Integer		,	"max-password-length"	,	"Maximum length of the password column in database",	"100"	},
			{	Boolean		,	"odbc-pooling"	,	"Use pooling in odbc",	"true"	},
			{	Integer		,	"odbc-display-timings-interval"	,	"Display timing statistics after this count of seconds",	"0"	},
			{	Integer		,	"odbc-display-timings-after-count"	,	"Display timing statistics once the number of samples reach this number.",	"0"	},
			{	Boolean		,	"odbc-asynchronous"	,	"Retrieve passwords asynchronously.",	"false"	},
			{	Integer		,	"cache-expire"	,	"Duration of the validity of the credentials added to the cache in seconds.",	"1800"	},
			{	Boolean		,	"immediate-retrieve-password"	,	"Retrieve password immediately so that it is cached when an authenticated request arrives.",	"true"},
			{	Boolean		,	"hashed-passwords"	,	"True if the passwords retrieved from the database are already SIP hashed (HA1=MD5(A1)=MD5(username:realm:password)).", "false" },
			config_item_end
		};
		module_config->addChildrenValues(items);
		/* modify the default value for "enabled" */
		module_config->get<ConfigBoolean>("enabled")->setDefault("false");


		StatItemDescriptor stats[] = {
				{	Counter64,	countPasswordFound, "Number of passwords found."},
				{	Counter64,	countPasswordNotFound, "Number of passwords not found."},
				{	Counter64,	countAsyncRetrieve, "Number of asynchronous retrieves."},
				{	Counter64,	countSyncRetrieve, "Number of synchronous retrieves."},
				stat_item_end };
		module_config->addChildrenValues(stats);
	}

	void onLoad(Agent *agent, const GenericStruct * module_config){
		list<string>::const_iterator it;
		mDomains=module_config->get<ConfigStringList>("auth-domains")->read();
		for (it=mDomains.begin();it!=mDomains.end();++it){
			mAuthModules[*it] = auth_mod_create(NULL,
									AUTHTAG_METHOD("odbc"),
									AUTHTAG_REALM((*it).c_str()),
									AUTHTAG_OPAQUE("+GNywA=="),
									AUTHTAG_FORBIDDEN(1),
									TAG_END());
			auth_plugin_t *ap = AUTH_PLUGIN(mAuthModules[*it]);
			ap->mModule = this;
			LOGI("Found auth domain: %s",(*it).c_str());
			if (mAuthModules[*it] == NULL) {
				LOGE("Cannot create auth module odbc");
			}
		}

		mTrustedHosts=module_config->get<ConfigStringList>("trusted-hosts")->read();
		dbUseHashedPasswords = module_config->get<ConfigBoolean>("hashed-passwords")->read();
		mImmediateRetrievePassword = module_config->get<ConfigBoolean>("immediate-retrieve-password")->read();
	}

	void onRequest(std::shared_ptr<SipEvent> &ev) {
		sip_t *sip=ev->getSip();
		map<string,auth_mod_t *>::iterator authModuleIt;
		// first check for auth module for this domain
		authModuleIt = mAuthModules.find(sip->sip_from->a_url[0].url_host);
		if (authModuleIt == mAuthModules.end()) {
			LOGI("unknown domain [%s]",sip->sip_from->a_url[0].url_host);
			nta_msg_treply(getAgent()->getSofiaAgent (),ev->getMsg(),SIP_488_NOT_ACCEPTABLE,
					SIPTAG_CONTACT(sip->sip_contact),
					SIPTAG_SERVER_STR(getAgent()->getServerString()),
					TAG_END());
			ev->terminateProcessing();
			return;
		}

		sip_via_t *via=sip->sip_via;
		list<string>::const_iterator trustedHostsIt=mTrustedHosts.begin();
		const char *receivedHost=!empty(via->v_received) ? via->v_received : via->v_host;
		for (;trustedHostsIt != mTrustedHosts.end(); ++trustedHostsIt) {
			if (*trustedHostsIt == receivedHost) {
				LOGD("Allowing message from trusted host %s", receivedHost);
				return;
			}
		}

		auth_status_t *as;
		as = auth_status_new(ev->getHome());
		as->as_method = sip->sip_request->rq_method_name;
	    as->as_source = msg_addrinfo(ev->getMsg());
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
			auth_mod_verify((*authModuleIt).second, as, sip->sip_authorization,&mRegistrarChallenger);
		} else {
			auth_mod_verify((*authModuleIt).second, as, sip->sip_proxy_authorization,&mProxyChallenger);
		}
	}
	void onResponse(std::shared_ptr<SipEvent> &ev) {/*nop*/};

};

ModuleInfo<Authentication> Authentication::sInfo("Authentication",
	"The authentication module challenges SIP requests according to a user/password database.");


Authentication::AuthenticationListener::AuthenticationListener(Agent *ag, std::shared_ptr<SipEvent> ev, bool hashedPasswords):
		mAgent(ag),mEv(ev),mHashedPass(hashedPasswords),mAm(NULL),mAs(NULL),mAch(NULL) {
	memset(&mAr, '\0', sizeof(mAr)), mAr.ar_size=sizeof(mAr);
}

void Authentication::AuthenticationListener::setData(auth_mod_t *am, auth_status_t *as,  auth_challenger_t const *ach){
	this->mAm=am;
	this->mAs=as;
	this->mAch=ach;
}

void Authentication::AuthenticationListener::sendReplyAndDestroy(){
	sendReply();
	delete(this);
}
/**
 * return true if the event is terminated
 */
bool Authentication::AuthenticationListener::sendReply(){
	sip_t *sip=mEv->getSip();
	if (mAs->as_status) {
		nta_msg_treply(mAgent->getSofiaAgent(),mEv->getMsg(),mAs->as_status,mAs->as_phrase,
				SIPTAG_CONTACT(sip->sip_contact),
				SIPTAG_HEADER((const sip_header_t*)mAs->as_info),
				SIPTAG_HEADER((const sip_header_t*)mAs->as_response),
				SIPTAG_SERVER_STR(mAgent->getServerString()),
				TAG_END());
		mEv->terminateProcessing();
		return true;
	}else{
		// Success
		if (sip->sip_request->rq_method == sip_method_register){
			sip_header_remove(mEv->getMsg(),sip,(sip_header_t*)sip->sip_authorization);
		} else {
			sip_header_remove(mEv->getMsg(),sip, (sip_header_t*)sip->sip_proxy_authorization);
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
		++mEv->getCurrentModule()->findStat(countPasswordFound);
		if (mHashedPass) {
			strncpy(a1buf, passwd, 33); // remove trailing NULL character
			a1 = a1buf;
		} else {
			auth_digest_a1(&mAr, a1buf, passwd), a1 = a1buf;
		}
	} else {
		++mEv->getCurrentModule()->findStat(countPasswordNotFound);
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
		delete this;
		break;
	default:
		LOGE("unhandled asynchronous response %u", res);
		// error
	case AUTH_ERROR:
		onError();
		break;
	}
}

// Called when starting asynchronous retrieving of password
void Authentication::AuthenticationListener::switchToAsynchronousMode() {
	// Send pending message, needed data will be kept as long
	// as SipEvent is held in the listener.
	mEv->suspendProcessing();
	LOGW("stateful asynchronous mode for AuthenticationListener not implemented");
}

void Authentication::AuthenticationListener::onError() {
	if (!mAs->as_status) {
		mAs->as_status = 500, mAs->as_phrase = "Internal error";
		mAs->as_response = NULL;
	}

	sendReplyAndDestroy();
}







#define PA "Authorization missing "

/** Verify digest authentication */
void Authentication::flexisip_auth_check_digest(auth_mod_t *am,
		auth_status_t *as,
		auth_response_t *ar,
		auth_challenger_t const *ach) {

	AuthenticationListener *listener=(AuthenticationListener*) as->as_magic;

	if (am == NULL || as == NULL || ar == NULL || ach == NULL) {
		if (as) {
			as->as_status = 500, as->as_phrase = "Internal Server Error";
			as->as_response = NULL;
		}
		listener->sendReplyAndDestroy();
		return;
	}

	char const *phrase = "Bad authorization";
	if ((!ar->ar_username && (phrase = PA "username")) ||
			(!ar->ar_nonce && (phrase = PA "nonce")) ||
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
		listener->sendReplyAndDestroy();
		return;
	}

	if (!ar->ar_username || !as->as_user_uri->url_user || !ar->ar_realm || !as->as_user_uri->url_host) {
		as->as_status = 403, as->as_phrase = "Authentication info missing";
		LOGD("from and authentication usernames [%s/%s] or from and authentication hosts [%s/%s] empty",
				ar->ar_username, as->as_user_uri->url_user,
				ar->ar_realm, as->as_user_uri->url_host);
		as->as_response = NULL;
		listener->sendReplyAndDestroy();
		return;
	}

	msg_time_t now = msg_now();
	if (as->as_nonce_issued == 0 /* Already validated nonce */ &&
			auth_validate_digest_nonce(am, as, ar,  now) < 0) {
		as->as_blacklist = am->am_blacklist;
		auth_challenge_digest(am, as, ach);
		listener->sendReplyAndDestroy();
		return;
	}

	if (as->as_stale) {
		auth_challenge_digest(am, as, ach);
		listener->sendReplyAndDestroy();
		return;
	}

	// Retrieve password. The result may be either synchronous OR asynchronous,
	// on a case by case basis.
	string foundPassword;
	AuthDbResult res=AuthDb::get()->password(listener->getRoot(), as->as_user_uri, ar->ar_username, foundPassword, listener);
	const Authentication *module=listener->getModule();
	switch (res) {
		case PENDING:
			// The password couldn't be retrieved synchronously
			// It will be retrieved asynchronously and the listener
			// will be called with it.
			++module->findStat(countAsyncRetrieve);
			LOGD("authentication PENDING for %s", ar->ar_username);
			break;
		case PASSWORD_FOUND:
			++module->findStat(countSyncRetrieve);
			listener->checkPassword(foundPassword.c_str());
			listener->sendReply();
			delete(listener);
			break;
		case PASSWORD_NOT_FOUND:
			++module->findStat(countSyncRetrieve);
			listener->checkPassword(NULL);
			listener->sendReply();
			delete(listener);
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
		auth_digest_response_get(as->as_home, &listener->mAr, au->au_params);
		as->as_match = (msg_header_t *)au;
		flexisip_auth_check_digest(am, as, &listener->mAr, ach);
	}
	else {
		/* There was no realm or credentials, send challenge */
		LOGD("%s: no credentials matched realm or no realm", __func__);
		auth_challenge_digest(am, as, ach);

		// Retrieve the password in the hope it will be in cache when the remote UAC
		// sends back its request; this time with the expected authentication credentials.
		if (listener->mImmediateRetrievePass) {
			LOGD("Searching for %s password to have it when the authenticated request comes", as->as_user_uri->url_user);
			string foundPassword;
			AuthDb::get()->password(listener->getRoot(), as->as_user_uri, as->as_user_uri->url_user, foundPassword, NULL);
		}
		listener->sendReplyAndDestroy();
	}
}
