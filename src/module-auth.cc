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
		for(map<string,auth_mod_t *>::iterator it = mAuthModules.begin(); it != mAuthModules.end(); it = mAuthModules.erase(it)) {
			auth_mod_destroy(it->second);
		}

		delete mOdbcAuthScheme;
	}

	virtual void onDeclare(ConfigStruct * module_config){
		ConfigItemDescriptor items[]={
			{	StringList	,	"auth-domains"	, 	"List of whitespace separated domain names to challenge. Others are denied.",	""	},
			{	StringList	,	"trusted-hosts"	, 	"List of whitespace separated IP which will not be challenged.",	""	},
			{	String		,	"db-implementation"		,	"backend implementation [odbc, redis].",		"odbc"	},
			{	String		,	"datasource"		,	"Odbc connection string to use for connecting to database. ex: 'DSN=myodbc3;' where 'myodbc3' is the datasource name.",		""	},
			{	String		,	"request"				,	"Odbc SQL request to execute to obtain the password. Named parameters are :id, :domain and :authid.'",
					"select password from accounts where id = :id and domain = :domain and authid=:authid"	},
			{	Integer		,	"max-id-length"	,	"Maximum length of the login column in database.",	"100"	},
			{	Integer		,	"max-password-length"	,	"Maximum length of the password column in database",	"100"	},
			{	Boolean		,	"odbc-pooling"	,	"Use pooling in odbc",	"true"	},
			{	Integer		,	"cache-expire"	,	"Duration of the validity of the credentials added to the cache in seconds.",	"1800"	},
			{	Boolean	,	"hashed-passwords"	,	"True if the passwords retrieved from the database are already SIP hashed (HA1).", "false" },
			config_item_end
		};
		module_config->addChildrenValues(items);
		/* modify the default value for "enabled" */
		module_config->get<ConfigBoolean>("enabled")->setDefault("false");
	}

	void onLoad(Agent *agent, const ConfigStruct * module_config){
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
	}

	void onRequest(std::shared_ptr<SipEvent> &ev) {
		sip_t *sip=ev->mSip;
		map<string,auth_mod_t *>::iterator authModuleIt;
		// first check for auth module for this domain
		authModuleIt = mAuthModules.find(sip->sip_from->a_url[0].url_host);
		if (authModuleIt == mAuthModules.end()) {
			LOGI("unknown domain [%s]",sip->sip_from->a_url[0].url_host);
			nta_msg_treply(getAgent()->getSofiaAgent (),ev->mMsg,SIP_488_NOT_ACCEPTABLE,
					SIPTAG_CONTACT(sip->sip_contact),
					SIPTAG_SERVER_STR(getAgent()->getServerString()),
					TAG_END());
			ev->stopProcessing();
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
	    as->as_source = msg_addrinfo(ev->mMsg);
		as->as_realm = sip->sip_from->a_url[0].url_host;
		as->as_user_uri = sip->sip_from->a_url;
		as->as_display = sip->sip_from->a_display;
		if (sip->sip_payload)
		    as->as_body = sip->sip_payload->pl_data,
		as->as_bodylen = sip->sip_payload->pl_len;

		AuthDbListener *listener = new AuthDbListener(getAgent(), ev, dbUseHashedPasswords);
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


AuthDbListener::AuthDbListener(Agent *ag, std::shared_ptr<SipEvent> ev, bool hashedPasswords):
		mAgent(ag),mEv(ev),mHashedPass(hashedPasswords),mAm(NULL),mAs(NULL),mAch(NULL) {
	memset(&mAr, '\0', sizeof(mAr)), mAr.ar_size=sizeof(mAr);
}
void AuthDbListener::setData(auth_mod_t *am, auth_status_t *as,  auth_challenger_t const *ach){
	this->mAm=am;
	this->mAs=as;
	this->mAch=ach;
}

void AuthDbListener::sendReplyAndDestroy(){
	sendReply();
	delete(this);
}
void AuthDbListener::sendReply(){
	sip_t *sip=mEv->mSip;
	if (mAs->as_status) {
		nta_msg_treply(mAgent->getSofiaAgent(),mEv->mMsg,mAs->as_status,mAs->as_phrase,
				SIPTAG_CONTACT(sip->sip_contact),
				SIPTAG_HEADER((const sip_header_t*)mAs->as_info),
				SIPTAG_HEADER((const sip_header_t*)mAs->as_response),
				SIPTAG_SERVER_STR(mAgent->getServerString()),
				TAG_END());
		mEv->stopProcessing();
	}else{
		// Success
		if (sip->sip_request->rq_method == sip_method_register){
			sip_header_remove(mEv->mMsg,sip,(sip_header_t*)sip->sip_authorization);
		} else {
			sip_header_remove(mEv->mMsg,sip, (sip_header_t*)sip->sip_proxy_authorization);
		}
	}
}

void AuthDbListener::checkFoundPassword(const string &password) {
	const char* passwd = password.c_str();
	const string id = mAr.ar_username;
	//LOGD("Retrieving password of user %s", id.c_str());

	char const *a1;
	auth_hexmd5_t a1buf, response;

	if (passwd) {
		if (mHashedPass) {
			strncpy(a1buf, passwd, 33); // remove trailing NULL character
			a1 = a1buf;
		} else {
			auth_digest_a1(&mAr, a1buf, passwd), a1 = a1buf;
		}
	} else {
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
		LOGD("auth_method_digest: response did not match");

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

void AuthDbListener::onSynchronousPasswordFound(const string &password) {
	checkFoundPassword(password);
	sendReplyAndDestroy();
}

void AuthDbListener::onAsynchronousPasswordFound(const string &password) {
	checkFoundPassword(password);
	sendReply();
	mAgent->injectRequestEvent(mEv);
	delete this;
}

// Called when starting asynchronous retrieving of password
void AuthDbListener::passwordRetrievingPending() {
	// Send pending message, needed data will be kept as long
	// as SipEvent is held in the listener.
	mAs->as_status=100, mAs->as_phrase="Authentication pending";
	//as->as_callback=auth_callback; // should be set according to doc
	msg_ref_create(mEv->mMsg); // Avoid temporary reference to make the message destroyed.
	sendReply();
}

void AuthDbListener::onError() {
	if (!mAs->as_status) {
		mAs->as_status = 500, mAs->as_phrase = "Internal error";
		mAs->as_response = NULL;
	}

	sendReplyAndDestroy();
}







#define PA "Authorization missing "

/**************************************************
 * code derivated from sofia sip auth_module.c begin
 */


/** Verify digest authentication */
void Authentication::flexisip_auth_check_digest(auth_mod_t *am,
		auth_status_t *as,
		auth_response_t *ar,
		auth_challenger_t const *ach) {

	AuthDbListener *listener=(AuthDbListener*) as->as_magic;

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

	// Synchronous or asynchronous retrieving of password depending
	// on implementation and presence of valid credentials in the cache.
	string foundPassword;
	AuthDbResult res=AuthDb::get()->password(listener->getRoot(), as->as_user_uri, ar->ar_username, foundPassword, listener);
	switch (res) {
		case PENDING:
			listener->passwordRetrievingPending();
			break;
		case PASSWORD_FOUND:
			listener->onSynchronousPasswordFound(foundPassword);
			break;
		case AUTH_ERROR:
			listener->onError();
			break;
		default:
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
	AuthDbListener *listener=(AuthDbListener*) as->as_magic;
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

		// Asynchronously fetch the credentials so that they are present in the
		// cache when a request with credentials comes back from client.
		string foundPassword;
		AuthDb::get()->password(listener->getRoot(), as->as_user_uri, as->as_user_uri->url_user, foundPassword, NULL);
		listener->sendReplyAndDestroy();
	}
}


/*
 * code derivated from sofia sip begin end
 ******************************************/

