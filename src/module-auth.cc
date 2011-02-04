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
#include "sofia-sip/auth_module.h"
#include "sofia-sip/sip_status.h"
#include "sofia-sip/msg_addr.h"
#include "sofia-sip/auth_plugin.h"
#include "sofia-sip/su_tagarg.h"

#include "auth-odbc.hh"

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
	bool databaseUseHashedPasswords;

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
		delete mOdbcAuthScheme;
	}

	virtual void onDeclare(ConfigStruct * module_config){
		ConfigItemDescriptor items[]={
			{	StringList	,	"auth-domains"	, 	"List of whitespace separated domain names to challenge. Others are denied.",	""	},
			{	String		,	"datasource"		,	"Please document this.",		""	},
			{	String		,	"request"				,	"The sql request to execute to obtain the password.",		""	},
			{	Integer		,	"max-id-length"	,	"Please document this.",	""	},
			{	Integer		,	"max-password-length"	,	"Please document this",	""	},
			{	Boolean	,	"hashed-passwords"	,	"Please document this.", "false" },
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


		string none = "none";
		string dsn = module_config->get<ConfigString>("datasource")->read();
		if (dsn == none) LOGF("Authentication is activated but no datasource found");
		LOGD("Datasource found: %s", dsn.c_str());

		string request = module_config->get<ConfigString>("request")->read();
		if (request == none) LOGF("Authentication is activated but no request found");
		LOGD("request found: %s", request.c_str());

		int maxIdLength = module_config->get<ConfigInt>("max-id-length")->read();
		if (maxIdLength == 0) LOGF("Authentication is activated but no max_id_length found");
		LOGD("maxIdLength found: %i", maxIdLength);

		int maxPassLength = module_config->get<ConfigInt>("max-password-length")->read();
		if (maxPassLength == 0) LOGF("Authentication is activated but no max_password_length found");
		LOGD("maxPassLength found: %i", maxPassLength);


		OdbcConnector *odbc = OdbcConnector::getInstance();
		if (odbc->connect(dsn, request, maxIdLength, maxPassLength)) {
			LOGD("Connection OK");
		} else {
			LOGE("Unable to connect to odbc database");
		}

		databaseUseHashedPasswords = module_config->get<ConfigBoolean>("hashed-passwords")->read();
	}

	void onRequest(SipEvent *ev) {
		sip_t *sip=ev->mSip;
		map<string,auth_mod_t *>::iterator lAuthModuleIt;
		// first check for auth module for this domain
		lAuthModuleIt = mAuthModules.find(sip->sip_from->a_url[0].url_host);
		if (lAuthModuleIt == mAuthModules.end()) {
			LOGI("unknown domain [%s]",sip->sip_from->a_url[0].url_host);
			nta_msg_treply(getAgent()->getSofiaAgent (),ev->mMsg,SIP_488_NOT_ACCEPTABLE,
									               SIPTAG_CONTACT(sip->sip_contact),
			             							SIPTAG_SERVER_STR(getAgent()->getServerString()),
									               TAG_END());
			ev->stopProcessing();
			return;
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

		 if(sip->sip_request->rq_method == sip_method_register) {
			 auth_mod_verify((*lAuthModuleIt).second, as, sip->sip_authorization,&mRegistrarChallenger);
		 } else {
			 auth_mod_verify((*lAuthModuleIt).second, as, sip->sip_proxy_authorization,&mProxyChallenger);
		 }
		 if (as->as_status) {
			 nta_msg_treply(getAgent()->getSofiaAgent (),ev->mMsg,as->as_status,as->as_phrase,
							               	   	   	   	   	   SIPTAG_CONTACT(sip->sip_contact),
							               	   	   	   	   	   SIPTAG_HEADER((const sip_header_t*)as->as_info),
							               	   	   	   	   	   SIPTAG_HEADER((const sip_header_t*)as->as_response),
			                									SIPTAG_SERVER_STR(getAgent()->getServerString()),
							               	   	   	   	   	   TAG_END());
				ev->stopProcessing();
				return;
	  	 }
		 return;

	}
	void onResponse(SipEvent *ev) {/*nop*/};

};

ModuleInfo<Authentication> Authentication::sInfo("Authentication",
	"The authentication module challenges SIP requests according to a user/password database.");





static const char* passwordRetrievingFallback(auth_status_t *as, const string &id) {
	if (!OdbcConnector::getInstance()->reconnect()) {
		LOGE("Authentication: failed to reconnect while searching for user %s", id.c_str());
		if (OdbcConnector::getInstance()->cachedPasswords.count(id) > 0) {
			LOGW("Using cached password found for user %s", id.c_str());
			return OdbcConnector::getInstance()->cachedPasswords[id].c_str();
		}
	} else {
		LOGD("Odbc reconnection succeeded");
		try {
			return OdbcConnector::getInstance()->password(id).c_str();
		} catch (int e) {
			LOGE("Authentication: error '%i' while retrieving user %s", e, id.c_str());
		}
	}

	as->as_status = 500, as->as_phrase = "Internal error";
	as->as_response = NULL;
	return NULL;
}


/**************************************************
 * code derivated from sofia sip auth_module.c begin
 */


/** Verify digest authentication */
void Authentication::flexisip_auth_check_digest(auth_mod_t *am,
		auth_status_t *as,
		auth_response_t *ar,
		auth_challenger_t const *ach) {

	if (am == NULL || as == NULL || ar == NULL || ach == NULL) {
		if (as) {
			as->as_status = 500, as->as_phrase = "Internal Server Error";
			as->as_response = NULL;
		}
		return;
	}


#define PA "Authorization missing "

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
		LOGD("auth_method_digest: 400 %s\n", phrase);
		as->as_status = 400, as->as_phrase = phrase;
		as->as_response = NULL;
		return;
	}

	if (strcmp(ar->ar_username, as->as_user_uri->url_user) || strcmp(ar->ar_realm, as->as_user_uri->url_host)) {
		as->as_status = 403, as->as_phrase = "from and authentication data mismatch";
		LOGD("from and authentication usernames [%s/%s] or from and authentication hosts [%s/%s] mismatch",
				ar->ar_username, as->as_user_uri->url_user,
				ar->ar_realm, as->as_user_uri->url_host);
		as->as_response = NULL;
		return;
	}

	msg_time_t now = msg_now();
	if (as->as_nonce_issued == 0 /* Already validated nonce */ &&
			auth_validate_digest_nonce(am, as, ar,  now) < 0) {
		as->as_blacklist = am->am_blacklist;
		auth_challenge_digest(am, as, ach);
		return;
	}

	if (as->as_stale) {
		auth_challenge_digest(am, as, ach);
		return;
	}

	const char* passwd = NULL;
	const string id = ar->ar_username;
	//LOGD("Retrieving password of user %s", id.c_str());
	try {
		passwd = OdbcConnector::getInstance()->password(id).c_str();
	} catch (int error) {
		switch (error) {
		case OdbcConnector::ERROR_PASSWORD_NOT_FOUND:
			LOGD("Authentication: password not found for username %s", id.c_str());
			break;
		case OdbcConnector::ERROR_ID_TOO_LONG:
			LOGD("Authentication: username '%s' too long %i", id.c_str(), id.length());
			break;
		case OdbcConnector::ERROR_LINK_FAILURE:
			LOGW("Odbc link failed ; trying reconnection");
			if ((passwd = passwordRetrievingFallback(as, id)) == NULL) return;
			break;
		case OdbcConnector::ERROR_NOT_CONNECTED:
			LOGW("Odbc not connected; trying reconnection");
			if ((passwd = passwordRetrievingFallback(as, id)) == NULL) return;
			break;
		default:
			if ((passwd = passwordRetrievingFallback(as, id)) == NULL) return;
			break;
		}
	}

	char const *a1;
	auth_hexmd5_t a1buf, response;

	if (passwd) {
		auth_plugin_t *ap = AUTH_PLUGIN(am);
		if (ap->mModule->databaseUseHashedPasswords) {
			strncpy(a1buf, passwd, 33); // remove trailing NULL character
			a1 = a1buf;
		} else {
			auth_digest_a1(ar, a1buf, passwd), a1 = a1buf;
		}
	} else {
		auth_digest_a1(ar, a1buf, "xyzzy"), a1 = a1buf;
	}


	if (ar->ar_md5sess)
		auth_digest_a1sess(ar, a1buf, a1), a1 = a1buf;

	auth_digest_response(ar, response, a1,
			as->as_method, as->as_body, as->as_bodylen);

	if (!passwd || strcmp(response, ar->ar_response)) {

		if (am->am_forbidden) {
			as->as_status = 403, as->as_phrase = "Forbidden";
			as->as_response = NULL;
			as->as_blacklist = am->am_blacklist;
		}
		else {
			auth_challenge_digest(am, as, ach);
			as->as_blacklist = am->am_blacklist;
		}
		LOGD("auth_method_digest: response did not match\n");

		return;
	}

	//assert(apw);
	as->as_user = ar->ar_username;
	as->as_anonymous = false;

	if (am->am_nextnonce || am->am_mutual)
		auth_info_digest(am, as, ach);

	if (am->am_challenge)
		auth_challenge_digest(am, as, ach);

	LOGD("auth_method_digest: successful authentication\n");

	as->as_status = 0;	/* Successful authentication! */
	as->as_phrase = "";
}

/** Authenticate a request with @b Digest authentication scheme.
 */
void Authentication::flexisip_auth_method_digest(auth_mod_t *am,
			auth_status_t *as,
			msg_auth_t *au,
			auth_challenger_t const *ach)
{
  as->as_allow = as->as_allow || auth_allow_check(am, as) == 0;

  if (as->as_realm)
    au = auth_digest_credentials(au, as->as_realm, am->am_opaque);
  else
    au = NULL;

  if (as->as_allow) {
    LOGD("%s: allow unauthenticated %s\n", __func__, as->as_method);
    as->as_status = 0, as->as_phrase = NULL;
    as->as_match = (msg_header_t *)au;
    return;
  }

  if (au) {
    auth_response_t ar[1] = {{ sizeof(ar) }};
    auth_digest_response_get(as->as_home, ar, au->au_params);
    as->as_match = (msg_header_t *)au;
    flexisip_auth_check_digest(am, as, ar, ach);
  }
  else {
    /* There was no matching credentials, send challenge */
    LOGD("%s: no credentials matched\n", __func__);
    auth_challenge_digest(am, as, ach);
  }
}


/*
 * code derivated from sofia sip begin end
 ******************************************/

