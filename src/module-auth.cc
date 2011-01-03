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
using namespace std;

class Authentication : public Module {

private:
	string mUsersDbFile;
	map<string,auth_mod_t *> mAuthModules;
	list<string> mDomains;
	static ModuleInfo<Authentication> sInfo;
	auth_challenger_t mRegistrarChallenger[1];
	auth_challenger_t mProxyChallenger[1];

public:
	Authentication(Agent *ag):Module(ag),mUsersDbFile(CONFIG_DIR "/userdb.conf"){

		mProxyChallenger[0].ach_status=407;/*SIP_407_PROXY_AUTH_REQUIRED*/
		mProxyChallenger[0].ach_phrase=sip_407_Proxy_auth_required;
		mProxyChallenger[0].ach_header=sip_proxy_authenticate_class;
		mProxyChallenger[0].ach_info=sip_proxy_authentication_info_class;

		mRegistrarChallenger[0].ach_status=401;/*SIP_401_UNAUTHORIZED*/
		mRegistrarChallenger[0].ach_phrase=sip_401_Unauthorized;
		mRegistrarChallenger[0].ach_header=sip_www_authenticate_class;
		mRegistrarChallenger[0].ach_info=sip_authentication_info_class;


	}

	void onLoad(Agent *agent, const ConfigArea & module_config){
		list<string>::const_iterator it;
		mDomains=module_config.get("auth_domains",list<string>());
		for (it=mDomains.begin();it!=mDomains.end();++it){
			mAuthModules[*it] = auth_mod_create(NULL,
									AUTHTAG_METHOD("Digest"),
									AUTHTAG_REALM((*it).c_str()),
									AUTHTAG_DB(mUsersDbFile.c_str()),
									AUTHTAG_OPAQUE("+GNywA=="),
									TAG_END());
			LOGD("Found auth domain: %s",(*it).c_str());
		}


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
									               TAG_END());
			ev->stopProcessing();
			return;
		}

		auth_status_t *as;
		as = auth_status_new(ev->getHome());
		as->as_method = sip->sip_request->rq_method_name;
	    as->as_source = msg_addrinfo(ev->mMsg);
		as->as_realm = "Realm";
		as->as_user_uri = sip->sip_from->a_url;
		as->as_display = sip->sip_from->a_display;
		if (sip->sip_payload)
		    as->as_body = sip->sip_payload->pl_data,
		as->as_bodylen = sip->sip_payload->pl_len;

		 if(sip->sip_request->rq_method == sip_method_register) {
			 auth_mod_verify((*lAuthModuleIt).second, as, sip->sip_authorization,mRegistrarChallenger);
		 } else {
			 auth_mod_verify((*lAuthModuleIt).second, as, sip->sip_proxy_authorization,mProxyChallenger);
		 }
		 if (as->as_status) {
				nta_msg_treply(getAgent()->getSofiaAgent (),ev->mMsg,as->as_status,as->as_phrase,
							               	   	   	   	   	   SIPTAG_CONTACT(sip->sip_contact),
							               	   	   	   	   	   TAG_END());
				ev->stopProcessing();
				return;
	  	 }
		 return;

	}
	void onResponse(SipEvent *ev) {/*nop*/};

};

ModuleInfo<Authentication> Authentication::sInfo("Authentication");
