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
#include "etchosts.hh"

class ForwardModule : public Module {
	public:
		ForwardModule(Agent *ag);
		virtual void onRequest(SipEvent *ev);
		virtual void onResponse(SipEvent *ev);
	private:
		static ModuleInfo<ForwardModule> sInfo;
};

ModuleInfo<ForwardModule> ForwardModule::sInfo("Forward");


ForwardModule::ForwardModule(Agent *ag) : Module(ag){
}

void ForwardModule::onRequest(SipEvent *ev){
	size_t msg_size;
	char *buf;
	url_t* dest=NULL;
	sip_t *sip=ev->mSip;
	msg_t *msg=ev->mMsg;

	
	switch(sip->sip_request->rq_method){
		case sip_method_invite:
			LOGD("This is an invite");
			break;
		case sip_method_register:
			LOGD("This is a register");
			//rewrite the request uri to the domain
			//this assume the domain is also the proxy
			sip->sip_request->rq_url->url_host=sip->sip_to->a_url->url_host;
			sip->sip_request->rq_url->url_port=sip->sip_to->a_url->url_port;
		case sip_method_ack:
		default:
			break;
	}
	dest=sip->sip_request->rq_url;
	// removes top route header if it maches us
	if (sip->sip_route!=NULL){
		if (getAgent()->isUs(sip->sip_route->r_url)){
			sip_route_remove(msg,sip);
		}
		if (sip->sip_route!=NULL){
			/*forward to this route*/
			dest=sip->sip_route->r_url;
		}
	}


	char contact_route_param[64];
	// now need to check if request uri has special param inserted by contact-route-inserter module
	if (url_param(dest->url_params,getAgent()->getUniqueId().c_str(),contact_route_param,sizeof(contact_route_param))) {
		//first remove param
		dest->url_params = url_strip_param_string(su_strdup(ev->getHome(),dest->url_params),getAgent()->getUniqueId().c_str());
		//test and remove maddr param
		if (url_has_param(dest,"maddr")) {
			dest->url_params = url_strip_param_string(su_strdup(ev->getHome(),dest->url_params),"maddr");
		}
		//second change dest to
		char* hostport_separator = strchr(contact_route_param, ':');
		dest->url_host=su_strndup(ev->getHome(), contact_route_param, (hostport_separator-contact_route_param) );
		dest->url_port=su_strdup(ev->getHome(), hostport_separator+1);
	}


	std::string ip;
	if (EtcHostsResolver::get()->resolve(dest->url_host,&ip)){
		LOGD("Found %s in /etc/hosts",dest->url_host);
		dest->url_host=ip.c_str();
	}


	if (!getAgent()->isUs(dest)) {
		buf=msg_as_string(ev->getHome(), msg, NULL, 0,&msg_size);
		LOGD("About to forward request to %s:\n%s",url_as_string(ev->getHome(),dest),buf);
		nta_msg_tsend (getSofiaAgent(),msg,(url_string_t*)dest,TAG_END());
	}else{
		LOGD("This message has final destination this proxy, discarded...");
		nta_msg_discard(getSofiaAgent(),msg);
	}
}


void ForwardModule::onResponse(SipEvent *ev){
	su_home_t home;
	char *buf;
	size_t msg_size;
	
	su_home_init(&home);

	buf=msg_as_string(&home, ev->mMsg, NULL, 0,&msg_size);
	LOGD("About to forward response:\n%s",buf);
	
	nta_msg_tsend(getSofiaAgent(),ev->mMsg,(url_string_t*)NULL,TAG_END());

	su_home_deinit(&home);
}
