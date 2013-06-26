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

using namespace ::std;

class ContactRouteInserter: public Module {
public:
	ContactRouteInserter(Agent *ag) :
		Module(ag) {

	}

	void onDeclare(GenericStruct *module_config) {
		ConfigItemDescriptor items[] = {
			{ Boolean, "masquerade-contacts-on-registers", "Masquerade register contacts with proxy address.", "true" },
			{ Boolean, "masquerade-contacts-for-invites", "Masquerade invite-related messages with proxy address.", "false" },
			{ Boolean, "insert-domain", "Masquerade register with from domain.", "false" },
			config_item_end
		};
		module_config->addChildrenValues(items);
	}

	void onLoad(const GenericStruct *mc) {
		mCtRtParamName = string("CtRt") + getAgent()->getUniqueId();
		mMasqueradeInvites = mc->get<ConfigBoolean>("masquerade-contacts-for-invites")->read();
		mMasqueradeRegisters = mc->get<ConfigBoolean>("masquerade-contacts-on-registers")->read();
		mInsertDomain =  mc->get<ConfigBoolean>("insert-domain")->read();
	}


	void onRequest(shared_ptr<RequestSipEvent> &ev) {
		const shared_ptr<MsgSip> &ms = ev->getMsgSip();
		sip_t *sip = ms->getSip();
		const sip_method_t rq_method=sip->sip_request->rq_method;

		if (mMasqueradeRegisters && rq_method== sip_method_register) {
			//rewrite the request uri to the domain
			//this assumes the domain is also the proxy
			sip->sip_request->rq_url->url_host = sip->sip_to->a_url->url_host;
			sip->sip_request->rq_url->url_port = sip->sip_to->a_url->url_port;
			LOGD("Masquerading contact");
			masqueradeContact(ev, mInsertDomain);
		} else if (mMasqueradeInvites && rq_method == sip_method_invite) {
			LOGD("Masquerading contact");
			masqueradeContact(ev);
		}

		if (rq_method != sip_method_register) {
			// check if request-uri contains a contact-route parameter,
			// so that we can route back to the client
			char ctrt[64];
			url_t *dest = sip->sip_request->rq_url;
			// now need to check if request uri has special param inserted
			// by contact-route-inserter module
			if (url_param(dest->url_params, mCtRtParamName.c_str(), ctrt, sizeof(ctrt))) {
				LOGD("Found a contact route parameter");
				rewriteReqUrlWithCtrt(dest, ctrt, ms->getHome());
			} else {
				LOGD("No countact route parameter found");
			}
		}
	}
	virtual void onResponse(shared_ptr<ResponseSipEvent> &ev) {
		const shared_ptr<MsgSip> &ms = ev->getMsgSip();
		sip_t *sip = ms->getSip();
		if (mMasqueradeInvites && (sip->sip_cseq->cs_method == sip_method_invite || sip->sip_cseq->cs_method == sip_method_subscribe)) {
			masqueradeContact(ev);
		}
	}


private:
	/*add a parameter like "CtRt15.128.128.2=tcp:201.45.118.16:50025" in the contact, so that we know where is the client
	 when we later have to route an INVITE to him */
	void masqueradeContact(shared_ptr<SipEvent> ev, bool insertDomain = false) {
		const shared_ptr<MsgSip> &ms = ev->getMsgSip();
		sip_t *sip = ms->getSip();
		if (sip->sip_contact == NULL || sip->sip_contact->m_url == NULL) {
			LOGD("Sip contact or url is null");
			return;
		}

		url_t *ct_url = sip->sip_contact->m_url;

		//grab the transport of the contact uri
		char ct_tport[32] = "udp";
		if (url_param(ct_url->url_params, "transport", ct_tport, sizeof(ct_tport)) > 0) {

		}


		// Create parameter
		string param = mCtRtParamName + "=" + ct_tport + ":";
		if (insertDomain) {
			// param=tport:domain
			param += sip->sip_from->a_url->url_host;
		} else {
			// param=tport:ip_prev_hop:port_prev_hop
			param += ct_url->url_host;
			param += ":";
			param += url_port(ct_url);
		}

		// Add parameter
		SLOGD << "Rewriting contact with param [" << param << "]";
		if (url_param_add(ms->getHome(), ct_url, param.c_str())) {
			LOGE("Cannot insert url param [%s]", param.c_str());
		}

		/*masquerade the contact, so that later requests (INVITEs) come to us */
		const url_t*preferedRoute=getAgent()->getPreferredRouteUrl();
		ct_url->url_host = preferedRoute->url_host;
		ct_url->url_port = url_port(preferedRoute);
		ct_url->url_scheme=preferedRoute->url_scheme;
		ct_url->url_params = url_strip_param_string(su_strdup(ms->getHome(), ct_url->url_params), "transport");
		char tport_value[64];
		if (url_param(preferedRoute->url_params,"transport",tport_value,sizeof(tport_value))>0){
			char *lParam = su_sprintf(ms->getHome(), "transport=%s",tport_value);
			url_param_add(ms->getHome(),ct_url,lParam);
		}
		SLOGD << "Contact has been rewritten to " << url_as_string(ms->getHome(), ct_url);
	}


	void rewriteReqUrlWithCtrt(url_t *dest, char ctrt_param[64], su_home_t *home) {
		//first remove param
		dest->url_params = url_strip_param_string(su_strdup(home, dest->url_params), mCtRtParamName.c_str());

		//test and remove maddr param
		if (url_has_param(dest, "maddr")) {
			dest->url_params = url_strip_param_string(su_strdup(home, dest->url_params), "maddr");
		}

		//test and remove transport param
		if (url_has_param(dest, "transport")) {
			dest->url_params = url_strip_param_string(su_strdup(home, dest->url_params), "transport");
		}

		//second change dest to
		char* tend = strchr(ctrt_param, ':');
		if (!tend) {
			LOGD("Skipping url rewrite: first ':' not found");
			return;
		}

		const char* transport = su_strndup(home, ctrt_param, tend - ctrt_param);
		const url_t *paramurl = url_format(home, "sip:%s", tend +1);
		
		dest->url_host = paramurl->url_host; // move ownership
		dest->url_port = paramurl->url_port; // move ownership
		if (strcasecmp(transport, "udp") != 0) {
			char *t_param = su_sprintf(home, "transport=%s", transport);
			url_param_add(home, dest, t_param);
		}

		LOGD("Request url changed to %s", url_as_string(home, dest));
	}

	string mCtRtParamName;
	bool mMasqueradeRegisters, mMasqueradeInvites;
	bool mInsertDomain;
	static ModuleInfo<ContactRouteInserter> sInfo;
};

ModuleInfo<ContactRouteInserter> ContactRouteInserter::sInfo("ContactRouteInserter", "The purpose of the ContactRouteInserter module is to masquerade the contact header of incoming registers that are not handled locally "
		"(think about flexisip used as a SBC gateway) in such a way that it is then possible to route back outgoing invites to the original address. "
		"It is a kind of similar mechanism as Record-Route, but for REGISTER.",
		ModuleInfoBase::ModuleOid::ContactRouteInserter);
