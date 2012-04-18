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
		ConfigItemDescriptor items[] = { { Boolean, "masquerade-contacts-for-invites", "Hack for workarounding Nortel CS2k gateways bug.", "false" }, config_item_end };
		module_config->addChildrenValues(items);
	}

	void onLoad(const GenericStruct *module_config) {
		mContactRouteParamName = string("CtRt") + getAgent()->getUniqueId();
		mMasqueradeInviteContacts = module_config->get<ConfigBoolean>("masquerade-contacts-for-invites")->read();
	}

	void onRequest(shared_ptr<SipEvent> &ev) {
		const shared_ptr<MsgSip> &ms = ev->getMsgSip();
		sip_t *sip = ms->getSip();

		if (sip->sip_request->rq_method == sip_method_register) {
			//rewrite the request uri to the domain
			//this assume the domain is also the proxy
			sip->sip_request->rq_url->url_host = sip->sip_to->a_url->url_host;
			sip->sip_request->rq_url->url_port = sip->sip_to->a_url->url_port;
		}

		if (sip->sip_request->rq_method == sip_method_register || ((sip->sip_request->rq_method == sip_method_invite) && mMasqueradeInviteContacts)) {
			masqueradeContact(ev);
		}
		if (sip->sip_request->rq_method != sip_method_register) {
			/* check if request-uri contains a contact-route parameter, so that we can route back to the client */
			char contact_route_param[64];
			url_t *dest = sip->sip_request->rq_url;
			// now need to check if request uri has special param inserted by contact-route-inserter module
			if (url_param(dest->url_params, mContactRouteParamName.c_str(), contact_route_param, sizeof(contact_route_param))) {
				//first remove param
				dest->url_params = url_strip_param_string(su_strdup(ms->getHome(), dest->url_params), mContactRouteParamName.c_str());
				//test and remove maddr param
				if (url_has_param(dest, "maddr")) {
					dest->url_params = url_strip_param_string(su_strdup(ms->getHome(), dest->url_params), "maddr");
				}
				//second change dest to
				char* tmp = strchr(contact_route_param, ':');
				if (tmp) {
					char* transport = su_strndup(ms->getHome(), contact_route_param, tmp - contact_route_param);
					char *tmp2 = tmp + 1;
					tmp = strchr(tmp2, ':');
					if (tmp) {
						dest->url_host = su_strndup(ms->getHome(), tmp2, tmp - tmp2);
						dest->url_port = su_strdup(ms->getHome(), tmp + 1);
						if (strcasecmp(transport, "udp") != 0) {
							char *t_param = su_sprintf(ms->getHome(), "transport=%s", transport);
							url_param_add(ms->getHome(), dest, t_param);
						}
					}
				}
			}
		}
	}
	virtual void onResponse(shared_ptr<SipEvent> &ev) {
		const shared_ptr<MsgSip> &ms = ev->getMsgSip();
		sip_t *sip = ms->getSip();
		if (mMasqueradeInviteContacts && (sip->sip_cseq->cs_method == sip_method_invite || sip->sip_cseq->cs_method == sip_method_subscribe)) {
			masqueradeContact(ev);
		}
	}
private:
	void masqueradeContact(shared_ptr<SipEvent> &ev) {
		const shared_ptr<MsgSip> &ms = ev->getMsgSip();
		sip_t *sip = ms->getSip();
		if (sip->sip_contact != NULL && sip->sip_contact->m_url != NULL) {
			//rewrite contact, put local host instead and store previous contact host in new parameter
			char ct_tport[32] = "udp";
			char* lParam;
			url_t *ct_url = sip->sip_contact->m_url;

			//grab the transport of the contact uri
			if (url_param(sip->sip_contact->m_url->url_params, "transport", ct_tport, sizeof(ct_tport)) > 0) {

			}
			/*add a parameter like "CtRt15.128.128.2=tcp:201.45.118.16:50025" in the contact, so that we know where is the client
			 when we later have to route an INVITE to him */
			lParam = su_sprintf(ms->getHome(), "%s=%s:%s:%s", mContactRouteParamName.c_str(), ct_tport, ct_url->url_host, ct_url->url_port);
			LOGD("Rewriting contact with param [%s]", lParam);
			if (url_param_add(ms->getHome(), ct_url, lParam)) {
				LOGE("Cannot insert url param [%s]", lParam);
			}
			/*masquerade the contact, so that later requests (INVITEs) come to us */
			ct_url->url_host = getAgent()->getPublicIp().c_str();
			ct_url->url_port = su_sprintf(ms->getHome(), "%i", getAgent()->getPort());
			/*remove the transport, in most case further requests should come back to us in UDP*/
			ct_url->url_params = url_strip_param_string(su_strdup(ms->getHome(), ct_url->url_params), "transport");
		}
	}

	string mContactRouteParamName;
	bool mMasqueradeInviteContacts;
	static ModuleInfo<ContactRouteInserter> sInfo;
};

ModuleInfo<ContactRouteInserter> ContactRouteInserter::sInfo("ContactRouteInserter", "The purpose of the ContactRouteInserter module is to masquerade the contact header of incoming registers that are not handled locally "
		"(think about flexisip used as a SBC gateway) in such a way that it is then possible to route back outgoing invites to the original address. "
		"It is a kind of similar mechanism as Record-Route, but for REGISTER.");
