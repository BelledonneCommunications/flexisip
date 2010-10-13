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

class ContactRouteInserter : public Module {
	public:
	ContactRouteInserter(Agent *ag):Module(ag){

	}
	void onRequest(SipEvent *ev) {
		sip_t *sip=ev->mSip;

		if(sip->sip_request->rq_method == sip_method_register){
				//rewrite contact, put local host instead and store previous contact host in new parameter
				char* lParam = su_sprintf (ev->getHome(),"%s=%s:%s",getAgent()->getUniqueId().c_str()
														,sip->sip_contact->m_url[0].url_host
														,sip->sip_contact->m_url[0].url_port);
				LOGD("Rewriting contact with param [%s]",lParam);
				if (url_param_add (ev->getHome(), sip->sip_contact->m_url,lParam)) {
					LOGE("Cannot insert url param [%s]",lParam);
				}

				sip->sip_contact->m_url[0].url_host = getAgent()->getLocAddr().c_str();
				sip->sip_contact->m_url[0].url_port = su_sprintf (ev->getHome(),"%i",getAgent()->getPort());

		}
	}
	void onResponse(SipEvent *ev) {/*nop*/};
	private:
		static ModuleInfo<ContactRouteInserter> sInfo;
};

ModuleInfo<ContactRouteInserter> ContactRouteInserter::sInfo("ContactRouteInserter");
