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
#include "generic-contact-route-inserter.hh"

class ContactRouteInserter : public GenericContactRouteInserter {
	public:
	ContactRouteInserter(Agent *ag):GenericContactRouteInserter(ag){

	}

	void onRequest(std::shared_ptr<SipEvent> &ev) {
		sip_t *sip=ev->mSip;

		if(sip->sip_request->rq_method == sip_method_register){
			//rewrite the request uri to the domain
			//this assume the domain is also the proxy
			sip->sip_request->rq_url->url_host=sip->sip_to->a_url->url_host;
			sip->sip_request->rq_url->url_port=sip->sip_to->a_url->url_port;
		}
		
		GenericContactRouteInserter::onRequest(ev);
	}
	private:
		static ModuleInfo<ContactRouteInserter> sInfo;
};

ModuleInfo<ContactRouteInserter> ContactRouteInserter::sInfo("ContactRouteInserter",
	"The purpose of the ContactRouteInserter module is to masquerade the contact header of incoming registers that are not handled locally "
    "(think about flexisip used as a SBC gateway) in such a way that it is then possible to route back outgoing invites to the original address. "
    "It is a kind of similar mechanism as Record-Route, but for REGISTER.");
