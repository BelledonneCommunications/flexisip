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

#ifndef Contact_Masquerader_hh
#define Contact_Masquerader_hh

#include <memory>
#include "event.hh"
#include "agent.hh"
#include <string>


class ContactMasquerader {
	Agent *mAgent;
	std::string mCtRtParamName;

public:

	ContactMasquerader(Agent *agent, std::string paramName) :
	mAgent(agent), mCtRtParamName(paramName) {
	}


	/*add a parameter like "CtRt15.128.128.2=tcp:201.45.118.16:50025" in the contact, so that we know where is the client
	 when we later have to route an INVITE to him */
	void masquerade(su_home_t *home, sip_contact_t *c, const char *domain = NULL);
	inline void masquerade(std::shared_ptr<SipEvent> ev, bool insertDomain = false) {
		masquerade(ev->getHome(), ev->getSip()->sip_contact, insertDomain ? ev->getSip()->sip_from->a_url->url_host : NULL);
	}

	void restore(su_home_t *home, url_t *dest, char ctrt_param[64], const char* new_param = NULL);
};

#endif
