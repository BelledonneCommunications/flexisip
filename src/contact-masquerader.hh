/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <memory>
#include <string>

#include "flexisip/event.hh"

#include "agent.hh"
#include "eventlogs/writers/event-log-writer.hh"

namespace flexisip {

class ContactMasquerader {
	Agent* mAgent;
	std::string mCtRtParamName;

public:
	ContactMasquerader(Agent* agent, std::string paramName) : mAgent(agent), mCtRtParamName(paramName) {
	}

	/*add a parameter like "CtRt15.128.128.2=tcp:201.45.118.16:50025" in the contact, so that we know where is the
	 client
	 when we later have to route an INVITE to him */
	void masquerade(su_home_t *home, sip_contact_t *c, const char *domain = NULL);
	
	/**
	 * Masquerade each contact header of a REGISTER request except those
	 * which have an 'expires' parameter with a null value. Those contact headers
	 * will be removed from the REGISTER request. However, if each contact header
	 * has a null 'expires' parameter, the last one will be preserved.
	 */
	void masquerade(std::shared_ptr<SipEvent> ev, bool insertDomain = false);

	void restore(su_home_t *home, url_t *dest, char ctrt_param[64], const char *new_param = NULL);
};

}