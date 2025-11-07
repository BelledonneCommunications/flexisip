/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include <string>

#include "agent.hh"
#include "flexisip/event.hh"

namespace flexisip {

class ContactMasquerader {
public:
	ContactMasquerader(Agent* agent, const std::string& paramName) : mAgent(agent), mCtRtParamName(paramName) {}

	/**
	 * Add a parameter in the form "CtRt15.128.128.2=tcp:201.45.118.16:50025" into the contact header field. Thus, we
	 * know the transport to use to forward requests back to the client.
	 *
	 * @param home home to store the new contact url
	 * @param contact contact to masquerade
	 * @param domain SIP domain to insert into the contact route parameter
	 */
	void masquerade(su_home_t* home, sip_contact_t* contact, const std::string& domain) const;
	/**
	 * @brief Masquerade each contact header field of the provided request except those which have an 'expires'
	 * parameter with a null value. These contact header fields will be removed from the request. However, if
	 * each contact header has a null 'expires' parameter, the last one will be preserved.
	 *
	 * @param ms the message containing header fields to masquerade
	 * @param insertDomain if 'true', use the host part in the 'From' header field instead of 'host:port' in the
	 * original 'Contact' header field to masquerade the provided message.
	 */
	void masquerade(MsgSip& ms, bool insertDomain = false) const;
	/**
	 * Parse the provided contact route parameter and modify the provided uri with parsed information.
	 *
	 * @param home home to store the restored uri
	 * @param dest uri that will be set to the restored uri
	 * @param param the contact route parameter
	 * @param newParam a new parameter to add
	 */
	void restore(su_home_t* home, url_t* dest, const std::string& param, const std::string& newParam = {}) const;

private:
	static constexpr std::string_view mLogPrefix{"ContactMasquerader"};

	Agent* mAgent;
	std::string mCtRtParamName;
};

} // namespace flexisip