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

#include <list>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>

#include <flexisip/configmanager.hh>

#include <linphone++/nat_policy.hh>
#include <linphone++/transports.hh>

namespace flexisip::configuration_utils {

/**
 * Configure provided 'linphone::Transports' in function of the given parameter and conditions.
 *
 * @param transports structure to configure (listening transport)
 * @param parameter parameter from Flexisip configuration file (must be a SIP URI)
 * @param allowedSip allowed transport types for 'sip' scheme
 * @param allowedSips allowed transport types for 'sips' scheme
 *
 * @throw BadConfiguration if the parameter is not a valid SIP URI
 * @throw BadConfiguration if the SIP URI in the parameter does not contain a port
 * @throw BadConfiguration if a forbidden scheme is used in the parameter
 * @throw BadConfiguration if a forbidden transport type for the current scheme is used in the parameter
 * @throw BadConfiguration if the scheme is not valid (i.e. not in ['sip', 'sips'])
 */
void configureTransport(const std::shared_ptr<linphone::Transports>& transports,
                        const ConfigString* parameter,
                        const std::set<std::string>& allowedSip = {"", "udp", "tcp", "tls"},
                        const std::set<std::string>& allowedSips = {"udp", "", "tcp"});

} // namespace flexisip::configuration_utils