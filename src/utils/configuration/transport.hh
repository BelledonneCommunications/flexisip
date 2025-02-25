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

using IP_FAMILY = int;

/**
 * Parse a host name or a numeric host address for a given service.
 *
 * @param address host name or numeric host address
 * @param service service name or port number
 *
 * @return corresponding IP address along with IP address family if successful, empty string and unspecified family in
 * case of error
 */
std::pair<std::string, IP_FAMILY> parseInternetAddress(std::string_view address, std::string_view service = "5060");

/**
 * Configure NAT addresses of the provided 'linphone::NatPolicy' in function of the provided addresses.
 * @note you can only configure one IP address for each IP address family
 *
 * @param policy NAT policy
 * @param parameter parameter from Flexisip configuration file (list of IP addresses)
 *
 * @throw BadConfiguration if an error occurred while parsing the provided addresses
 * @throw BadConfiguration if several IP addresses of the same type are provided
 * @throw BadConfiguration if one of the IP address family of the provided addresses is invalid
 */
void configureNatAddresses(const std::shared_ptr<linphone::NatPolicy>& policy, const ConfigStringList* parameter);

} // namespace flexisip::configuration_utils