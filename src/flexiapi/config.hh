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

#include "flexisip/configmanager.hh"
#include "flexisip/sofia-wrapper/su-root.hh"
#include "utils/transport/http/http2client.hh"
#include "utils/transport/http/rest-client.hh"

namespace flexisip::flexiapi {

/**
 * Create a Http2Client based on the content of the global::flexiapi section of the configuration.
 *
 * @throws BadConfiguration if the configuration fields contains invalid values.
 */
std::shared_ptr<Http2Client> createClient(const std::shared_ptr<ConfigManager>& cfg, sofiasip::SuRoot& root);

/**
 * Create a RestClient based on the content of the global::flexiapi section of the configuration.
 *
 * @param http2Client should be the client created by createClient, for the same ConfigManager.
 * @throws BadConfiguration if the configuration fields contains invalid or empty values.
 */
RestClient createRestClient(const ConfigManager& cfg, const std::shared_ptr<Http2Client>& http2Client);

} // namespace flexisip::flexiapi