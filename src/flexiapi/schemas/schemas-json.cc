/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "schemas-json.hh"

#include "flexisip/logmanager.hh"

namespace flexisip::flexiapi {

void ApiFormattedUri::JsonHandler::fromJson(const nlohmann::json& j, ApiFormattedUri& a) {
	LOGD_CTX("ApiFormattedUri") << "This function is not safe (no verifications)";
	a.apiFormattedUri = j.get<std::string>();
}

void ApiFormattedUri::JsonHandler::toJson(nlohmann::json& j, const ApiFormattedUri& a) {
	j = a.apiFormattedUri;
}

} // namespace flexisip::flexiapi