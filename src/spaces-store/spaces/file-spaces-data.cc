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

#include "file-spaces-data.hh"

#include <filesystem>
#include <string>

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "exceptions/bad-configuration.hh"
#include "flexiapi/schemas/space/space-json.hh"
#include "utils/load-file.hh"

using namespace std;

namespace flexisip {

FileSpacesData::FileSpacesData(const std::filesystem::path& domainsConfigFilePath,
                               const NotifySpacesChangedCb& notifySpacesChangedCb) {
	try {
		vector<flexiapi::Space> spaces{};

		const auto data = loadFromFile(domainsConfigFilePath);
		const auto config = nlohmann::json::parse(data);

		flexiapi::verifySpacesSchemaIntegrity(config);

		std::transform(config.begin(), config.end(), std::back_inserter(spaces),
		               [](const nlohmann::json& object) { return object.get<flexiapi::Space>(); });

		notifySpacesChangedCb(spaces);
	} catch (const nlohmann::json::exception& exception) {
		throw BadConfiguration{"parsing error (" + domainsConfigFilePath.string() + "): "s + exception.what()};
	}
}

FileSpacesData::FileSpacesData(const std::list<std::string>& domains,
                               const NotifySpacesChangedCb& notifySpacesChangedCb) {
	vector<flexiapi::Space> spaces{};
	std::transform(domains.begin(), domains.end(), std::back_inserter(spaces),
	               [](const std::string& domain) { return flexiapi::Space{.domain = domain}; });
	notifySpacesChangedCb(spaces);
}

} // namespace flexisip