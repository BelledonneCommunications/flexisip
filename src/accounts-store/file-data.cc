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

#include "file-data.hh"

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "flexisip/logmanager.hh"
#include "utils/load-file.hh"

using namespace flexisip::flexiapi;
namespace flexisip {

FileData::FileData(const std::filesystem::path& filePath) {
	auto data = loadFromFile(filePath);
	auto jsonData = nlohmann::json::parse(data);
	try {
		for (const auto& entity : jsonData) {
			auto p = flexiapi::loadAdvancedAccount(to_string(entity));
			mData.mAccounts.insert(p);
		}
	} catch (std::exception& e) {
		LOGW << "Parsing error: " << e.what();
	}
}

void FileData::fetchAccount(const SipUri&) {}

void FileData::findCallDiversions(
    const SipUri& uri, stl_backports::move_only_function<void(const std::vector<CallDiversion>&)>&& callback) {
	const auto account = mData.mAccounts.find(uri);
	if (account == mData.mAccounts.cend()) {
		LOGD << "Unkonw account '" << uri.str() << "'";
		return callback({});
	}
	callback(account->call_diversions);
}

} // namespace flexisip
