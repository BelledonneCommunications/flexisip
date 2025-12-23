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

#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "accounts-data-manager.hh"
#include "flexisip/utils/sip-uri.hh"

namespace flexisip {

class FileData : public IDataManager {
public:
	FileData(const std::filesystem::path& filePath);
	void fetchAccount(const SipUri& uri) override;
	void findCallDiversions(
	    const SipUri& uri,
	    stl_backports::move_only_function<void(const std::vector<flexiapi::CallDiversion>&)>&& callback) override;

private:
	static constexpr std::string_view mLogPrefix{"AccountsStore::FileData"};
	AccountsData mData;
};

} // namespace flexisip
