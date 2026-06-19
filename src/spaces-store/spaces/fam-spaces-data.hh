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

#include <chrono>
#include <memory>
#include <string>
#include <unordered_set>

#include "flexisip/sofia-wrapper/su-root.hh"
#include "flexisip/sofia-wrapper/timer.hh"
#include "spaces-data-manager.hh"
#include "utils/transport/http/rest-client.hh"

namespace flexisip {

class FAMSpacesData : public ISpacesDataManager {
public:
	FAMSpacesData(const std::shared_ptr<sofiasip::SuRoot>& root,
	              RestClient&& restClient,
	              std::chrono::milliseconds delay);

	const std::unordered_set<std::string>& getDomains() const override {
		return mDomains;
	}

private:
	static constexpr std::string_view mLogPrefix{"FAMSpacesData"};

	void askAccountManager();
	void onAccountManagerResponse(const std::shared_ptr<HttpResponse>& rep);

	RestClient mFAMClient;
	sofiasip::Timer mTimer;
	std::unordered_set<std::string> mDomains{};
};

} // namespace flexisip