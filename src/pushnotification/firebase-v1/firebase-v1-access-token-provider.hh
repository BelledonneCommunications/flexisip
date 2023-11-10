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

#include <filesystem>
#include <optional>
#include <string>

#include "pushnotification/access-token-provider.hh"

namespace flexisip::pushnotification {

/*
 * Provides an OAuth2 access token.
 */
class FirebaseV1AccessTokenProvider : public AccessTokenProvider {
public:
	explicit FirebaseV1AccessTokenProvider(const std::filesystem::path& scriptPath,
	                                       const std::filesystem::path& serviceAccountFilePath);

	// Calls a python script that requests a new OAuth2 access token from the Firebase servers.
	// This function must therefore be called asynchronously.
	std::optional<AccessToken> getToken() override;

private:
	std::string mLogPrefix;
	std::string mCommand;
};

} // namespace flexisip::pushnotification
