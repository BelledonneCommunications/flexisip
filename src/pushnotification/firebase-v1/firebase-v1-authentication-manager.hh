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

#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include "firebase-v1-access-token-provider.hh"
#include "flexisip/logmanager.hh"
#include "flexisip/sofia-wrapper/timer.hh"
#include "utils/thread/must-finish-thread.hh"
#include "utils/transport/http/authentication-manager.hh"

namespace flexisip::pushnotification {

/*
 * Adds the "authorization" field that contains an OAuth2 access token in a FirebaseV1Request header.
 * Manages the renewal of the access token and makes sure the token in use is always valid.
 */
class FirebaseV1AuthenticationManager : public AuthenticationManager,
                                        public std::enable_shared_from_this<FirebaseV1AuthenticationManager> {
public:
	explicit FirebaseV1AuthenticationManager(const std::shared_ptr<sofiasip::SuRoot>& root,
	                                         const std::filesystem::path& scriptPath,
	                                         const std::filesystem::path& serviceAccountFilePath,
	                                         const std::chrono::milliseconds& defaultRefreshInterval,
	                                         const std::chrono::milliseconds& tokenExpirationAnticipationTime);

	bool addAuthentication(const std::shared_ptr<HttpMessage>& req) override;

	[[nodiscard]] std::string_view getProjectId() const {
		return mProjectId;
	}

private:
	void onTokenRefreshStart();
	void onTokenRefreshEnd(const std::optional<FirebaseV1AccessTokenProvider::AccessToken>& newToken);

	MustFinishThread mThread;
	std::weak_ptr<sofiasip::SuRoot> mRoot;

	std::shared_ptr<AccessTokenProvider> mTokenProvider;
	std::optional<AccessTokenProvider::AccessToken> mToken;

	std::unique_ptr<sofiasip::Timer> mTimer;
	std::chrono::milliseconds mDefaultRefreshInterval;
	std::chrono::milliseconds mTokenExpirationAnticipationTime;

	std::string mLogPrefix;
	std::string mProjectId;
};

} // namespace flexisip::pushnotification
