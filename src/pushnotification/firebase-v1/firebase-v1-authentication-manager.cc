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

#include "firebase-v1-authentication-manager.hh"

#include <chrono>
#include <fstream>
#include <memory>
#include <thread>

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "flexisip/logmanager.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

#include "firebase-v1-request.hh"

using namespace std;
using namespace std::chrono_literals;
using namespace nlohmann;
using HttpRequest = flexisip::HttpMessage;

namespace flexisip::pushnotification {

FirebaseV1AuthenticationManager::FirebaseV1AuthenticationManager(
    const std::shared_ptr<sofiasip::SuRoot>& root,
    const std::filesystem::path& scriptPath,
    const std::filesystem::path& serviceAccountFilePath,
    const std::chrono::milliseconds& defaultRefreshInterval,
    const std::chrono::milliseconds& tokenExpirationAnticipationTime)
    : mRoot(root), mTokenProvider(make_unique<FirebaseV1AccessTokenProvider>(scriptPath, serviceAccountFilePath)),
      mDefaultRefreshInterval(defaultRefreshInterval),
      mTokenExpirationAnticipationTime(tokenExpirationAnticipationTime) {

	ifstream file;
	file.open(serviceAccountFilePath);
	if (!file) {
		throw runtime_error("failed to open firebase service account file: " + serviceAccountFilePath.string());
	}

	const auto parsedFile = json::parse(file, nullptr, false);
	file.close();

	if (parsedFile.is_discarded()) {
		throw runtime_error("failed to parse firebase service account file: " + serviceAccountFilePath.string());
	}

	if (mProjectId = parsedFile.value("project_id", ""); mProjectId.empty()) {
		throw runtime_error("failed to read \"project_id\" value from firebase service account file: " +
		                    serviceAccountFilePath.string());
	}

	mLogPrefix = "FirebaseV1AuthenticationManager[" + mProjectId + "]";

	chrono::milliseconds interval;
	if (mToken = mTokenProvider->getToken(); mToken) {
		interval = mToken->lifetime - mTokenExpirationAnticipationTime;
		SLOGD << mLogPrefix << ": successfully get access token [lifetime=" << mToken->lifetime.count() << "ms]";
	} else {
		interval = mDefaultRefreshInterval;
		SLOGW << mLogPrefix << ": failed to get access token, automatic retry in " << interval.count() << "ms";
	}

	mTimer = make_unique<sofiasip::Timer>(root->getCPtr());
	mTimer->set([this]() { this->onTokenRefreshStart(); }, interval);
}

bool FirebaseV1AuthenticationManager::addAuthentication(const std::shared_ptr<HttpRequest>& req) {
	if (mToken == nullopt) {
		return false;
	}

	auto firebaseReq = dynamic_pointer_cast<FirebaseV1Request>(req);
	firebaseReq->getHeaders().add("authorization", "Bearer " + mToken->content);

	return true;
}

void FirebaseV1AuthenticationManager::onTokenRefreshStart() {
	SLOGD << mLogPrefix << ": trying to refresh access token...";

	// WARNING: this code can still block execution of the main loop if successive rapid calls are made to this method.
	// Indeed, it will wait for the end of the current thread before starting the new one (see operator=).
	// However, this cannot happen as it is. Indeed, the next call to this method is only made once the execution of the
	// python script is done. That is to say the thread must be in its "final state" before deciding when to run this
	// method again. So successive calls happening before the precedent thread has terminated are not possible.

	mThread = thread{[weakThis = weak_from_this(), weakTokenProvider = weak_ptr<AccessTokenProvider>(mTokenProvider),
	                  weakRoot = mRoot, logPrefix = mLogPrefix] {
		// Get new access token.
		const auto tokenProvider = weakTokenProvider.lock();
		if (tokenProvider == nullptr) {
			SLOGD << logPrefix << ": pointer on access token provider is empty, cancel refresh";
			return;
		}

		const auto token = tokenProvider->getToken();

		// Add update token event to the main loop.
		const auto root = weakRoot.lock();
		if (root == nullptr) {
			SLOGD << logPrefix << ": pointer on main loop is empty, cancel refresh";
			return;
		}

		root->addToMainLoop([weakThis, newToken = token, logPrefix]() {
			const auto manager = weakThis.lock();
			if (manager == nullptr) {
				SLOGD << logPrefix << ": pointer on authentication manager is empty, cancel refresh";
				return;
			}
			manager->onTokenRefreshEnd(newToken);
		});
	}};
}

void FirebaseV1AuthenticationManager::onTokenRefreshEnd(
    const std::optional<FirebaseV1AccessTokenProvider::AccessToken>& newToken) {
	chrono::milliseconds interval;
	if (newToken) {

		if (newToken == mToken) {
			SLOGW << mLogPrefix << ": token provider returned same token as the one currently in use";
		}

		mToken = newToken;
		interval = mToken->lifetime - mTokenExpirationAnticipationTime;
		SLOGD << mLogPrefix
		      << ": successfully refreshed and updated access token [lifetime=" << mToken->lifetime.count() << "ms]";
	} else {
		interval = mDefaultRefreshInterval;
		SLOGW << mLogPrefix << ": failed to refresh access token, automatic retry in " << interval.count() << "ms";
	}

	mTimer->set([this]() { this->onTokenRefreshStart(); }, interval);
}

} // namespace flexisip::pushnotification
