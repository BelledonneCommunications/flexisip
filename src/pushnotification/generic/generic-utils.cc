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

#include "generic-utils.hh"

#include "utils/uri-utils.hh"

using namespace std;

namespace flexisip::pushnotification {

std::tuple<std::string, std::string, std::string>
GenericUtils::getLegacyParams(const std::shared_ptr<const PushInfo> pushInfo, PushType pushType) noexcept {
	constexpr auto kInvalid = "<invalid>";
	try {
		const auto& rfcPushParams = pushInfo->mDestinations.at(pushType);
		const auto& pnProvider = rfcPushParams->getProvider();
		const auto& pnParam = rfcPushParams->getParam();
		const auto& pnPrid = rfcPushParams->getPrid();
		if (rfcPushParams->isApns()) {
			auto appId = string{kInvalid};
			if (const auto idx = pnParam.find('.'); idx != pnParam.npos) {
				const bool isDev = (pnProvider == "apns.dev");
				appId = pnParam.substr(idx + 1) + (isDev ? ".dev" : ".prod");
			}
			return make_tuple("apple", appId, pnPrid);
		} else if (rfcPushParams->isFirebase()) {
			return make_tuple("firebase", pnParam, pnPrid);
		} else {
			// wp, wp10 and other
			return make_tuple(pnProvider, pnParam, pnPrid);
		}
	} catch (const std::out_of_range&) {
		LOGE << "No push parameters found for the given push type [" << pushType << "]";
		return make_tuple(kInvalid, kInvalid, kInvalid);
	} catch (const std::exception& e) {
		LOGE << "Unexpected exception: " << e.what();
		return make_tuple(kInvalid, kInvalid, kInvalid);
	}
}

void GenericUtils::substituteArgs(std::string& input,
                                  const std::shared_ptr<const PushInfo>& pushInfo,
                                  PushType pushType) noexcept {
	auto [pnType, appID, pnTok] = getLegacyParams(pushInfo, pushType);
	map<string, string, std::less<>> keyValues{{"$type", pnType},
	                                           {"$token", pnTok},
	                                           {"$app-id", appID},
	                                           {"$from-name", pushInfo->mFromName},
	                                           {"$from-uri", pushInfo->mFromUri},
	                                           {"$from-tag", pushInfo->mFromTag},
	                                           {"$to-uri", pushInfo->mToUri},
	                                           {"$call-id", pushInfo->mCallId},
	                                           {"$event", pushInfo->mEvent},
	                                           {"$uid", pushInfo->mUid},
	                                           {"$msgid", pushInfo->mAlertMsgId},
	                                           {"$sound", pushInfo->mAlertSound}};

	for (const auto& [key, value] : keyValues) {
		auto pos = input.find(key);
		if (pos != string::npos) {
			auto valueEscaped = UriUtils::escape(value, UriUtils::uriReserved);
			input.replace(pos, key.size(), valueEscaped);
		}
	}
}

} // namespace flexisip::pushnotification