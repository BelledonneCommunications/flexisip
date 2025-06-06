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

#include "apple-request.hh"

#include <regex>
#include <string>

#include "flexisip/common.hh"
#include "flexisip/sofia-wrapper/msg-sip.hh"
#include "pushnotification/push-notification-exceptions.hh"
#include "utils/string-utils.hh"

using namespace std;

namespace flexisip {
namespace pushnotification {

AppleRequest::AppleRequest(PushType pType, const std::shared_ptr<const PushInfo>& info)
    : Request{pType, info}, mLogPrefix(LogManager::makeLogPrefixForInstance(this, "AppleRequest")) {
	const auto& deviceToken = getDeviceToken();
	const auto& msg_id = mPInfo->mAlertMsgId;
	const auto& arg = mPInfo->mFromName.empty() ? mPInfo->mFromUri : mPInfo->mFromName;
	const auto& sound = mPInfo->mAlertSound;
	const auto& callid = mPInfo->mCallId;
	auto date = getPushTimeStamp();
	auto ttl = static_cast<int>(mPInfo->mTtl.count());
	int nwritten = 0;

	mBody.assign(MAXPAYLOAD_SIZE + 1, '\0');

	checkDeviceToken();

	auto customPayload = mPInfo->mCustomPayload.empty() ? string{"{}"} : mPInfo->mCustomPayload;

	switch (pType) {
		case PushType::Unknown:
			throw InvalidPushParameters{"Apple push type not set"};
		case PushType::VoIP: {
			// We also need msg_id and call_id in case the push is received but the device cannot register
			constexpr auto rawPayload = R"json({
	"aps": {
		"sound": "",
		"loc-key": "%s",
		"loc-args": ["%s"],
		"call-id": "%s",
		"uuid": %s,
		"send-time": "%s"
	},
	"from-uri": "%s",
	"display-name": "%s",
	"pn_ttl": %d,
	"customPayload": %s
})json";
			nwritten = snprintf(mBody.data(), mBody.size(), rawPayload, msg_id.c_str(), arg.c_str(), callid.c_str(),
			                    quoteStringIfNeeded(mPInfo->mUid).c_str(), date.c_str(), mPInfo->mFromUri.c_str(),
			                    mPInfo->mFromName.c_str(), ttl, customPayload.c_str());
			break;
		}
		case PushType::Background: {
			// Use a normal push notification with content-available set to 1, no alert, no sound.
			constexpr auto rawPayload = R"json({
	"aps": {
		"badge": 0,
		"content-available": 1,
		"loc-key": "%s",
		"loc-args": ["%s"],
		"call-id": "%s",
		"uuid": %s,
		"send-time": "%s"
	},
	"from-uri": "%s",
	"display-name": "%s",
	"pn_ttl": %d,
	"customPayload": %s
})json";
			nwritten = snprintf(mBody.data(), mBody.size(), rawPayload, msg_id.c_str(), arg.c_str(), callid.c_str(),
			                    quoteStringIfNeeded(mPInfo->mUid).c_str(), date.c_str(), mPInfo->mFromUri.c_str(),
			                    mPInfo->mFromName.c_str(), ttl, customPayload.c_str());
			break;
		}
		case PushType::Message: {
			/* some apps don't want the push to update the badge - but if they do,
			we always put the badge value to 1 because we want to notify the user that
			he/she has unread messages even if we do not know the exact count */
			constexpr auto rawPayload = R"json({
	"aps": {
		"alert": {
			"loc-key": "%s",
			"loc-args": ["%s"]
		},
		"sound": "%s",
		"mutable-content": 1,
		"badge": %d
	},
	"from-uri": "%s",
	"display-name": "%s",
	"call-id": "%s",
	"pn_ttl": %d,
	"uuid": %s,
	"send-time": "%s",
	"chat-room-addr": "%s",
	"customPayload": %s
})json";
			nwritten = snprintf(mBody.data(), mBody.size(), rawPayload, msg_id.c_str(), arg.c_str(), sound.c_str(),
			                    (mPInfo->mNoBadge ? 0 : 1), mPInfo->mFromUri.c_str(), mPInfo->mFromName.c_str(),
			                    callid.c_str(), ttl, quoteStringIfNeeded(mPInfo->mUid).c_str(), date.c_str(),
			                    mPInfo->mChatRoomAddr.c_str(), customPayload.c_str());
			break;
		}
	}

	LOGD << "Payload is:\n" << mBody.data();
	if (nwritten < 0 || unsigned(nwritten) >= mBody.size()) {
		LOGE << "Cannot be sent because the payload size is higher than " << MAXPAYLOAD_SIZE;
		mBody.clear();
		return;
	}
	mBody.resize(nwritten);

	auto expire = 0;
	if (ttl > 0) {
		expire = time(nullptr) + ttl;
	}
	auto path = "/3/device/" + deviceToken;
	auto collapseId = mPInfo->mCollapseId;
	if (collapseId.size() > 64) {
		ostringstream msg{};
		msg << "Value of apns-collapse-id exceeds 64 characters, shrinking '" << collapseId << "' -> '";
		collapseId.resize(64);
		msg << collapseId << "'";
		LOGW << msg.str();
	}

	HttpHeaders headers{};
	headers.add(":method", "POST");
	headers.add(":scheme", "https");
	headers.add(":path", path);
	headers.add("apns-expiration", to_string(expire));
	headers.add("apns-topic", getDestination().getAPNSTopic());
	headers.add("apns-push-type", pushTypeToApnsPushType(pType));
	headers.add("apns-priority", "10");
	if (!collapseId.empty()) headers.add("apns-collapse-id", collapseId);
	this->setHeaders(headers);

	LOGD << "Https headers are:\n" << headers.toString();
}

std::string AppleRequest::getTeamId() const noexcept {
	const auto& pnParam = getDestination().getParam();
	return pnParam.substr(0, pnParam.find('.'));
}

void AppleRequest::checkDeviceToken() const {
	static const regex tokenMatch{R"regex([0-9A-Za-z]+)regex"};
	const auto& deviceToken = getDeviceToken();
	if (!regex_match(deviceToken, tokenMatch) || deviceToken.size() != DEVICE_BINARY_SIZE * 2) {
		throw InvalidPushParameters{"invalid device token for ApplePushNotification"};
	}
}

string AppleRequest::pushTypeToApnsPushType(PushType type) {
	switch (type) {
		case PushType::Unknown:
			throw InvalidPushParameters{"no 'apns-push-type' value for 'PushType::Unknown'"};
		case PushType::Message:
			return "alert";
		case PushType::Background:
			return "background";
		case PushType::VoIP:
			return "voip";
	}
	throw InvalidPushParameters{to_string(static_cast<int>(type)) + " isn't a valid PushType value"};
}

// redundant declaration (required for C++14 compatibility)
constexpr std::size_t AppleRequest::MAXPAYLOAD_SIZE;
constexpr std::size_t AppleRequest::DEVICE_BINARY_SIZE;

} // namespace pushnotification
} // namespace flexisip