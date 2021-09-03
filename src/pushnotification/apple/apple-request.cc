/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <regex>
#include <string>

#include <flexisip/common.hh>

#include "apple-request.hh"

using namespace std;

namespace flexisip {
namespace pushnotification {

// redundant declaration (required for C++14 compatibility)
constexpr std::size_t AppleRequest::MAXPAYLOAD_SIZE;
constexpr std::size_t AppleRequest::DEVICE_BINARY_SIZE;

AppleRequest::AppleRequest(const PushInfo& info) : Request(info.mAppId, "apple"), mPayloadType{info.mApplePushType} {
	const string& deviceToken = info.mDeviceToken;
	const string& msg_id = info.mAlertMsgId;
	const string& arg = info.mFromName.empty() ? info.mFromUri : info.mFromName;
	const string& sound = info.mAlertSound;
	const string& callid = info.mCallId;
	string date = getPushTimeStamp();
	int nwritten = 0;

	mBody.assign(MAXPAYLOAD_SIZE + 1, '\0');

	mDeviceToken = deviceToken;
	checkDeviceToken();

	string customPayload = (info.mCustomPayload.empty()) ? "{}" : info.mCustomPayload;

	switch (info.mApplePushType) {
		case ApplePushType::Unknown:
			throw invalid_argument{"Apple push type not set"};
		case ApplePushType::Pushkit: {
			// We also need msg_id and callid in case the push is received but the device cannot register
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
			                    quoteStringIfNeeded(info.mUid).c_str(), date.c_str(), info.mFromUri.c_str(),
			                    info.mFromName.c_str(), info.mTtl, customPayload.c_str());
			break;
		}
		case ApplePushType::Background: {
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
			                    quoteStringIfNeeded(info.mUid).c_str(), date.c_str(), info.mFromUri.c_str(),
			                    info.mFromName.c_str(), info.mTtl, customPayload.c_str());
			break;
		}
		case ApplePushType::RemoteBasic: {
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
		"badge": %d
	},
	"from-uri": "%s",
	"display-name": "%s",
	"call-id": "%s",
	"pn_ttl": %d,
	"uuid": %s,
	"send-time": "%s",
	"customPayload": %s
})json";
			nwritten = snprintf(mBody.data(), mBody.size(), rawPayload, msg_id.c_str(), arg.c_str(), sound.c_str(),
			                    (info.mNoBadge ? 0 : 1), info.mFromUri.c_str(), info.mFromName.c_str(), callid.c_str(),
			                    info.mTtl, quoteStringIfNeeded(info.mUid).c_str(), date.c_str(), customPayload.c_str());
			break;
		}
		case ApplePushType::RemoteWithMutableContent: {
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
			                    (info.mNoBadge ? 0 : 1), info.mFromUri.c_str(), info.mFromName.c_str(), callid.c_str(),
			                    info.mTtl, quoteStringIfNeeded(info.mUid).c_str(), date.c_str(),
			                    info.mChatRoomAddr.c_str(), customPayload.c_str());
			break;
		}
	}

	SLOGD << "Apple PNR " << this << " payload is :\n" << mBody.data();
	if (nwritten < 0 || unsigned(nwritten) >= mBody.size()) {
		SLOGE << "Apple PNR " << this << " cannot be sent because the payload size is higher than " << MAXPAYLOAD_SIZE;
		mBody.clear();
		return;
	}
	mBody.resize(nwritten);

	auto expire = 0;
	if (info.mTtl > 0) {
		expire = time(nullptr) + info.mTtl;
	}
	auto path = string{"/3/device/"} + mDeviceToken;
	auto topicLen = mAppId.rfind(".");
	auto apnsTopic = mAppId.substr(0, topicLen);

	HttpHeaders headers{};
	headers.add(":method", "POST");
	headers.add(":scheme", "https");
	headers.add(":path", move(path));
	headers.add("apns-expiration", to_string(expire));
	headers.add("apns-topic", apnsTopic);
	headers.add("apns-push-type", pushTypeToApnsPushType(mPayloadType));
	this->setHeaders(headers);

	SLOGD << "Apple PNR  " << this << " https headers are :\n" << headers.toString();
}

void AppleRequest::checkDeviceToken() const {
	static const regex tokenMatch{R"regex([0-9A-Za-z]+)regex"};
	if (!regex_match(mDeviceToken, tokenMatch) || mDeviceToken.size() != DEVICE_BINARY_SIZE * 2) {
		throw runtime_error("ApplePushNotification: Invalid deviceToken");
	}
}

string AppleRequest::pushTypeToApnsPushType(ApplePushType type) {
	string res{};
	switch (type) {
		case ApplePushType::Unknown:
			throw invalid_argument("no 'apns-push-type' value for 'ApplePushType::Unknown'");
		case ApplePushType::RemoteBasic:
		case ApplePushType::RemoteWithMutableContent:
			res = "alert";
			break;
		case ApplePushType::Background:
			res = "background";
			break;
		case ApplePushType::Pushkit:
			res = "voip";
			break;
	}
	return res;
}

} // namespace pushnotification
} // namespace flexisip
