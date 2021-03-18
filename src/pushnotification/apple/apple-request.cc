/*
 * apple_request.cc
 *
 *  Created on: Mar 17, 2021
 *      Author: anthony
 */

#include <regex>
#include <string>

#include <flexisip/common.hh>

#include "apple-request.hh"

using namespace std;

namespace flexisip {
namespace pushnotification {

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

	SLOGD << "PNR " << this << " payload is " << mBody.data();
	if (nwritten < 0 || unsigned(nwritten) >= mBody.size()) {
		SLOGE << "PNR " << this << " cannot be sent because the payload size is higher than " << MAXPAYLOAD_SIZE;
		mBody.clear();
		return;
	}
	mBody.resize(nwritten);
}

void AppleRequest::checkDeviceToken() const {
	static const regex tokenMatch{R"regex([0-9A-Za-z]+)regex"};
	if (!regex_match(mDeviceToken, tokenMatch) || mDeviceToken.size() != DEVICE_BINARY_SIZE * 2) {
		throw runtime_error("ApplePushNotification: Invalid deviceToken");
	}
}

} // namespace pushnotification
} // namespace flexisip
