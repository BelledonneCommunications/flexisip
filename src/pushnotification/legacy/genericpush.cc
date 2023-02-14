/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include <iostream>
#include <list>
#include <stdexcept>
#include <string.h>

#include "flexisip/common.hh"

#include "pushnotification/apple/apple-request.hh"
#include "pushnotification/firebase/firebase-request.hh"
#include "utils/uri-utils.hh"

#include "genericpush.hh"

using namespace std;

namespace flexisip {
namespace pushnotification {

const std::string& GenericRequest::getLegacyServiceName() const noexcept {
	static const std::string invalidType{"<invalid>"};
	static const std::map<string, string> translationMap {
		{"apns", "apple"},
		{"apns.dev", "apple"},
		{"fcm", "firebase"},
		{"wp", "wp"},
		{"wp10", "wp10"}
	};
	if (mPInfo == nullptr) {
		return invalidType;
	}
	try {
		auto provider = mPInfo->getPNProvider();
		auto it = translationMap.find(provider);
		if (it == translationMap.end()) return invalidType;
		return it->second;
	} catch (const std::exception& e) {
		SLOGD << __func__ << "(): " << e.what();
		return invalidType;
	}
}

const std::vector<char>& GenericRequest::getData(const sofiasip::Url& url, Method method) {
	auto methodStr = method == Method::HttpPost ? "POST" : "GET";
	auto host = url.getHost();
	auto port = url.getPort();
	auto path = url.getPath();
	auto headers = url.getHeaders();

	substituteArgs(path);
	substituteArgs(headers);

	ostringstream httpMessage{};
	httpMessage << methodStr << " /" << path;
	if (!headers.empty()) httpMessage << "?" << headers;
	httpMessage << " HTTP/1.1\r\n";
	httpMessage << "Host: " << host;
	if (!port.empty()) httpMessage << ":" << port;
	httpMessage << "\r\n";
	if (!mPInfo->mText.empty()) {
		httpMessage << "Content-Type: text/plain\r\n";
		httpMessage << "Content-Length: " << mPInfo->mText.size() << "\r\n";
	} else httpMessage << "Content-Length: 0\r\n";
	httpMessage << "\r\n";
	if (!mPInfo->mText.empty()) {
		httpMessage << mPInfo->mText;
		httpMessage << "\r\n";
	}
	auto httpMessageStr = httpMessage.str();
	SLOGD << "GenericPushNotificationRequest" << this << " http message is " << httpMessageStr;
	mBuffer.assign(httpMessageStr.cbegin(), httpMessageStr.cend());
	return mBuffer;
}

std::string GenericRequest::isValidResponse([[maybe_unused]] const std::string& str) {
	// LOGD("GenericPushNotificationRequest: http response is \n%s", str.c_str());
	return "";
}

std::string& GenericRequest::substituteArgs(std::string& input) {
	map<string, string> keyvals{
		{"$type", getLegacyServiceName()},
		{"$token", getDestination().getPrid()},
		{"$app-id", getDestination().getParam()},
		{"$from-name", mPInfo->mFromName},
		{"$from-uri", mPInfo->mFromUri},
		{"$from-tag", mPInfo->mFromTag},
		{"$to-uri", mPInfo->mToUri},
		{"$call-id", mPInfo->mCallId},
		{"$event", mPInfo->mEvent},
		{"$uid", mPInfo->mUid},
		{"$msgid", mPInfo->mAlertMsgId},
		{"$sound", mPInfo->mAlertSound},
		{"$api-key", mFirebaseAuthKey}
	};

	for (const auto& keyval : keyvals) {
		const auto& key = keyval.first;
		const auto& val = keyval.second;
		auto pos = input.find(key);
		if (pos != string::npos) {
			auto value = UriUtils::escape(val, UriUtils::uriReserved);
			input.replace(pos, key.size(), value);
		}
	}
	return input;
}

} // namespace pushnotification
} // namespace flexisip
