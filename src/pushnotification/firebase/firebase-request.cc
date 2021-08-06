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

#include <iostream>
#include <string>

#include "flexisip/logmanager.hh"

#include "firebase-client.hh"
#include "utils/string-formater.hh"
#include "utils/string-utils.hh"

#include "firebase-request.hh"

using namespace std;

namespace flexisip {
namespace pushnotification {

// redundant declaration (required for C++14 compatibility)
constexpr int FirebaseRequest::FIREBASE_MAX_TTL;

FirebaseRequest::FirebaseRequest(const PushInfo& pinfo) : Request(pinfo.mAppId, "firebase") {
	const string& from = pinfo.mFromName.empty() ? pinfo.mFromUri : pinfo.mFromName;
	auto ttl = min(pinfo.mTtl, FIREBASE_MAX_TTL);

	// clang-format off
	StringFormater strFormatter(
		R"json({
	"to":"@to@",
	"time_to_live": @ttl@,
	"priority":"high",
	"data":{
		"uuid":"@uuid@",
		"from-uri":"@from-uri@",
		"display-name":"@display-name@",
		"call-id":"@call-id@",
		"sip-from":"@sip-from@",
		"loc-key":"@loc-key@",
		"loc-args":"@loc-args@",
		"send-time":"@send-time@"
	}
})json",
		'@', '@');

	std::map<std::string, std::string> values = {
		{"to", pinfo.mDeviceToken},
		{"ttl", to_string(ttl)},
		{"uuid", StringUtils::unquote(pinfo.mUid)},
		{"from-uri", pinfo.mFromUri},
		{"display-name", pinfo.mFromName},
		{"call-id", pinfo.mCallId},
		{"sip-from", from},
		{"loc-key", pinfo.mAlertMsgId},
		{"loc-args", from},
		{"send-time", getPushTimeStamp()}
	};
	// clang-format on

	auto formatedBody = strFormatter.format(values);

	mBody.assign(formatedBody.begin(), formatedBody.end());

	SLOGD << "Firebase request creation " << this << " payload is :\n" << formatedBody;

	HttpHeaders headers{};
	headers.add(":method", "POST");
	headers.add(":scheme", "https");
	headers.add(":path", "/fcm/send");
	headers.add(":authority", string(FirebaseClient::FIREBASE_ADDRESS) + ":" + string(FirebaseClient::FIREBASE_PORT));
	headers.add("content-type", "application/json");
	headers.add("authorization", "key=" + pinfo.mApiKey);
	this->setHeaders(headers);

	SLOGD << "Firebase request creation  " << this << " https headers are :\n" << headers.toString();
}

} // namespace pushnotification
} // namespace flexisip
