/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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
const std::chrono::seconds FirebaseRequest::FIREBASE_MAX_TTL{4 * 7 * 24 * 3600}; // 4 weeks

FirebaseRequest::FirebaseRequest(PushType pType, const std::shared_ptr<const PushInfo>& pInfo) : Request{pType, pInfo} {
	const string& from = mPInfo->mFromName.empty() ? mPInfo->mFromUri : mPInfo->mFromName;
	auto ttl = min(mPInfo->mTtl, FIREBASE_MAX_TTL);

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
		"custom-payload":@custom-payload@
	}
})json",
		'@', '@');

	auto customPayload = mPInfo->mCustomPayload.empty() ? "{}"s : mPInfo->mCustomPayload;
	std::map<std::string, std::string> values = {
		{"to", getDestination().getPrid()},
		{"ttl", to_string(ttl.count())},
		{"uuid", StringUtils::unquote(mPInfo->mUid)},
		{"from-uri", mPInfo->mFromUri},
		{"display-name", mPInfo->mFromName},
		{"call-id", mPInfo->mCallId},
		{"sip-from", from},
		{"loc-key", mPInfo->mAlertMsgId},
		{"loc-args", from},
		{"send-time", getPushTimeStamp()},
		{"custom-payload", customPayload},
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
	this->setHeaders(headers);

	SLOGD << "Firebase request creation  " << this << " https headers are :\n" << headers.toString();
}

} // namespace pushnotification
} // namespace flexisip
