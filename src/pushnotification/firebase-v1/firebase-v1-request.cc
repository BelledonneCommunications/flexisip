/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include "firebase-v1-request.hh"

#include <chrono>
#include <map>
#include <memory>
#include <string>

#include "firebase-v1-client.hh"
#include "flexisip/logmanager.hh"
#include "utils/string-formatter.hh"
#include "utils/string-utils.hh"

using namespace std;

namespace flexisip::pushnotification {

FirebaseV1Request::FirebaseV1Request(PushType pType,
                                     const std::shared_ptr<const PushInfo>& pInfo,
                                     std::string_view projectId)
    : Request{pType, pInfo}, mProjectId(projectId) {
	const string& from = mPInfo->mFromName.empty() ? mPInfo->mFromUri : mPInfo->mFromName;
	auto ttl = min(mPInfo->mTtl, FIREBASE_MAX_TTL);

	// clang-format off
	StringFormatter strFormatter(
	R"json({
	"message":{
		"token": "@to@",
		"android":{
			"priority": "high",
			"ttl": "@ttl@s",
			"data":{
				"uuid":"@uuid@",
				"from-uri":"@from-uri@",
				"display-name":"@display-name@",
				"call-id":"@call-id@",
				"sip-from":"@sip-from@",
				"loc-key":"@loc-key@",
				"loc-args":"@loc-args@",
				"send-time":"@send-time@",
				"custom-payload":"@custom-payload@"
			}
		}
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
		{"custom-payload", StringUtils::searchAndReplace(customPayload, R"(")", R"(\")")},
	};
	// clang-format on

	auto formattedBody = strFormatter.format(values);

	mBody.assign(formattedBody.begin(), formattedBody.end());

	SLOGD << "FirebaseV1 request[" << this << "] creation, payload:\n" << formattedBody;

	HttpHeaders headers{};
	headers.add(":method", "POST");
	headers.add(":scheme", "https");
	headers.add(":path", "/v1/projects/" + mProjectId + "/messages:send");
	headers.add(":authority", FirebaseV1Client::FIREBASE_ADDRESS + ":" + FirebaseV1Client::FIREBASE_PORT);
	headers.add("content-type", "application/json");
	this->setHeaders(headers);

	SLOGD << "FirebaseV1 request[" << this << "] creation, headers:\n" << headers.toString();
}

} // namespace flexisip::pushnotification
