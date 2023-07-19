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

#include "generic-http2-request.hh"

#include "generic-utils.hh"

namespace flexisip::pushnotification {

GenericHttp2Request::GenericHttp2Request(PushType pType,
                                         const std::shared_ptr<const PushInfo>& pInfo,
                                         Method method,
                                         const std::string& host,
                                         const std::string& port,
                                         const std::string& authKey,
                                         std::string path,
                                         std::string urlParameters)
    : Request(pType, pInfo) {
	GenericUtils::substituteArgs(path, mPInfo, mPType, authKey);
	GenericUtils::substituteArgs(urlParameters, mPInfo, mPType, authKey);

	HttpHeaders headers{};
	headers.add(":method", method == Method::HttpPost ? "POST" : "GET");
	headers.add(":scheme", "https");
	headers.add(":path", "/" + path + (urlParameters.empty() ? "" : "?" + urlParameters));
	headers.add(":authority", host + ":" + port);
	headers.add("content-type", "text/plain");
	if (!mPInfo->mText.empty()) {
		headers.add("content-length", std::to_string(mPInfo->mText.size()));
		mBody.assign(mPInfo->mText.begin(), mPInfo->mText.end());
	} else {
		headers.add("content-length", "0");
	}
	this->setHeaders(headers);
}

} // namespace flexisip::pushnotification
