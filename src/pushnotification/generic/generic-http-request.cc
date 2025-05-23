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

#include "generic-http-request.hh"

#include <iostream>
#include <stdexcept>

#include "pushnotification/generic/generic-utils.hh"
#include "pushnotification/service.hh"

using namespace std;

namespace flexisip::pushnotification {

std::string GenericHttpRequest::getAppIdentifier() const noexcept {
	return Service::kExternalClientName;
}

const std::vector<char>& GenericHttpRequest::getData(const sofiasip::Url& url, Method method) {
	if (mLogPrefix.empty()) mLogPrefix = LogManager::makeLogPrefixForInstance(this, "GenericHttpRequest");
	auto methodStr = method == Method::HttpPost ? "POST" : "GET";
	auto host = url.getHost();
	auto port = url.getPort();
	auto path = url.getPath();
	auto headers = url.getHeaders();

	GenericUtils::substituteArgs(path, mPInfo, mPType);
	GenericUtils::substituteArgs(headers, mPInfo, mPType);

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
	LOGD << "Http message is: " << httpMessageStr;
	mBuffer.assign(httpMessageStr.cbegin(), httpMessageStr.cend());
	return mBuffer;
}

std::string GenericHttpRequest::isValidResponse([[maybe_unused]] const std::string& str) {
	return "";
}

} // namespace flexisip::pushnotification