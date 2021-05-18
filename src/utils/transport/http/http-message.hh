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

#pragma once

#include <string>

#include "http-headers.hh"

namespace flexisip {

/**
 * Representation of any HTTP messages (request or response), fit HTTP and HTTP/2 messages.
 */
class HttpMessage {
public:
	HttpMessage() = default;
	HttpMessage(const HttpHeaders& headers, const std::vector<char>& body) : mHeaders(headers), mBody(body){};
	virtual ~HttpMessage() = default;

	const std::vector<char>& getBody() const {
		return mBody;
	}

	void setBody(const std::vector<char>& body) {
		this->mBody = body;
	}

	void appendBody(const std::string& body) {
		this->mBody.insert(mBody.end(), body.begin(), body.end());
	}

	const HttpHeaders& getHeaders() const {
		return mHeaders;
	}

	HttpHeaders& getHeaders() {
		return mHeaders;
	}

	void setHeaders(const HttpHeaders& headers) {
		this->mHeaders = headers;
	}

	std::string toString() const noexcept;

protected:
	HttpHeaders mHeaders{};
	std::vector<char> mBody{};
};

} // namespace flexisip
