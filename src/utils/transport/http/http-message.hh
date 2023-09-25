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

#include <memory>
#include <string>

#include <nghttp2/nghttp2.h>

#include "http-headers.hh"
#include "ng-data-provider.hh"

namespace flexisip {

/**
 * Representation of any HTTP messages (request or response), fit HTTP and HTTP/2 messages.
 */
class HttpMessage {
public:
	class PrioritySpecification : public nghttp2_priority_spec {
	public:
		PrioritySpecification() {
			nghttp2_priority_spec_default_init(this);
		}
	};

	HttpMessage() = default;
	HttpMessage(const HttpHeaders& headers, const std::vector<char>& body) : mHeaders(headers), mBody(body){};
	HttpMessage(const HttpHeaders& headers, const std::string& body) : mHeaders(headers) {
		mBody.assign(body.cbegin(), body.cend());
	};
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

	/**
	 * WARNING: if you modify the body after a first call to getCDataProvider, the provider will be the same on the
	 * next call to getCDataProvider. Only call this when you are ready to send the request.
	 */
	const nghttp2_data_provider* getCDataProvider() {
		if (!mDataProvider) {
			mDataProvider = std::make_unique<NgDataProvider>(mBody);
		}

		return mDataProvider->getCStruct();
	}

	std::string toString() const noexcept;

	PrioritySpecification mPriority{};

protected:
	HttpHeaders mHeaders{};
	std::vector<char> mBody{};
	std::unique_ptr<NgDataProvider> mDataProvider{};
};

} // namespace flexisip
