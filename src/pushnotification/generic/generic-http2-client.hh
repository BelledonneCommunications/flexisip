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

#pragma once

#include <string>

#include "generic-http2-request.hh"
#include "pushnotification/client.hh"
#include "utils/transport/http/http-message.hh"
#include "utils/transport/http/http-response.hh"
#include "utils/transport/http/http2client.hh"
#include "utils/transport/tls-connection.hh"

namespace flexisip::pushnotification {

/**
 * PNR (Push Notification Request) client designed to send push notification to a custom push API.
 */
class GenericHttp2Client : public Client {
public:
	GenericHttp2Client(const sofiasip::Url& url, Method method, sofiasip::SuRoot& root, Service* pushService = nullptr);

	/**
	 * Create a HTTP client to send push notification through an API that requires a JSON body.
	 */
	GenericHttp2Client(const sofiasip::Url& url,
	                   const std::string& apiKey,
	                   JsonBodyGenerationFunc&& jsonBodyGenerationFunc,
	                   sofiasip::SuRoot& root,
	                   Service* pushService = nullptr,
	                   const std::shared_ptr<Http2Client>& http2Client = nullptr);

	void sendPush(const std::shared_ptr<Request>& request) override;
	std::shared_ptr<Request> makeRequest(PushType, const std::shared_ptr<const PushInfo>&) override;

	bool isIdle() const noexcept override {
		return mHttp2Client->isIdle();
	}

	void enableInsecureTestMode() {
		mHttp2Client->enableInsecureTestMode();
	}

	void setRequestTimeout(std::chrono::seconds requestTimeout) override {
		mHttp2Client->setRequestTimeout(requestTimeout);
	}

	const std::shared_ptr<Http2Client>& getHttp2Client() const {
		return mHttp2Client;
	}

private:
	void onResponse(const std::shared_ptr<HttpMessage>& request, const std::shared_ptr<HttpResponse>& response);
	void onError(const std::shared_ptr<HttpMessage>& request);

	std::shared_ptr<Http2Client> mHttp2Client;
	std::string mLogPrefix{};
	std::string mHost{};
	std::string mPort{};
	std::string mPath{};
	std::string mUrlParameters{};
	std::string mApiKey{};
	Method mMethod;
	JsonBodyGenerationFunc mJsonBodyGenerationFunc{};
};

} // namespace flexisip::pushnotification