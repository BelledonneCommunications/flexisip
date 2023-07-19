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
 * PNR (Push Notification Request) client designed to send push notification toa custom push API.
 */
class GenericHttp2Client : public Client {
public:
	GenericHttp2Client(const sofiasip::Url& url, Method method, sofiasip::SuRoot& root, Service* pushService = nullptr);

	void sendPush(const std::shared_ptr<Request>& request) override;
	std::shared_ptr<Request> makeRequest(flexisip::pushnotification::PushType,
	                                     const std::shared_ptr<const PushInfo>&,
	                                     const std::map<std::string, std::shared_ptr<Client>>& = {}) override;

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
	Method mMethod;
};

} // namespace flexisip::pushnotification
