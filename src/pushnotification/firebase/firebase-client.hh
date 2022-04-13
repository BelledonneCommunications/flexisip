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

#pragma once

#include <string>

#include "firebase-request.hh"
#include "pushnotification/client.hh"
#include "utils/transport/http/http-message.hh"
#include "utils/transport/http/http-response.hh"
#include "utils/transport/http/http2client.hh"
#include "utils/transport/tls-connection.hh"

namespace flexisip {
namespace pushnotification {

/**
 * PNR (Push Notification Request) client designed to send push notification to the Firebase push API.
 */
class FirebaseClient : public Client {
public:
	FirebaseClient(su_root_t& root, const Service* service = nullptr);

	/**
	 * Send the request to the Firebase PNR server. If the request succeed, if a response is received, the
	 * FirebaseClient::onResponse method is called. If the request failed, no response/timeout, tls/handshake errors...
	 * the FirebaseClient::onError method is called.
	 *
	 * @param req The request to send, this MUST be of FirebaseRequest type.
	 */
	void sendPush(const std::shared_ptr<Request>& req) override;
	bool isIdle() const noexcept override {
		return mHttp2Client->isIdle();
	}

	void enableInsecureTestMode() {
		mHttp2Client->enableInsecureTestMode();
	}

	static std::string FIREBASE_ADDRESS;
	static std::string FIREBASE_PORT;

private:
	void onResponse(const std::shared_ptr<HttpMessage>& request, const std::shared_ptr<HttpResponse>& response);
	void onError(const std::shared_ptr<HttpMessage>& request);

	std::unique_ptr<Http2Client> mHttp2Client;
	std::string mLogPrefix{};
};

} // namespace pushnotification
} // namespace flexisip
