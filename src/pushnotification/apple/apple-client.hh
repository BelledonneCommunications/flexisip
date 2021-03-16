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

#include "apple-request.hh"
#include "pushnotification/client.hh"
#include "utils/transport/http/http-message.hh"
#include "utils/transport/http/http-response.hh"
#include "utils/transport/http/http2client.hh"
#include "utils/transport/tls-connection.hh"

namespace flexisip {
namespace pushnotification {

class AppleClient : public Client {
  public:
	AppleClient(su_root_t& root, const std::string& trustStorePath, const std::string& certPath,
				const std::string& certName);

	void sendPush(const std::shared_ptr<Request>& req) override;
	bool isIdle() const noexcept override {
		return mHttp2Client->isIdle();
	}

  private:
	void onResponse(const std::shared_ptr<HttpMessage>& request, const std::shared_ptr<HttpResponse>& response);
	void onError(const std::shared_ptr<HttpMessage>& request);

	std::string mLogPrefix{};
	std::unique_ptr<Http2Client> mHttp2Client;

	static constexpr const char* APN_DEV_ADDRESS = "api.development.push.apple.com";
	static constexpr const char* APN_PROD_ADDRESS = "api.push.apple.com";
	static constexpr const char* APN_PORT = "443";
};

} // namespace pushnotification
} // namespace flexisip