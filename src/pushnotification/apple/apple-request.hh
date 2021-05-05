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

#include "pushnotification/request.hh"
#include "utils/transport/http/http-message.hh"

namespace flexisip {
namespace pushnotification {

/**
 * This class represent one Apple push notification request. This class inherits from Request, so it can be treated
 * like another type of PNR by the flexisip push notification module, and from HttpMessage so it can be sent by the
 * Http2Client.
 */
class AppleRequest : public Request, public HttpMessage {
public:
	AppleRequest(const PushInfo& pinfo);

	const std::string& getDeviceToken() const noexcept {
		return mDeviceToken;
	}

	std::string isValidResponse(const std::string& str) override {
		return std::string{};
	}

	bool isServerAlwaysResponding() override {
		return false;
	}

	[[deprecated("Here for compatibility issue, use getBody() instead")]] const std::vector<char>& getData() override {
		return mBody;
	}

protected:
	void checkDeviceToken() const;
	static std::string pushTypeToApnsPushType(ApplePushType type);

	ApplePushType mPayloadType{ApplePushType::Unknown};
	std::string mDeviceToken{};
	std::string mReason{};
	int mStatusCode{0};

	static constexpr std::size_t MAXPAYLOAD_SIZE = 2048;
	static constexpr std::size_t DEVICE_BINARY_SIZE = 32;

	friend class AppleClient;
};

} // namespace pushnotification
} // namespace flexisip
