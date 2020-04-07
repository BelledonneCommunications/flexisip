/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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

#include "pushnotification.hh"

namespace flexisip {

class ApplePushNotificationRequest : public PushNotificationRequest {
public:
	ApplePushNotificationRequest(const PushInfo &pinfo);

	const std::vector<char> &getData() override;
	std::string isValidResponse(const std::string &str) override;
	bool isServerAlwaysResponding() override {return false;}

protected:
	struct Item{
		uint8_t mId{0};
		std::vector<char> mData;

		void clear() noexcept {mData.clear();}
	};

	int formatDeviceToken(const std::string &deviceToken);
	void createPushNotification();
	std::size_t writeItem(std::size_t pos, const Item &item);

	static constexpr std::size_t MAXPAYLOAD_SIZE = 2048;
	static constexpr std::size_t DEVICE_BINARY_SIZE = 32;
	std::vector<char> mBuffer;
	std::vector<char> mDeviceToken;
	std::string mPayload;
	unsigned int mTtl{0};
	static uint32_t sIdentifier;
};

}
