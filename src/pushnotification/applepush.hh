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

#ifndef _APPLE_PUSH_H_
#define _APPLE_PUSH_H

#include "pushnotification.hh"


class ApplePushNotificationRequest : public PushNotificationRequest {
public:
	static const unsigned int MAXPAYLOAD_SIZE;
	static const unsigned int DEVICE_BINARY_SIZE;
	virtual const std::vector<char> &getData();
	virtual bool isValidResponse(const std::string &str);
	ApplePushNotificationRequest(const PushInfo &pinfo);
	~ApplePushNotificationRequest() {
	}
	virtual bool serverResponseIsImmediate() {
		return false;
	}

protected:
	int formatDeviceToken(const std::string &deviceToken);
	void createPushNotification();
	std::vector<char> mBuffer;
	std::vector<char> mDeviceToken;
	std::string mPayload;
	static uint32_t Identifier;
};

#endif
