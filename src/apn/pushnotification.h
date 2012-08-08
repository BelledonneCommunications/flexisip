/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2012  Belledonne Communications SARL.

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

#ifndef PUSH_NOTIFICATION_H
#define PUSH_NOTIFICATION_H

#include <string>
#include <vector>

class PushNotificationRequest {
public:
	virtual const std::vector<char> getData() const = 0;
	virtual ~PushNotificationRequest() = 0;
};
inline PushNotificationRequest::~PushNotificationRequest() {
}

class ApplePushNotificationRequest: public PushNotificationRequest {
public:
	static const int MAXPAYLOAD_SIZE;
	virtual const std::vector<char> getData() const;
	ApplePushNotificationRequest(const std::vector<char> &data);
	ApplePushNotificationRequest(const std::string &deviceToken, const std::string &payload);
	~ApplePushNotificationRequest() {};
private:

	static int formatDeviceToken(const std::string &deviceToken, std::vector<char> &retVal);
	static int createPushNotification(const std::vector<char> &deviceToken, const std::string &payload, std::vector<char> &retVal);

private:
	std::vector<char> mData;
};

#endif
