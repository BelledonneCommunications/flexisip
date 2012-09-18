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
	const std::string &getAppIdentifier(){
		return mAppId;
	}
	virtual const std::vector<char> getData() = 0;
	virtual ~PushNotificationRequest() = 0;
private:
	const std::string mAppId;
protected:
	PushNotificationRequest(const std::string &appid) : mAppId(appid){};
};
inline PushNotificationRequest::~PushNotificationRequest() {
}

class ApplePushNotificationRequest: public PushNotificationRequest {
public:
	static const unsigned int MAXPAYLOAD_SIZE;
	static const unsigned int DEVICE_BINARY_SIZE;
	virtual const std::vector<char> getData();
	ApplePushNotificationRequest(const std::string & appId, const std::string &deviceToken, const std::string &msg_id, const std::string &arg, const std::string &sound);
	~ApplePushNotificationRequest() {};

protected:
	int formatDeviceToken(const std::string &deviceToken);
	std::vector<char> createPushNotification();

	std::vector<char> mDeviceToken;
	std::string mPayload;
};

class GooglePushNotificationRequest: public PushNotificationRequest {
public:
	virtual const std::vector<char> getData();
	GooglePushNotificationRequest(const std::string & appId, const std::string &deviceToken, const std::string &apiKey, const std::string &msg_id, const std::string &arg, const std::string &sound);
	~GooglePushNotificationRequest() {};

protected:
	std::vector<char> createPushNotification();

	std::string mHttpHeader;
	std::string mHttpBody;
};

#endif
