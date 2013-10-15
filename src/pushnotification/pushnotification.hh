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
#include <memory>

class PushNotificationRequestCallback {
public:
	virtual void onError(const std::string &msg) = 0;
};

class PushNotificationRequest : public PushNotificationRequestCallback {
public:
	const std::string &getAppIdentifier(){
		return mAppId;
	}
	const std::string &getType(){
		return mType;
	}
	virtual const std::vector<char> &getData() = 0;
	virtual bool isValidResponse(const std::string &str) = 0;
	virtual bool mustReadServerResponse() = 0;
	virtual ~PushNotificationRequest() = 0;
	void setCallBack(const std::shared_ptr<PushNotificationRequestCallback> &cb) { mCallBack = cb; }
	std::shared_ptr<PushNotificationRequestCallback> &getCallBack() { return mCallBack; }
	virtual void onError(const std::string &msg) { mCallBack->onError(msg); }
private:
	const std::string mAppId;
	const std::string mType;
	std::shared_ptr<PushNotificationRequestCallback> mCallBack;
protected:
	PushNotificationRequest(const std::string &appid, const std::string &type)
	: mAppId(appid), mType(type), mCallBack({}) {}
};
inline PushNotificationRequest::~PushNotificationRequest() {
}

class ApplePushNotificationRequest: public PushNotificationRequest {
public:
	static const unsigned int MAXPAYLOAD_SIZE;
	static const unsigned int DEVICE_BINARY_SIZE;
	virtual const std::vector<char> &getData();
	virtual bool isValidResponse(const std::string &str);
	ApplePushNotificationRequest(const std::string & appId, const std::string &deviceToken, const std::string &msg_id, const std::string &arg, const std::string &sound, const std::string &callid);
	~ApplePushNotificationRequest() {};
	virtual bool mustReadServerResponse() { return false; }

protected:
	int formatDeviceToken(const std::string &deviceToken);
	void createPushNotification();
	std::vector<char> mBuffer;
	std::vector<char> mDeviceToken;
	std::string mPayload;
};

class GooglePushNotificationRequest: public PushNotificationRequest {
public:
	virtual const std::vector<char> & getData();
	virtual bool isValidResponse(const std::string &str);
	GooglePushNotificationRequest(const std::string &appId, const std::string &deviceToken, const std::string &apiKey, const std::string &arg, const std::string &callid);
	~GooglePushNotificationRequest() {};
	virtual bool mustReadServerResponse() { return true; }

protected:
	void createPushNotification();
	std::vector<char> mBuffer;
	std::string mHttpHeader;
	std::string mHttpBody;
};

class WindowsPhonePushNotificationRequest: public PushNotificationRequest {
public:
	virtual const std::vector<char> & getData();
	virtual bool isValidResponse(const std::string &str);
	WindowsPhonePushNotificationRequest(const std::string &host, const std::string &query, bool is_message, const std::string &message, const std::string &sender_name, const std::string &sender_uri);
	~WindowsPhonePushNotificationRequest() {};
	virtual bool mustReadServerResponse() { return true; }

protected:
	void createPushNotification();
	std::vector<char> mBuffer;
	std::string mHttpHeader;
	std::string mHttpBody;
};

class ErrorPushNotificationRequest: public PushNotificationRequest {
public:
	virtual const std::vector<char> & getData() { return mBuffer; };
	virtual bool isValidResponse(const std::string &str);
	ErrorPushNotificationRequest()
	: PushNotificationRequest("error", "error"), mBuffer() {}
	~ErrorPushNotificationRequest() {}
	virtual bool mustReadServerResponse() { return true; }

protected:
	std::vector<char> mBuffer;
};

#endif
