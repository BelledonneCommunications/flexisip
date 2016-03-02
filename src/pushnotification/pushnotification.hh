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
#ifndef PUSH_NOTIFICATION_H
#define PUSH_NOTIFICATION_H

#include <string>
#include <vector>
#include <memory>
#include <boost/concept_check.hpp>

#include <sofia-sip/url.h>

struct PushInfo {
	enum Event { Call, Message };
	PushInfo() : mEvent(Event::Message), mNoBadge(false){};
	Event mEvent; // Event to advertise: call or text message.
	std::string mType; // type of push notif: apple, google, wp
	std::string mAppId; // app id, as extracted from Contact
	std::string mDeviceToken; // device token, as extracted from Contact
	std::string mApiKey; // api key (magic number required for Google)
	std::string mAlertSound; // sound to play
	std::string mAlertMsgId; // ID of message to show to user
	std::string mFromName; // From's display name
	std::string mFromUri; // From's SIP uri
	std::string mFromTag; // From tag
	std::string mToUri;   // To SIP uri
	std::string mCallId;  // CallID
	std::string mText;	// Text of the chat message.
	std::string mUid; // The unique id as used in the ExtendedContact, if available
	bool mNoBadge; // Whether to display a badge on the application (ios specific).
};

class PushNotificationRequestCallback {
  public:
	virtual void onError(const std::string &msg) = 0;
};

class PushNotificationRequest : public PushNotificationRequestCallback {
  public:
	const std::string &getAppIdentifier() {
		return mAppId;
	}
	const std::string &getType() {
		return mType;
	}
	virtual const std::vector<char> &getData() = 0;
	virtual bool isValidResponse(const std::string &str) = 0;
	virtual bool serverResponseIsImmediate() = 0;
	virtual ~PushNotificationRequest() {}
	void setCallBack(const std::shared_ptr<PushNotificationRequestCallback> &cb) {
		mCallBack = cb;
	}
	std::shared_ptr<PushNotificationRequestCallback> &getCallBack() {
		return mCallBack;
	}
	virtual void onError(const std::string &msg) {
		mCallBack->onError(msg);
	}

  private:
	const std::string mAppId;
	const std::string mType;
	std::shared_ptr<PushNotificationRequestCallback> mCallBack;

  protected:
	PushNotificationRequest(const std::string &appid, const std::string &type)
		: mAppId(appid), mType(type), mCallBack({}) {
	}
};


class ErrorPushNotificationRequest : public PushNotificationRequest {
  public:
	ErrorPushNotificationRequest() : PushNotificationRequest("error", "error"), mBuffer() {}
	~ErrorPushNotificationRequest() {}
	
	virtual bool serverResponseIsImmediate() { return true; }
	virtual bool isValidResponse(const std::string &str) { return false; }
	virtual const std::vector<char> &getData() { return mBuffer; }
  protected:
	std::vector<char> mBuffer;
};


class GenericPushNotificationRequest : public PushNotificationRequest {
  public:

	GenericPushNotificationRequest(const PushInfo &pinfo, const url_t *url, const std::string &method);
	
	virtual ~GenericPushNotificationRequest() {}
	virtual bool serverResponseIsImmediate() { return true; }
	virtual const std::vector<char> &getData();
	virtual bool isValidResponse(const std::string &str);
  protected:
	std::string &substituteArgs(std::string &input, const PushInfo &pinfo);
	void createPushNotification();
	std::vector<char> mBuffer;
	std::string mHttpMessage;
};

#endif
