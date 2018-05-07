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

#include <string>
#include <vector>
#include <memory>

#include <sofia-sip/url.h>

struct PushInfo {
	enum Event { Call, Message };
	PushInfo() : mEvent(Event::Message), mNoBadge(false), mSilent(false){};
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
	std::string mAccessToken; // access token required by Microsoft to authenticate our server
	int mTtl; //Time to live of the push notification.
	bool mNoBadge; // Whether to display a badge on the application (ios specific).
	bool mSilent;
};

class PushNotificationRequest {
	public:
		enum State{
			NotSubmitted,
			InProgress,
			Successful,
			Failed
		};

		virtual ~PushNotificationRequest() {};

		const std::string &getAppIdentifier() {
			return mAppId;
		}
		const std::string &getType() {
			return mType;
		}
		virtual const std::vector<char> &getData() = 0;
		virtual std::string isValidResponse(const std::string &str) = 0;
		virtual bool isServerAlwaysResponding() = 0;
		State getState()const{
			return mState;
		}
		void setState(State state){
			mState = state;
		}
	protected:
		PushNotificationRequest(const std::string &appid, const std::string &type)
			: mState( NotSubmitted), mAppId(appid), mType(type) {
		}
	private:
		State mState;
		const std::string mAppId;
		const std::string mType;

};
