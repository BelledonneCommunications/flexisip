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

#include "pushnotification.hh"

#include <string.h>
#include <stdexcept>
#include <boost/asio.hpp>
#include "common.hh"

#include <iostream>

using namespace ::std;

const unsigned int ApplePushNotificationRequest::MAXPAYLOAD_SIZE = 256;
const unsigned int ApplePushNotificationRequest::DEVICE_BINARY_SIZE = 32;

ApplePushNotificationRequest::ApplePushNotificationRequest(const PushInfo &info)
: PushNotificationRequest(info.mAppId, "apple") {
	const string &deviceToken = info.mDeviceToken;
	const string &msg_id = info.mAlertMsgId;
	const string &arg = info.mFromName.empty() ? info.mFromUri : info.mFromName;
	const string &sound = info.mAlertSound;
	const string &callid = info.mCallId;
	ostringstream payload;

	int ret = formatDeviceToken(deviceToken);
	if ((ret != 0) || (mDeviceToken.size() != DEVICE_BINARY_SIZE)) {
		throw runtime_error("ApplePushNotification: Invalid deviceToken");
	}

	if( msg_id == "IC_SIL" ){ // silent push: just send "content-available=1", the device will figure out what's happening
		payload << "{\"aps\":{\"sound\":\"\", \"content-available\":1},\"pn_ttl\":60}"; // PN expiration set to 60 seconds.
	} else {

		payload << "{\"aps\":{\"alert\":{\"loc-key\":\"" << msg_id << "\",\"loc-args\":[\"" << arg << "\"]},\"sound\":\"" << sound << "\"";
		/* some apps don't want the push to update the badge - but if they do,
		we always put the badge value to 1 because we want to notify the user that
		he/she has unread messages even if we do not know the exact count */
		payload << ",\"badge\":" << (info.mNoBadge ? 0 : 1);
		payload << "},\"call-id\":\"" << callid << "\",\"pn_ttl\":60}"; // PN expiration set to 60 seconds.
	}
	if (payload.str().length() > MAXPAYLOAD_SIZE) {
		return;
	}
	mPayload = payload.str();
	LOGD("Push notification payload is %s", mPayload.c_str());
}


const vector<char> & ApplePushNotificationRequest::getData() {
	createPushNotification();
	return mBuffer;
}


int ApplePushNotificationRequest::formatDeviceToken(const string &deviceToken) {
	char car = 0;
	char oct = 0;
	char val;

	mDeviceToken.clear();
	for (unsigned int i = 0; i < deviceToken.length(); ++i) {
		char tokenCar = deviceToken[i];
		if (tokenCar >= '0' && tokenCar <= '9') {
			val = tokenCar - '0';
		} else if (tokenCar >= 'a' && tokenCar <= 'f') {
			val = tokenCar - 'a' + 10;
		} else if (tokenCar >= 'A' && tokenCar <= 'F') {
			val = tokenCar - 'A' + 10;
		} else if (tokenCar == ' ' || tokenCar == '\t') {
			continue;
		} else {
			return -1;
		}
		if (oct) {
			car |= val & 0x0f;
		} else {
			car = val << 4;
		}
		oct = 1 - oct;
		if (oct == 0) {
			mDeviceToken.push_back(car);
		}
	}
	return 0;
}

void ApplePushNotificationRequest::createPushNotification() {
	unsigned int payloadLength = mPayload.length();

	/* Init */
	mBuffer.clear();
	/* message format is, |COMMAND|TOKENLEN|TOKEN|PAYLOADLEN|PAYLOAD| */
	mBuffer.resize(sizeof(uint8_t) + sizeof(uint16_t) + DEVICE_BINARY_SIZE + sizeof(uint16_t) + payloadLength);
	char *binaryMessageBuff = &mBuffer[0];
	char *binaryMessagePt = binaryMessageBuff;

	/* Compute PushNotification */

	uint8_t command = 0; /* command number */
	uint16_t networkOrderTokenLength = htons(DEVICE_BINARY_SIZE);
	uint16_t networkOrderPayloadLength = htons(payloadLength);

	/* command */
	*binaryMessagePt++ = command;

	/* token length network order */
	memcpy(binaryMessagePt, &networkOrderTokenLength, sizeof(uint16_t));
	binaryMessagePt += sizeof(uint16_t);

	/* device token */
	memcpy(binaryMessagePt, &mDeviceToken[0], DEVICE_BINARY_SIZE);
	binaryMessagePt += DEVICE_BINARY_SIZE;

	/* payload length network order */
	memcpy(binaryMessagePt, &networkOrderPayloadLength, sizeof(uint16_t));
	binaryMessagePt += sizeof(uint16_t);

	/* payload */
	memcpy(binaryMessagePt, &mPayload[0], payloadLength);
	binaryMessagePt += payloadLength;
}

bool ApplePushNotificationRequest::isValidResponse(const string &str) {
	return true;
}

GooglePushNotificationRequest::GooglePushNotificationRequest(const PushInfo &pinfo)
: PushNotificationRequest(pinfo.mAppId, "google") {
	const string &deviceToken = pinfo.mDeviceToken;
	const string &apiKey = pinfo.mApiKey;
	const string &arg = pinfo.mFromName.empty() ? pinfo.mFromUri : pinfo.mFromName;
	const string &callid = pinfo.mCallId;
	ostringstream httpBody;
	httpBody << "{\"registration_ids\":[\"" << deviceToken << "\"],\"data\":{\"loc-args\":\"" << arg << "\"}"
			",\"call-id\":\"" <<callid<< "\"}";
	mHttpBody = httpBody.str();
	LOGD("Push notification https post body is %s", mHttpBody.c_str());

	ostringstream httpHeader;
	httpHeader << "POST /gcm/send HTTP/1.1\r\nHost:android.googleapis.com\r\nContent-Type:application/json\r\nAuthorization:key=" << apiKey << "\r\nContent-Length:" << httpBody.str().size() << "\r\n\r\n";
	mHttpHeader = httpHeader.str();
	SLOGD << "PNR " << this << " https post header is " << mHttpHeader;
}

void GooglePushNotificationRequest::createPushNotification() {
	int headerLength = mHttpHeader.length();
	int bodyLength = mHttpBody.length();

	mBuffer.clear();
	mBuffer.resize(headerLength + bodyLength);

	char *binaryMessageBuff = &mBuffer[0];
	char *binaryMessagePt = binaryMessageBuff;

	memcpy(binaryMessagePt, &mHttpHeader[0], headerLength);
	binaryMessagePt += headerLength;

	memcpy(binaryMessagePt, &mHttpBody[0], bodyLength);
	binaryMessagePt += bodyLength;
}

const vector<char> & GooglePushNotificationRequest::getData() {
	createPushNotification();
	return mBuffer;
}

bool GooglePushNotificationRequest::isValidResponse(const string &str) {
	static const char expected[] = "HTTP/1.1 200";
	return strncmp(expected, str.c_str(), sizeof(expected) -1) == 0;
}


WindowsPhonePushNotificationRequest::WindowsPhonePushNotificationRequest(const PushInfo &pinfo)
: PushNotificationRequest(pinfo.mAppId, "wp") {
	const string &host = pinfo.mAppId;
	const string &query = pinfo.mDeviceToken;
	bool is_message = pinfo.mEvent == PushInfo::Message;
	const std::string &message = pinfo.mText;
	const std::string &sender_name = pinfo.mFromName;
	const std::string &sender_uri = pinfo.mFromUri;
	ostringstream httpBody;
	if (is_message) {
		// We have to send the content of the message and the name of the sender.
		// We also need the sender address to be able to display the full chat view in case the receiver click the toast.
		httpBody << "<?xml version=\"1.0\" encoding=\"utf-8\"?><wp:Notification xmlns:wp=\"WPNotification\"><wp:Toast><wp:Text1>" << sender_name << "</wp:Text1><wp:Text2>" << message << "</wp:Text2><wp:Param>" << "/Views/Chat.xaml?sip=" << sender_uri << "</wp:Param></wp:Toast></wp:Notification>";
	} else {
		// No need to specify name or number, this PN will only wake up linphone.
		httpBody << "<?xml version=\"1.0\" encoding=\"utf-8\"?><IncomingCall><Name></Name><Number></Number></IncomingCall>";
	}
	mHttpBody = httpBody.str();
	LOGD("Push notification https post body is %s", mHttpBody.c_str());

	ostringstream httpHeader;
	if (is_message) {
		// Notification class 2 is the type for toast notifitcation.
		httpHeader << "POST " << query << " HTTP/1.1\r\nHost:" << host <<"\r\nX-WindowsPhone-Target:toast\r\nX-NotificationClass:2\r\nContent-Type:text/xml\r\nContent-Length:" << httpBody.str().size() << "\r\n\r\n";
	} else {
		// Notification class 4 is the type for VoIP incoming call.
		httpHeader << "POST " << query << " HTTP/1.1\r\nHost:" << host <<"\r\nX-NotificationClass:4\r\nContent-Type:text/xml\r\nContent-Length:" << httpBody.str().size() << "\r\n\r\n";
	}
	mHttpHeader = httpHeader.str();
	SLOGD << "PNR " << this << " https post header is " << mHttpHeader;
}

void WindowsPhonePushNotificationRequest::createPushNotification() {
	int headerLength = mHttpHeader.length();
	int bodyLength = mHttpBody.length();

	mBuffer.clear();
	mBuffer.resize(headerLength + bodyLength);

	char *binaryMessageBuff = &mBuffer[0];
	char *binaryMessagePt = binaryMessageBuff;

	memcpy(binaryMessagePt, &mHttpHeader[0], headerLength);
	binaryMessagePt += headerLength;

	memcpy(binaryMessagePt, &mHttpBody[0], bodyLength);
	binaryMessagePt += bodyLength;
}

const vector<char> & WindowsPhonePushNotificationRequest::getData() {
	createPushNotification();
	return mBuffer;
}

bool WindowsPhonePushNotificationRequest::isValidResponse(const string &str) {
	string line;
	istringstream iss(str);
	bool connect, notif, subscr = notif = connect = false;
	while (getline(iss, line)) {
		if (!connect) connect = line.find("X-DeviceConnectionStatus: Connected") != string::npos;
		if (!notif) notif = line.find("X-NotificationStatus: Received") != string::npos;
		if (!subscr) subscr = line.find("X-SubscriptionStatus: Active") != string::npos;
	}

	return connect && notif && subscr;
}

bool ErrorPushNotificationRequest::isValidResponse(const string &str) {
	return false;
}
