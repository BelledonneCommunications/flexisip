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

#include "pushnotification.hh"

#include <string.h>
#include <stdexcept>
#include <boost/asio.hpp>
#include <common.hh>

using namespace ::std;

const unsigned int ApplePushNotificationRequest::MAXPAYLOAD_SIZE = 256;
const unsigned int ApplePushNotificationRequest::DEVICE_BINARY_SIZE = 32;

ApplePushNotificationRequest::ApplePushNotificationRequest(const string & appid, const string &deviceToken, const string &msg_id, const string &arg, const string &sound, const string &callid) : PushNotificationRequest(appid) {
	ostringstream payload;
	int ret = formatDeviceToken(deviceToken);
	if ((ret != 0) || (mDeviceToken.size() != DEVICE_BINARY_SIZE)) {
		throw runtime_error("ApplePushNotification: Invalid deviceToken");
		return;
	}
	payload << "{\"aps\":{\"alert\":{\"loc-key\":\"" << msg_id << "\",\"loc-args\":[\"" << arg << "\"]},\"sound\":\"" << sound << "\"},\"call-id\":\""<<callid<<"\"}";
	if (payload.str().length() > MAXPAYLOAD_SIZE) {
		return;
	}
	mPayload = payload.str();
	LOGD("Push notification payload is %s", mPayload.c_str());
}

GooglePushNotificationRequest::GooglePushNotificationRequest(const string & appid, const string &deviceToken, const string &apiKey, const string &msg_id, const string &arg, const string &sound, const string &callid) : PushNotificationRequest(appid) {
	ostringstream httpBody;
	httpBody << "{\"registration_ids\":[\"" << deviceToken << "\"],\"data\":{\"loc-key\":\"" << msg_id << "\",\"loc-args\":\"" << arg << "\",\"sound\":\"" << sound << "\"}"
			",\"call-id\":\"" <<callid<< "\"}";
	mHttpBody = httpBody.str();
	LOGD("Push notification https post body is %s", mHttpBody.c_str());

	ostringstream httpHeader;
	httpHeader << "POST /gcm/send HTTP/1.1\r\nHost:android.googleapis.com\r\nContent-Type:application/json\r\nAuthorization:key=" << apiKey << "\r\nContent-Length:" << httpBody.str().size() << "\r\n\r\n";
	mHttpHeader = httpHeader.str();
	LOGD("Push notification https post header is %s", mHttpHeader.c_str());
	
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
