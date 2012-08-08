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

#include "pushnotification.h"

#include <string.h>
#include <stdexcept>
#include <boost/asio.hpp>

using namespace ::std;


ApplePushNotificationRequest::ApplePushNotificationRequest(const std::vector<char> &data) : mData(data) {

}

const int ApplePushNotificationRequest::MAXPAYLOAD_SIZE = 256;

ApplePushNotificationRequest::ApplePushNotificationRequest(const std::string &deviceToken, const std::string &payload) {
	std::vector<char> deviceData;
	int ret = formatDeviceToken(deviceToken, deviceData);
	if (ret != 0) {
		throw runtime_error("ApplePushNotification: Invalid deviceToken");
		return;
	}
	ret = createPushNotification(deviceData, payload, mData);
	if (ret != 0) {
		if (ret == -1) {
			throw runtime_error("ApplePushNotification: Invalid deviceToken");
		} else if (ret == -2) {
			throw runtime_error("ApplePushNotification: Too long payload");
		}
	}

}


const std::vector<char> ApplePushNotificationRequest::getData() const{
	return mData;
}

int ApplePushNotificationRequest::formatDeviceToken(const string &deviceToken, vector<char> &retVal) {
	char car = 0;
	char oct = 0;
	char val;

	retVal.clear();
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
			retVal.push_back(car);
		}
	}
	return 0;
}

int ApplePushNotificationRequest::createPushNotification(const vector<char> &deviceToken, const string &payload, vector<char> &retVal) {
	static const unsigned int DEVICE_BINARY_SIZE = 32;

	/* Inputs verifications */

	if (deviceToken.size() != DEVICE_BINARY_SIZE) {
		return -1;
	}

	int payloadLength = payload.length();
	if (payloadLength > MAXPAYLOAD_SIZE) {
		return -2;
	}

	/* Init */

	retVal.clear();
	/* message format is, |COMMAND|TOKENLEN|TOKEN|PAYLOADLEN|PAYLOAD| */
	retVal.resize(sizeof(uint8_t) + sizeof(uint16_t) + DEVICE_BINARY_SIZE + sizeof(uint16_t) + payloadLength);
	char *binaryMessageBuff = &retVal[0];
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
	memcpy(binaryMessagePt, &deviceToken[0], DEVICE_BINARY_SIZE);
	binaryMessagePt += DEVICE_BINARY_SIZE;

	/* payload length network order */
	memcpy(binaryMessagePt, &networkOrderPayloadLength, sizeof(uint16_t));
	binaryMessagePt += sizeof(uint16_t);

	/* payload */
	memcpy(binaryMessagePt, &payload[0], payloadLength);
	binaryMessagePt += payloadLength;

	return 0;
}
