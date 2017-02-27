
#include "applepush.hh"
#include "common.hh"
#include <sstream>
#include <string>
#include <stdexcept>

const unsigned int ApplePushNotificationRequest::MAXPAYLOAD_SIZE = 256;
const unsigned int ApplePushNotificationRequest::DEVICE_BINARY_SIZE = 32;
uint32_t ApplePushNotificationRequest::Identifier = 1;

ApplePushNotificationRequest::ApplePushNotificationRequest(const PushInfo &info)
: PushNotificationRequest(info.mAppId, "apple") {
	const std::string &deviceToken = info.mDeviceToken;
	const std::string &msg_id = info.mAlertMsgId;
	const std::string &arg = info.mFromName.empty() ? info.mFromUri : info.mFromName;
	const std::string &sound = info.mAlertSound;
	const std::string &callid = info.mCallId;
	std::ostringstream payload;

	int ret = formatDeviceToken(deviceToken);
	if ((ret != 0) || (mDeviceToken.size() != DEVICE_BINARY_SIZE)) {
		throw std::runtime_error("ApplePushNotification: Invalid deviceToken");
	}

	if (info.mSilent || msg_id == "IC_SIL") { 
		// silent push: just send "content-available=1", the device will figure out what's happening
		// We also need msg_id and callid in case the push is received but the device cannot register
		payload << "{\"aps\":{\"sound\":\"\", \"loc-key\":\"" << msg_id << "\", \"call-id\":\"" << callid << "\", \"content-available\":1},\"pn_ttl\":"<< info.mTtl <<"}";
	} else {

		payload << "{\"aps\":{\"alert\":{\"loc-key\":\"" << msg_id << "\",\"loc-args\":[\"" << arg
		<< "\"]},\"sound\":\"" << sound << "\"";
		/* some apps don't want the push to update the badge - but if they do,
		 we always put the badge value to 1 because we want to notify the user that
		 he/she has unread messages even if we do not know the exact count */
		payload << ",\"badge\":" << (info.mNoBadge ? 0 : 1);
		payload << "},\"call-id\":\"" << callid << "\",\"pn_ttl\":" << info.mTtl <<"}";
	}
	if (payload.str().length() > MAXPAYLOAD_SIZE) {
		return;
	}
	mPayload = payload.str();
	LOGD("Push notification payload is %s", mPayload.c_str());
}

int ApplePushNotificationRequest::formatDeviceToken(const std::string &deviceToken) {
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

const std::vector<char> &ApplePushNotificationRequest::getData() {
	unsigned int payloadLength = mPayload.length();

	/* Init */
	mBuffer.clear();
	/* message format is, |COMMAND|ID|EXPIRY|TOKENLEN|TOKEN|PAYLOADLEN|PAYLOAD| */
	mBuffer.resize(sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint16_t) + DEVICE_BINARY_SIZE + sizeof(uint16_t) + payloadLength);
	char *binaryMessageBuff = &mBuffer[0];
	char *binaryMessagePt = binaryMessageBuff;

	/* Compute PushNotification */

	uint8_t command = 1; /* command number. Use enhanced push notifs (cf http://redth.codes/the-problem-with-apples-push-notification-ser/) */
	uint16_t networkOrderTokenLength = htons(DEVICE_BINARY_SIZE);
	uint16_t networkOrderPayloadLength = htons(payloadLength);
	uint32_t expiry = time(0) + 31536000; /* expires in one year */
	uint32_t identifier = Identifier++; /* auto-increment identifier */

	/* command */
	*binaryMessagePt++ = command;

	/* identifier */
	memcpy(binaryMessagePt, &identifier, sizeof(identifier));
	binaryMessagePt += sizeof(identifier);

	/* expiry */
	memcpy(binaryMessagePt, &expiry, sizeof(expiry));
	binaryMessagePt += sizeof(expiry);

	/* token length network order */
	memcpy(binaryMessagePt, &networkOrderTokenLength, sizeof(networkOrderTokenLength));
	binaryMessagePt += sizeof(networkOrderTokenLength);

	/* device token */
	memcpy(binaryMessagePt, &mDeviceToken[0], DEVICE_BINARY_SIZE);
	binaryMessagePt += DEVICE_BINARY_SIZE;

	/* payload length network order */
	memcpy(binaryMessagePt, &networkOrderPayloadLength, sizeof(networkOrderPayloadLength));
	binaryMessagePt += sizeof(networkOrderPayloadLength);

	/* payload */
	memcpy(binaryMessagePt, &mPayload[0], payloadLength);
	binaryMessagePt += payloadLength;

	return mBuffer;
}

std::string ApplePushNotificationRequest::isValidResponse(const std::string &str) {
	// error response is COMMAND(1)|STATUS(1)|ID(4) in bytes
	if (str.length() >= 6) {
		uint8_t error = str[1];
		uint32_t identifier = (uint32_t)str[2];
		static const char* errorToString[] = {
			"No errors encountered",
			"Processing error",
			"Missing device token",
			"Missing topic",
			"Missing payload",
			"Invalid token size",
			"Invalid topic size",
			"Invalid payload size",
			"Invalid token",
		};
		std::stringstream ss;
		ss << "PNR " << this << " with identifier " << identifier << " failed with error "
		<< (int)error << " (" << (error>8 ? "unknown" : errorToString[error]) << ")";
		return ss.str();
	}
	return "";
}
