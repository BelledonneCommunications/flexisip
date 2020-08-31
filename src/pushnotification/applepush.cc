
#include "applepush.hh"
#include <flexisip/common.hh>
#include <sstream>
#include <string>
#include <stdexcept>

using namespace std;

namespace flexisip {
namespace pushnotification {

uint32_t AppleRequest::sIdentifier = 1;

AppleRequest::AppleRequest(const PushInfo &info) : Request(info.mAppId, "apple") {
	const string &deviceToken = info.mDeviceToken;
	const string &msg_id = info.mAlertMsgId;
	const string &arg = info.mFromName.empty() ? info.mFromUri : info.mFromName;
	const string &sound = info.mAlertSound;
	const string &callid = info.mCallId;
	string date = getPushTimeStamp();

	const char *rawPayload;
	size_t bufferMaxSize = MAXPAYLOAD_SIZE + 1;
	char buffer[bufferMaxSize];
	int returnCode = 0;

	int ret = formatDeviceToken(deviceToken);
	if ((ret != 0) || (mDeviceToken.size() != DEVICE_BINARY_SIZE)) {
		throw runtime_error("ApplePushNotification: Invalid deviceToken");
	}
	mTtl = info.mTtl;

	switch (info.mApplePushType) {
		case PushInfo::ApplePushType::Pushkit:
		// We also need msg_id and callid in case the push is received but the device cannot register
		rawPayload = R"json({
			"aps": {
				"sound": "",
				"loc-key": "%s",
				"loc-args": ["%s"],
				"call-id": "%s",
				"uuid": %s,
				"send-time": "%s"
			},
			"from-uri": "%s",
			"display-name": "%s",
			"pn_ttl": %d
		})json";
		returnCode = snprintf(buffer, bufferMaxSize, rawPayload,
			msg_id.c_str(),
			arg.c_str(),
			callid.c_str(),
			quoteStringIfNeeded(info.mUid).c_str(),
			date.c_str(),
			info.mFromUri.c_str(),
			info.mFromName.c_str(),
			info.mTtl
		);
		break;
	case PushInfo::ApplePushType::Background:
		// Use a normal push notification with content-available set to 1, no alert, no sound.
		rawPayload = R"json({
			"aps": {
				"badge": 0,
				"content-available": 1,
				"loc-key": "%s",
				"loc-args": ["%s"],
				"call-id": "%s",
				"uuid": %s,
				"send-time": "%s"
			},
			"from-uri": "%s",
			"display-name": "%s",
			"pn_ttl": %d
		})json";
		returnCode = snprintf(buffer, bufferMaxSize, rawPayload,
			msg_id.c_str(),
			arg.c_str(),
			callid.c_str(),
			quoteStringIfNeeded(info.mUid).c_str(),
			date.c_str(),
			info.mFromUri.c_str(),
			info.mFromName.c_str(),
			info.mTtl
		);
		break;
	case PushInfo::ApplePushType::RemoteBasic:
		/* some apps don't want the push to update the badge - but if they do,
		we always put the badge value to 1 because we want to notify the user that
		he/she has unread messages even if we do not know the exact count */
		rawPayload = R"json({
			"aps": {
				"alert": {
					"loc-key": "%s",
					"loc-args": ["%s"]
				},
				"sound": "%s",
				"badge": %d
			},
			"from-uri": "%s",
			"display-name": "%s",
			"call-id": "%s",
			"pn_ttl": %d,
			"uuid": %s,
			"send-time": "%s"
		})json";
		returnCode = snprintf(buffer, bufferMaxSize, rawPayload,
			msg_id.c_str(),
			arg.c_str(),
			sound.c_str(),
			(info.mNoBadge ? 0 : 1),
			info.mFromUri.c_str(),
			info.mFromName.c_str(),
			callid.c_str(),
			info.mTtl,
			quoteStringIfNeeded(info.mUid).c_str(),
			date.c_str()
		);
		break;
	case PushInfo::ApplePushType::RemoteWithMutableContent:
		/* some apps don't want the push to update the badge - but if they do,
		we always put the badge value to 1 because we want to notify the user that
		he/she has unread messages even if we do not know the exact count */
		rawPayload = R"json({
			"aps": {
				"alert": {
					"loc-key": "%s",
					"loc-args": ["%s"]
				},
				"sound": "%s",
				"mutable-content": 1,
				"badge": %d
			},
			"from-uri": "%s",
			"display-name": "%s",
			"call-id": "%s",
			"pn_ttl": %d,
			"uuid": %s,
			"send-time": "%s",
			"chat-room-addr": "%s"
		})json";
		returnCode = snprintf(buffer, bufferMaxSize, rawPayload,
			msg_id.c_str(),
			arg.c_str(),
			sound.c_str(),
			(info.mNoBadge ? 0 : 1),
			info.mFromUri.c_str(),
			info.mFromName.c_str(),
			callid.c_str(),
			info.mTtl,
			quoteStringIfNeeded(info.mUid).c_str(),
			date.c_str(),
			info.mChatRoomAddr.c_str()
		);
		break;
	}

	mPayload = buffer;
	SLOGD << "PNR " << this << " payload is " << mPayload;
	if (returnCode < 0 || returnCode >= (int)bufferMaxSize) {
		SLOGE << "PNR " << this << " cannot be sent because the payload size is higher than " << MAXPAYLOAD_SIZE;
		mPayload.clear();
		return;
	}
}

int AppleRequest::formatDeviceToken(const string &deviceToken) {
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

std::size_t AppleRequest::writeItem(std::size_t pos, const Item& item)
{
	size_t newSize = pos + sizeof(uint8_t) + sizeof(uint16_t) + item.mData.size();
	uint16_t itemSize = htons((uint16_t)item.mData.size());
	if (mBuffer.size()<newSize){
		mBuffer.resize(newSize);
	}
	mBuffer[pos] = item.mId;
	pos++;
	memcpy(&mBuffer[pos], &itemSize, sizeof(uint16_t));
	pos += sizeof(uint16_t);
	memcpy(&mBuffer[pos], &item.mData[0], item.mData.size());
	pos += item.mData.size();
	return pos;
}

const vector<char> &AppleRequest::getData() {
	size_t pos = 0;
	uint32_t frameSize;
	/* Init */
	mBuffer.clear();
	mBuffer.resize(sizeof(uint8_t) + sizeof(frameSize));

	mBuffer[pos] = 2;
	pos += sizeof(uint8_t);
	//the frame size will be written at the end of the processing
	pos += sizeof(frameSize);

	//now write items

	//device token item:
	Item item;
	item.mId = 1;
	item.mData = mDeviceToken;
	pos = writeItem(pos, item);

	//payload item:
	item.clear();
	item.mId = 2;
	item.mData.assign(mPayload.begin(), mPayload.end());
	pos = writeItem(pos, item);

	//Notification identifier
	item.clear();
	item.mId = 3;
	item.mData.resize(sizeof(sIdentifier));
	memcpy(&item.mData[0], &sIdentifier, sizeof(sIdentifier));
	pos = writeItem(pos, item);

	//Expiration date item
	item.clear();
	item.mId = 4;
	uint32_t expires = htonl((uint32_t)(time(NULL) + mTtl));
	item.mData.resize(sizeof(expires));
	memcpy(&item.mData[0], &expires, sizeof(expires));
	pos = writeItem(pos, item);

	//Priority item
	item.clear();
	item.mId = 5;
	uint8_t priority = 10; //top priority
	item.mData.push_back(priority);
	pos = writeItem(pos, item);

	//now write the total length of items for this frame
	frameSize = pos - sizeof(uint8_t) - sizeof(frameSize);
	frameSize = htonl(frameSize);
	memcpy(&mBuffer[1], &frameSize, sizeof(frameSize));

	return mBuffer;
}

string AppleRequest::isValidResponse(const string &str) {
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
		stringstream ss;
		ss << "PNR " << this << " with identifier " << identifier << " failed with error "
		<< (int)error << " (" << (error>8 ? "unknown" : errorToString[error]) << ")";
		return ss.str();
	}
	return "";
}

} // end of pushnotification namespace
} // end of flexisip namespace
