
#include "googlepush.hh"
#include <iostream>
#include <string.h>
#include "log/logmanager.hh"

using namespace std;

GooglePushNotificationRequest::GooglePushNotificationRequest(const PushInfo &pinfo)
: PushNotificationRequest(pinfo.mAppId, "google") {
	const string &deviceToken = pinfo.mDeviceToken;
	const string &apiKey = pinfo.mApiKey;
	const string &arg = pinfo.mFromName.empty() ? pinfo.mFromUri : pinfo.mFromName;
	const string &callid = pinfo.mCallId;
	ostringstream httpBody;
	string date = getPushTimeStamp();

	httpBody << "{\"registration_ids\":[\"" << deviceToken << "\"],\"data\":{\"loc-args\":\"" << arg
	<< "\"}"
	",\"priority\":\"high\""
	",\"call-id\":\"" << callid
	<< "\", \"uuid\":" << quoteStringIfNeeded(pinfo.mUid)
	<< ", \"send-time\":\"" << date << "\"}";
	mHttpBody = httpBody.str();
	LOGD("Push notification https post body is %s", mHttpBody.c_str());

	ostringstream httpHeader;
	httpHeader << "POST /gcm/send "
	"HTTP/1.1\r\nHost:android.googleapis.com\r\nContent-Type:application/json\r\nAuthorization:key="
	<< apiKey << "\r\nContent-Length:" << httpBody.str().size() << "\r\n\r\n";
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

const vector<char> &GooglePushNotificationRequest::getData() {
	createPushNotification();
	return mBuffer;
}

string GooglePushNotificationRequest::isValidResponse(const string &str) {
	static const char expected[] = "HTTP/1.1 200";
	return strncmp(expected, str.c_str(), sizeof(expected) - 1) == 0 ? "" : "Unexpected HTTP response value (not 200 OK)";
}
