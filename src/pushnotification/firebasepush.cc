
#include "firebasepush.hh"
#include <iostream>
#include <string.h>
#include <flexisip/logmanager.hh>

using namespace std;

namespace flexisip {
namespace pushnotification {

/*
 * This supports the legacy http Firebase protocol:
 * https://firebase.google.com/docs/cloud-messaging/http-server-ref
 */

FirebaseRequest::FirebaseRequest(const PushInfo &pinfo)
: Request(pinfo.mAppId, "firebase") {
	const string &deviceToken = pinfo.mDeviceToken;
	const string &apiKey = pinfo.mApiKey;
	const string &from = pinfo.mFromName.empty() ? pinfo.mFromUri : pinfo.mFromName;
	ostringstream httpBody;
	string date = getPushTimeStamp();
	int ttl = (pinfo.mEvent == PushInfo::Event::Call) ? 0 : 2419200; // 4 weeks, it is the maximum allowed TTL for firebase push
	
	httpBody << "{\"to\":\"" << deviceToken << "\", "
	 	<< "\"time_to_live\": " << ttl << ", "
		<< "\"priority\":\"high\""
		<< ", \"data\":{"
			<< "\"uuid\":" << quoteStringIfNeeded(pinfo.mUid)
			<< ", \"form-uri\":" << quoteStringIfNeeded(pinfo.mFromUri)
			<< ", \"display-name\":" << quoteStringIfNeeded(pinfo.mFromName)
			<< ", \"call-id\":" << quoteStringIfNeeded(pinfo.mCallId)
			<< ", \"sip-from\":" << quoteStringIfNeeded(from)
			<< ", \"loc-key\":" << quoteStringIfNeeded(pinfo.mAlertMsgId)
			<< ", \"loc-args\":" << quoteStringIfNeeded(from)
			<< ", \"send-time\":" << quoteStringIfNeeded(date) << "}"
		<< "}";
	mHttpBody = httpBody.str();
	LOGD("Push notification https post body is %s", mHttpBody.c_str());

	ostringstream httpHeader;
	httpHeader << "POST /fcm/send "
	"HTTP/1.1\r\nHost:fcm.googleapis.com\r\nContent-Type:application/json\r\nAuthorization:key="
	<< apiKey << "\r\nContent-Length:" << httpBody.str().size() << "\r\n\r\n";
	mHttpHeader = httpHeader.str();
	SLOGD << "PNR " << this << " https post header is " << mHttpHeader;
}

void FirebaseRequest::createPushNotification() {
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

const vector<char> &FirebaseRequest::getData() {
	createPushNotification();
	return mBuffer;
}

string FirebaseRequest::isValidResponse(const string &str) {
	static const char expected[] = "HTTP/1.1 200";
	return strncmp(expected, str.c_str(), sizeof(expected) - 1) == 0 ? "" : "Unexpected HTTP response value (not 200 OK)";
}

}
}
