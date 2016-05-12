
#include "microsoftpush.hh"
#include "log/logmanager.hh"
#include <string.h>
#include <iostream>
#include <vector>

using namespace std;

WindowsPhonePushNotificationRequest::WindowsPhonePushNotificationRequest(const PushInfo &pinfo)
: PushNotificationRequest(pinfo.mAppId, "wp"), mPushInfo(pinfo) { }

void WindowsPhonePushNotificationRequest::createHTTPRequest(const std::string &access_token) {
	const string &host = mPushInfo.mAppId;
	const string &query = mPushInfo.mDeviceToken;
	bool is_message = mPushInfo.mEvent == PushInfo::Message;
	const std::string &message = mPushInfo.mText;
	const std::string &sender_name = mPushInfo.mFromName;
	const std::string &sender_uri = mPushInfo.mFromUri;
	ostringstream httpBody;
	if (is_message) {
		// We have to send the content of the message and the name of the sender.
		// We also need the sender address to be able to display the full chat view in case the receiver click the
		// toast.
		httpBody << "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
				 	<< "<wp:Notification xmlns:wp=\"WPNotification\">"
				 		<< "<wp:Toast>"
				 			<< "<wp:Text1>"	<< sender_name << "</wp:Text1>"
				 			<< "<wp:Text2>" << message << "</wp:Text2>"
				 			<< "<wp:Param>"	<< "/Views/Chat.xaml?sip=" << sender_uri << "</wp:Param>"
				 		<< "</wp:Toast>"
				 	<< "</wp:Notification>";
	} else {
		// No need to specify name or number, this PN will only wake up linphone.
		httpBody << "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
					<< "<IncomingCall><Name></Name><Number></Number></IncomingCall>";
	}
	mHttpBody = httpBody.str();

	ostringstream httpHeader;

	httpHeader << "POST " << query << " HTTP/1.1\r\n"
				<< "Authorization: Bearer " << access_token << "\r\n"
				<< "X-WNS-RequestForStatus: true\r\n"
				<< "X-WNS-Type: wns/toast\r\n"
				<< "Content-Type: text/xml\r\n"
				<< "Host: " << host << "\r\n"
				<< "Content-Length: " << httpBody.str().size() << "\r\n\r\n";

	mHttpHeader = httpHeader.str();

	SLOGD << "PNR " << this << " POST header is " << mHttpHeader;
	SLOGD << "PNR " << this << " POST body is " << mHttpBody;
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

const vector<char> &WindowsPhonePushNotificationRequest::getData() {
	createPushNotification();
	return mBuffer;
}

bool WindowsPhonePushNotificationRequest::isValidResponse(const string &str) {
	string line;
	istringstream iss(str);
	bool valid = false, connect = false, notif = false;
	while (getline(iss, line)) {
		valid |= (line.find("HTTP/1.1 200 OK") != string::npos);
		connect |= (line.find("X-WNS-DEVICECONNECTIONSTATUS: connected") != string::npos);
		notif |= (line.find("X-WNS-STATUS: received") != string::npos);
	}
	return valid && connect && notif;
}
