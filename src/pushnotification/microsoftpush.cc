
#include "microsoftpush.hh"
#include "log/logmanager.hh"
#include <string.h>
#include <iostream>
#include <vector>

using namespace std;

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
		// We also need the sender address to be able to display the full chat view in case the receiver click the
		// toast.
		httpBody << "<?xml version=\"1.0\" encoding=\"utf-8\"?><wp:Notification "
		"xmlns:wp=\"WPNotification\"><wp:Toast><wp:Text1>"
		<< sender_name << "</wp:Text1><wp:Text2>" << message << "</wp:Text2><wp:Param>"
		<< "/Views/Chat.xaml?sip=" << sender_uri << "</wp:Param></wp:Toast></wp:Notification>";
	} else {
		// No need to specify name or number, this PN will only wake up linphone.
		httpBody
		<< "<?xml version=\"1.0\" encoding=\"utf-8\"?><IncomingCall><Name></Name><Number></Number></IncomingCall>";
	}
	mHttpBody = httpBody.str();
	LOGD("Push notification https post body is %s", mHttpBody.c_str());
	
	ostringstream httpHeader;
	if (is_message) {
		// Notification class 2 is the type for toast notifitcation.
		httpHeader
		<< "POST " << query << " HTTP/1.1\r\nHost:" << host
		<< "\r\nX-WindowsPhone-Target:toast\r\nX-NotificationClass:2\r\nContent-Type:text/xml\r\nContent-Length:"
		<< httpBody.str().size() << "\r\n\r\n";
	} else {
		// Notification class 4 is the type for VoIP incoming call.
		httpHeader << "POST " << query << " HTTP/1.1\r\nHost:" << host
		<< "\r\nX-NotificationClass:4\r\nContent-Type:text/xml\r\nContent-Length:" << httpBody.str().size()
		<< "\r\n\r\n";
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

const vector<char> &WindowsPhonePushNotificationRequest::getData() {
	createPushNotification();
	return mBuffer;
}

bool WindowsPhonePushNotificationRequest::isValidResponse(const string &str) {
	string line;
	istringstream iss(str);
	bool connect, notif, subscr = notif = connect = false;
	while (getline(iss, line)) {
		if (!connect)
			connect = line.find("X-DeviceConnectionStatus: Connected") != string::npos;
		if (!notif)
			notif = line.find("X-NotificationStatus: Received") != string::npos;
		if (!subscr)
			subscr = line.find("X-SubscriptionStatus: Active") != string::npos;
	}
	
	return connect && notif && subscr;
}
