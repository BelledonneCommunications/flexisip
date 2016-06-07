
#include "microsoftpush.hh"
#include "log/logmanager.hh"
#include <string.h>
#include <iostream>
#include <vector>

using namespace std;

WindowsPhonePushNotificationRequest::WindowsPhonePushNotificationRequest(const PushInfo &pinfo)
: PushNotificationRequest(pinfo.mAppId, pinfo.mType), mPushInfo(pinfo) {

    if(pinfo.mType == "wp"){
        createHTTPRequest("");
    }
}

void WindowsPhonePushNotificationRequest::createHTTPRequest(const std::string &access_token) {
    const string &host = mPushInfo.mAppId;
    
    char unescapedUrl[512];
    url_unescape(unescapedUrl, mPushInfo.mDeviceToken.c_str());// since the device token is an encoded URI, we must unescape it first
    const string &query = std::string(unescapedUrl);
    bool is_message = mPushInfo.mEvent == PushInfo::Message;
    const std::string &message = mPushInfo.mText;
    const std::string &sender_name = mPushInfo.mFromName;
    const std::string &sender_uri = mPushInfo.mFromUri;
    ostringstream httpBody;
    ostringstream httpHeader;
    
    if(mPushInfo.mType == "w10") {
   	  if (is_message) {
            // We have to send the content of the message and the name of the sender.
            // We also need the sender address to be able to display the full chat view in case the receiver click the
            // toast.
            
            httpBody << "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                << "<toast launch=\"" << "chat?sip=" << sender_uri  << "\">"
                << "<visual>"
                << "<binding template =\"ToastGeneric\">"
                << "<text>"	<< sender_name << "</text>"
                << "<text>" << message << "</text>"
                << "</binding>"
                <<  "</visual>"
                << "</toast>";
        } else {
            // No need to specify name or number, this PN will only wake up linphone.
            httpBody << "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        		<< "<toast launch=\"" << sender_uri << "\" >"
                << "<visual>"
                << "<binding template=\"ToastGeneric\" scenario=\'incomingCall\'>"
                << "<text>Incoming Call</text>"
                << "<text>" << sender_uri << "</text>"
                << "</binding>"
        		<< "</visual>"
                << "</toast>";
        }
        
        httpHeader << "POST " << query << " HTTP/1.1\r\n"
            << "Authorization: Bearer " << access_token << "\r\n"
            << "X-WNS-RequestForStatus: true\r\n"
            << "X-WNS-Type: wns/toast\r\n"
            << "Content-Type: text/xml\r\n"
            << "Host: " << host << "\r\n"
            << "Content-Length: " << httpBody.str().size() << "\r\n\r\n";
        
    } else if(mPushInfo.mType == "wp"){
        if(is_message){
            httpBody << "<?xml version=\"1.0\" encoding=\"utf-8\"?><wp:Notification "
                "xmlns:wp=\"WPNotification\"><wp:Toast><wp:Text1>"
                << sender_name << "</wp:Text1><wp:Text2>" << message << "</wp:Text2><wp:Param>"
            	<< "/Views/Chat.xaml?sip=" << sender_uri << "</wp:Param></wp:Toast></wp:Notification>";
            
            // Notification class 2 is the type for toast notifitcation.
            httpHeader
                << "POST " << query << " HTTP/1.1\r\nHost:" << host
                << "\r\nX-WindowsPhone-Target:toast\r\nX-NotificationClass:2\r\nContent-Type:text/xml\r\nContent-Length:"
                << httpBody.str().size() << "\r\n\r\n";
        } else {
            httpBody << "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                << "<IncomingCall><Name></Name><Number></Number></IncomingCall>";
            
            // Notification class 4 is the type for VoIP incoming call.
            httpHeader << "POST " << query << " HTTP/1.1\r\nHost:" << host
            	<< "\r\nX-NotificationClass:4\r\nContent-Type:text/xml\r\nContent-Length:" << httpBody.str().size()
            	<< "\r\n\r\n";
        }
    }
        
    mHttpHeader = httpHeader.str();
    mHttpBody = httpBody.str();

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

std::string WindowsPhonePushNotificationRequest::isValidResponse(const string &str) {
	string line;
	istringstream iss(str);
	bool valid = false, connect = false, notif = false;
	while (getline(iss, line)) {
        if(mPushInfo.mType == "w10"){
            valid |= (line.find("HTTP/1.1 200 OK") != string::npos);
            connect |= (line.find("X-WNS-DEVICECONNECTIONSTATUS: connected") != string::npos);
            notif |= (line.find("X-WNS-STATUS: received") != string::npos);
        } else {
            connect |= (line.find("X-DeviceConnectionStatus: connected") != string::npos);
            notif |= (line.find("X-NotificationStatus: Received") != string::npos);
            valid |= (line.find("X-SubscriptionStatus: Active") != string::npos);

        }
		

		auto it = line.find("X-WNS-ERROR-DESCRIPTION");
		if (it != string::npos) {
			return line.substr(line.find(' '));
		}
	}
	if (!valid) return "Unexpected HTTP response value (not 200 OK)";
	if (!connect) return "Device connection status not set to connected";
	if (!notif) return "Notification not received by server";
	return "";
}
