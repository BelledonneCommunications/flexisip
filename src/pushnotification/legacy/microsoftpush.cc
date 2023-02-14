/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include "microsoftpush.hh"
#include "sofia-sip/base64.h"
#include <flexisip/logmanager.hh>
#include <iostream>
#include <string.h>
#include <vector>

using namespace std;

namespace flexisip {
namespace pushnotification {

void WindowsPhoneRequest::createHTTPRequest([[maybe_unused]] const std::string& access_token) {
	const auto& host = getDestination().getParam();
	const auto& path = getDestination().getPrid();
	const auto& message = mPInfo->mText;
	const auto& sender_name = mPInfo->mFromName;
	const auto& sender_uri = mPInfo->mFromUri;
	ostringstream httpBody{};
	ostringstream httpHeader{};

	if (mPType == PushType::Message) {
		httpBody << "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		         << "<wp:Notification xmlns:wp=\"WPNotification\">"
		         << "<wp:Toast>"
		         << "<wp:Text1>" << sender_name << "</wp:Text1>"
		         << "<wp:Text2>" << message << "</wp:Text2>"
		         << "<wp:Param>/Views/Chat.xaml?sip=" << sender_uri << "</wp:Param>"
		         << "</wp:Toast>"
		         << "</wp:Notification>";

		// Notification class 2 is the type for toast notifitcation.
		httpHeader << "POST " << path << " HTTP/1.1\r\n"
		           << "Host:" << host << "\r\n"
		           << "X-WindowsPhone-Target:toast\r\n"
		           << "X-NotificationClass:2\r\n"
		           << "Content-Type:text/xml\r\n"
		           << "Content-Length:" << httpBody.str().size() << "\r\n\r\n";
	} else {
		httpBody << "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		         << "<IncomingCall><Name></Name><Number></Number></IncomingCall>";

		// Notification class 4 is the type for VoIP incoming call.
		httpHeader << "POST " << path << " HTTP/1.1\r\n"
		           << "Host:" << host << "\r\n"
		           << "X-NotificationClass:4\r\n"
		           << "Content-Type:text/xml\r\n"
		           << "Content-Length:" << httpBody.str().size() << "\r\n\r\n";
	}

	mHttpHeader = httpHeader.str();
	mHttpBody = httpBody.str();

	SLOGD << "PNR " << this << " POST header is " << mHttpHeader;
	SLOGD << "PNR " << this << " POST body is " << mHttpBody;
}

void Windows10Request::createHTTPRequest(const std::string& access_token) {
	const auto& host = getDestination().getParam();
	char decodeUri[512] = {0};

	const auto& message = mPInfo->mText;
	const auto& sender_uri = mPInfo->mFromUri;
	ostringstream httpBody{};
	ostringstream httpHeader{};

	string unescapedUrl;

	const auto& deviceToken = getDestination().getPrid();
	unescapedUrl.resize(deviceToken.size());
	url_unescape(&unescapedUrl[0], deviceToken.c_str());
	base64_d(decodeUri, sizeof(decodeUri), unescapedUrl.c_str());
	string query(decodeUri);
	if (mPType == PushType::Message) {
		// We have to send the content of the message and the name of the sender.
		// We also need the sender address to be able to display the full chat view in case the receiver click the
		// toast.

		httpBody << "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		         << "<toast launch=\"chat?sip=" << sender_uri << "\">"
		         << "<visual>"
		         << "<binding template =\"ToastGeneric\">"
		         << "<text>" << sender_uri << "</text>"
		         << "<text>" << message << "</text>"
		         << "</binding>"
		         << "</visual>"
		         << "</toast>";
	} else {
		// No need to specify name or number, this PN will only wake up Linphone.
		httpBody << "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		         << "<toast launch=\"" << sender_uri << "\">"
		         << "<visual>"
		         << "<binding template=\"ToastGeneric\">"
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

	mHttpHeader = httpHeader.str();
	mHttpBody = httpBody.str();

	SLOGD << "PNR " << this << " POST header is " << mHttpHeader;
	SLOGD << "PNR " << this << " POST body is " << mHttpBody;
}

void MicrosoftRequest::createPushNotification() {
	int headerLength = mHttpHeader.length();
	int bodyLength = mHttpBody.length();

	mBuffer.clear();
	mBuffer.resize(headerLength + bodyLength);

	char* binaryMessageBuff = &mBuffer[0];
	char* binaryMessagePt = binaryMessageBuff;

	memcpy(binaryMessagePt, &mHttpHeader[0], headerLength);
	binaryMessagePt += headerLength;

	memcpy(binaryMessagePt, &mHttpBody[0], bodyLength);
	binaryMessagePt += bodyLength;
}

const vector<char>& MicrosoftRequest::getData([[maybe_unused]] const sofiasip::Url& url, [[maybe_unused]] Method method) {
	createPushNotification();
	return mBuffer;
}

std::string MicrosoftRequest::isValidResponse(const string& str) {
	string line;
	istringstream iss(str);
	bool valid = false, connect = false, notif = false;
	while (getline(iss, line)) {
		checkResponseLine(line, valid, connect, notif);

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

void WindowsPhoneRequest::checkResponseLine(const std::string& line,
                                            bool& isValid,
                                            bool& isConnect,
                                            bool& isNotif) const {
	isConnect |= (line.find("X-DeviceConnectionStatus: connected") != string::npos);
	isNotif |= (line.find("X-NotificationStatus: Received") != string::npos);
	isValid |= (line.find("X-SubscriptionStatus: Active") != string::npos);
}

void Windows10Request::checkResponseLine(const std::string& line, bool& isValid, bool& isConnect, bool& isNotif) const {
	isValid |= (line.find("HTTP/1.1 200 OK") != string::npos);
	isConnect |= (line.find("X-WNS-DEVICECONNECTIONSTATUS: connected") != string::npos);
	isNotif |= (line.find("X-WNS-STATUS: received") != string::npos);
}

} // namespace pushnotification
} // namespace flexisip
