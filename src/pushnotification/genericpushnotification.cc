/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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
#include "common.hh"

#include <iostream>
#include <list>

using namespace ::std;

GenericPushNotificationRequest::GenericPushNotificationRequest(const PushInfo &pinfo, const url_t *url, const string &method)
: PushNotificationRequest("generic", "generic") {
	ostringstream httpMessage;
	string path(url->url_path);
	string headers(url->url_headers);
	
	substituteArgs(path, pinfo);
	substituteArgs(headers, pinfo);
	
	httpMessage<<method<<" /"<<path;
	if (!headers.empty()) httpMessage<<"?"<<headers;
	httpMessage<<" HTTP/1.1\r\n";
	httpMessage<<"Host: "<<url->url_host;
	if (url->url_port) httpMessage<<url->url_port;
	httpMessage<<"\r\n";
	if (!pinfo.mText.empty()){
		httpMessage<<"Content-Type: text/plain\r\n";
		httpMessage<<"Content-Length: "<<pinfo.mText.size()<<"\r\n";
	}else httpMessage<<"Content-Length: 0\r\n";
	httpMessage<<"\r\n";
	if (!pinfo.mText.empty()){
		httpMessage<<pinfo.mText;
		httpMessage<<"\r\n";
	}
	mHttpMessage = httpMessage.str();
	SLOGD << "GenericPushNotificationRequest" << this << " http message is" << mHttpMessage;
}

void GenericPushNotificationRequest::createPushNotification() {
	int headerLength = mHttpMessage.size();
	
	mBuffer.clear();
	mBuffer.resize(headerLength);

	char *binaryMessageBuff = &mBuffer[0];
	char *binaryMessagePt = binaryMessageBuff;

	memcpy(binaryMessagePt, &mHttpMessage[0], headerLength);
	binaryMessagePt += headerLength;
}

const vector<char> & GenericPushNotificationRequest::getData() {
	createPushNotification();
	return mBuffer;
}

bool GenericPushNotificationRequest::isValidResponse(const string &str) {
	LOGD("GenericPushNotificationRequest: http response is \n%s", str.c_str());
	return true;
}

struct KeyVal{
	KeyVal(const char *keyword, const string &value) : mKeyword(keyword), mValue(value){
	}
	const char *mKeyword;
	const string mValue;
};

string & GenericPushNotificationRequest::substituteArgs(string &input, const PushInfo &pinfo){
	list<KeyVal> keyvals;
	
	keyvals.push_back(KeyVal("$type", pinfo.mType));
	keyvals.push_back(KeyVal("$token", pinfo.mDeviceToken));
	keyvals.push_back(KeyVal("$api-key", pinfo.mApiKey));
	keyvals.push_back(KeyVal("$app-id", pinfo.mAppId));
	keyvals.push_back(KeyVal("$from-name", pinfo.mFromName));
	keyvals.push_back(KeyVal("$from-uri", pinfo.mFromUri));
	keyvals.push_back(KeyVal("$from-tag", pinfo.mFromTag));
	keyvals.push_back(KeyVal("$to-uri", pinfo.mToUri));
	keyvals.push_back(KeyVal("$call-id", pinfo.mCallId));
	keyvals.push_back(KeyVal("$event", pinfo.mEvent==PushInfo::Call ? "call" : "message"));
	keyvals.push_back(KeyVal("$sound", pinfo.mAlertSound));
	keyvals.push_back(KeyVal("$msgid", pinfo.mAlertMsgId));
	
	for(auto it=keyvals.begin(); it!=keyvals.end(); ++it){
		size_t pos=input.find((*it).mKeyword);
		if (pos!=string::npos){
			input.replace(pos,strlen((*it).mKeyword), (*it).mValue);
		}
	}
	return input;
}
