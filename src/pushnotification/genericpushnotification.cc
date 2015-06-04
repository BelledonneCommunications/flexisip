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
	ostringstream httpHeaders;
	string path(url->url_path);
	string headers(url->url_headers);
	
	substituteArgs(path, pinfo);
	substituteArgs(headers, pinfo);
	
	httpHeaders<<method<<" "<<path<<" HTTP/1.1\r\n";
	if (!pinfo.mText.empty()){
		httpHeaders<<"Content-Type: text/plain\r\n";
		httpHeaders<<"Content-Length: "<<pinfo.mText.size()<<"\r\n";
		httpHeaders<<"\r\n\r\n";
	}
	httpHeaders<<"Content-Length: 0\r\n\r\n";
	
	mHttpHeaders = httpHeaders.str();
	SLOGD << "GenericPushNotificationRequest" << this << " http message is" << mHttpHeaders;
}

void GenericPushNotificationRequest::createPushNotification() {
	int headerLength = mHttpHeaders.size();
	
	mBuffer.clear();
	mBuffer.resize(headerLength);

	char *binaryMessageBuff = &mBuffer[0];
	char *binaryMessagePt = binaryMessageBuff;

	memcpy(binaryMessagePt, &mHttpHeaders[0], headerLength);
	binaryMessagePt += headerLength;
}

const vector<char> & GenericPushNotificationRequest::getData() {
	createPushNotification();
	return mBuffer;
}

bool GenericPushNotificationRequest::isValidResponse(const string &str) {
	return true;
}

struct KeyVal{
	KeyVal(const char *keyword, const string &value) : mKeyword(keyword), mValue(value){
	}
	const char *mKeyword;
	const string &mValue;
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
