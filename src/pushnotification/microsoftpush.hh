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

#pragma once

#ifndef _MICROSOFT_PUSH_H_
#define _MICROSOFT_PUSH_H


#include "pushnotification.hh"


class WindowsPhonePushNotificationRequest : public PushNotificationRequest {
public:
	virtual const std::vector<char> &getData();
	virtual bool isValidResponse(const std::string &str);
	WindowsPhonePushNotificationRequest(const PushInfo &pinfo);
	~WindowsPhonePushNotificationRequest() {
	}
	virtual bool serverResponseIsImmediate() {
		return true;
	}
	
protected:
	void createPushNotification();
	std::vector<char> mBuffer;
	std::string mHttpHeader;
	std::string mHttpBody;
};

#endif