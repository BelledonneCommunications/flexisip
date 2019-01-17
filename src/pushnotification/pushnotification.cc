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

#include <ctime>
#include <sstream>

#include <flexisip/logmanager.hh>
#include "pushnotification.hh"

using namespace std;
using namespace flexisip;

PushNotificationRequest::PushNotificationRequest(const string &appid, const string &type)
			: mState( NotSubmitted), mAppId(appid), mType(type) {
}

string PushNotificationRequest::quoteStringIfNeeded(const string &str) const {
	if (str[0] == '"'){
		return str;
	}else{
		ostringstream ostr;
		ostr << "\"" << str << "\"";
		return ostr.str();
	}
}

string PushNotificationRequest::getPushTimeStamp() const {
	time_t t = time(NULL);
	struct tm time;
	gmtime_r(&t, &time);
	char date[20] = {0};
	size_t ret = strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", &time);
	if (ret == 0)
		SLOGE << "Invalid time stamp for push notification PNR: " << this;

	return string(date);
}
