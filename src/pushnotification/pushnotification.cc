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

#include <flexisip/logmanager.hh>
#include "pushnotification.hh"

using namespace std;

namespace flexisip {
namespace pushnotification {

std::string Request::quoteStringIfNeeded(const std::string &str) const noexcept {
	if (str[0] == '"') {
		return str;
	} else {
		string res;
		res.reserve(str.size() + 2);
		return move(res) + "\"" + str + "\"";
	}
}

std::string Request::getPushTimeStamp() const noexcept {
	time_t t = time(nullptr);
	struct tm time;
	gmtime_r(&t, &time);
	char date[20] = {0};
	size_t ret = strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", &time);
	if (ret == 0)
		SLOGE << "Invalid time stamp for push notification PNR: " << this;

	return string(date);
}

} // end of pushnotification namespace
} // end of flexisip namespace
