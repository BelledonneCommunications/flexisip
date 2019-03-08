/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2016  Belledonne Communications SARL.

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

#include <vector>

#include <sofia-sip/url.h>

#include "uri-utils.hh"

using namespace std;

std::string UriUtils::escape(const char *str, const char *reserved) {
	string escapedStr;
	if (url_reserved_p(str)) {
		escapedStr.resize(url_esclen(str, reserved));
		url_escape(&escapedStr.at(0), str, reserved);
	} else {
		escapedStr = str;
	}
	return escapedStr;
}

std::string UriUtils::unescape(const char *str, size_t n) {
	string unescapedStr(n, '\0');
	n = url_unescape_to(&unescapedStr[0], str, n);
	unescapedStr.resize(n);
	return unescapedStr;
}
