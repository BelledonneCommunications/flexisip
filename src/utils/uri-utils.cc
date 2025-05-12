/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <cstring>
#include <sstream>

#include "sofia-sip/hostdomain.h"
#include "sofia-sip/url.h"

#include "string-utils.hh"
#include "uri-utils.hh"

using namespace std;

namespace flexisip::uri_utils {
namespace {

string unescape(const char* str, size_t n) noexcept {
	string unescapedStr(n, '\0');
	n = url_unescape_to(&unescapedStr[0], str, n);
	unescapedStr.resize(n);
	return unescapedStr;
}

} // namespace

string unescape(const char* str) noexcept {
	return unescape(str, strlen(str));
}
string unescape(const string& str) noexcept {
	return unescape(str.c_str(), str.size());
}

string escape(const char* str, const char* reserved) noexcept {
	string escapedStr;
	if (url_reserved_p(str)) {
		escapedStr.resize(url_esclen(str, reserved));
		url_escape(&escapedStr.at(0), str, reserved);
	} else {
		escapedStr = str;
	}
	return escapedStr;
}

string getParamValue(const char* paramList, const char* paramName, const char* defaultValue) noexcept {
	constexpr size_t bufferSize = 255;
	string value(bufferSize, '\0');
	isize_t valueSize = url_param(paramList, paramName, &value[0], value.size());
	if (valueSize == 0) return defaultValue;
	value.resize(valueSize - 1);
	return value;
}

string uniqueIdToGr(const string& uid) noexcept {
	string ret;
	size_t begin = uid.find('<');
	if (begin != string::npos) {
		size_t end = uid.find('>', begin + 1);
		if (end != string::npos) {
			begin++; // skip '<'
			ret = uid.substr(begin, end - begin);
		}
	}
	return ret;
}

string grToUniqueId(const string& gr) noexcept {
	ostringstream uid;
	uid << "\"<" << gr << ">\"";
	return uid.str();
}

bool isIpv4Address(const char* str) {
	return host_is_ip4_address(str);
}

bool isIpv6Address(const char* str) {
	return host_is_ip6_address(str);
}

bool isIpAddress(const char* str) {
	return host_is_ip_address(str);
}

} // namespace flexisip::uri_utils