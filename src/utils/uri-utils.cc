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

#include <sstream>
#include <stdexcept>
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

std::string UriUtils::getParamValue(const char *paramList, const char *paramName) {
	string value(_bufferSize, '\0');
	isize_t valueSize = url_param(paramList, paramName, &value[0], value.size());
	if (valueSize == 0) throw out_of_range(string("\'") + paramName + "\' not found");
	value.resize(valueSize-1);
	return value;
}

std::string UriUtils::uniqueIdToGr(const std::string &uid) {
	string ret;
	size_t begin = uid.find('<');
	if (begin != string::npos) {
		size_t end = uid.find('>', begin + 1);
		if (end != string::npos) {
			begin++; //skip '<'
			ret = uid.substr(begin, end - begin);
		}
	}
	return ret;
}

std::string UriUtils::grToUniqueId(const std::string &gr) {
	ostringstream uid;
	uid << "\"<" << gr << ">\"";
	return uid.str();
}
