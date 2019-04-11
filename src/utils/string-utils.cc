/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010  Belledonne Communications SARL.

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

#include <cstring>
#include <stdexcept>

#include "string-utils.hh"

using namespace std;

vector<string> StringUtils::split (const string &str, const string &delimiter) {
	vector<string> out;

	size_t pos = 0, oldPos = 0;
	for (; (pos = str.find(delimiter, pos)) != string::npos; oldPos = pos + delimiter.length(), pos = oldPos)
		out.push_back(str.substr(oldPos, pos - oldPos));
	out.push_back(str.substr(oldPos));

	return out;
}

std::string StringUtils::strip(const char *str, char c) {
	size_t len = strlen(str);
	if (len < 2) return str;
	if (str[0] != c || str[len-1] != c) return str;
	return string(str+1, len-2);
}

std::string StringUtils::strip(const std::string &str, char c) {
	auto start = str.cbegin();
	auto end = str.cend();
	strip(start, end, c);
	return string(start, end);
}

void StringUtils::strip(std::string::const_iterator &start, std::string::const_iterator &end, char c) {
	if (end - start < 2) return;
	if (*start != c || *(end-1) != c) return;
	start++;
	end--;
}

std::string StringUtils::removePrefix(const std::string &str, const std::string &prefix) {
	if (str.compare(0, prefix.size(), prefix) != 0) {
		ostringstream os;
		os << "'" << prefix << "' is not a prefix of '" << str << "'";
		throw invalid_argument(os.str());
	}
	return str.substr(prefix.size());
}
