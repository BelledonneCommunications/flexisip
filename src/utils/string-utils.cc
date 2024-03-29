/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL.

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
#include <optional>
#include <stdexcept>

#include <flexisip/logmanager.hh>
#include <string_view>

#include "string-utils.hh"

using namespace std;

vector<string> StringUtils::split(const string& str, const string& delimiter) noexcept {
	vector<string> out;

	if (!str.empty()) {
		size_t pos = 0, oldPos = 0;
		for (; (pos = str.find(delimiter, pos)) != string::npos; oldPos = pos + delimiter.length(), pos = oldPos)
			out.push_back(str.substr(oldPos, pos - oldPos));
		out.push_back(str.substr(oldPos));
	}

	return out;
}

std::string StringUtils::strip(const char* str, char c) noexcept {
	auto start = str, end = const_cast<const char*>(index(str, '\0'));
	strip(start, end, c);
	return string{start, end};
}

std::string StringUtils::strip(const std::string& str, char c) noexcept {
	auto start = str.cbegin(), end = str.cend();
	strip(start, end, c);
	return string{start, end};
}

std::string StringUtils::stripAll(const char* str, char c) {
	const char* start = str;
	const char* end = index(str, '\0');
	while (end > start && *end == c)
		end--;
	while (end > start && *start == c)
		start++;
	return string(start, end - start);
}

std::string StringUtils::stripAll(const std::string& str, char c) {
	auto start = str.cbegin();
	auto end = str.cend();
	stripAll(start, end, c);
	return string(start, end);
}

void StringUtils::stripAll(std::string::const_iterator& start, std::string::const_iterator& end, char c) {
	while (end > start && *(end - 1) == c)
		end--;
	while (end > start && *start == c)
		start++;
}

optional<string_view> StringUtils::removePrefix(const string_view& str, const string_view& prefix) {
	if (!startsWith(str, prefix)) {
		return nullopt;
	}
	return str.substr(prefix.size());
}

std::string&
StringUtils::searchAndReplace(std::string& str, const std::string& key, const std::string& value) noexcept {
	auto index = str.find(key);
	while (index != string::npos) {
		str.replace(index, key.size(), value);
		index = str.find(key, index + value.size());
	}
	return str;
}

std::string StringUtils::transform(const std::string& str, const std::map<char, std::string>& transMap) noexcept {
	string res{};
	for (const auto& c : str) {
		auto transEntry = transMap.find(c);
		if (transEntry != transMap.cend()) {
			res.append(transEntry->second);
		} else {
			res.push_back(c);
		}
	}
	return res;
}

#ifdef HAVE_LIBLINPHONECXX
flexisip::stl_backports::optional<linphone::MediaEncryption>
StringUtils::string2MediaEncryption(const std::string& str) {
	using enc = linphone::MediaEncryption;
	if (str == "zrtp") {
		return enc::ZRTP;
	} else if (str == "sdes") {
		return enc::SRTP;
	} else if (str == "dtls-srtp") {
		return enc::DTLS;
	} else if (str == "none") {
		return enc::None;
	}

	SLOGE << "Invalid encryption mode: " << str
	      << " valids modes are : zrtp, sdes, dtls-srtp, none. Ignore this setting";
	return {};
}
#endif // HAVE_LIBLINPHONECXX
