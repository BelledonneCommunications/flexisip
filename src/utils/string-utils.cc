/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL.

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
	const auto views = split(string_view{str}, string_view{delimiter});

	return {views.begin(), views.end()};
}

vector<string_view> StringUtils::split(string_view str, string_view delimiter) noexcept {
	vector<string_view> out;

	if (!str.empty()) {
		size_t pos = 0, oldPos = 0;
		for (; (pos = str.find(delimiter, pos)) != string::npos; oldPos = pos + delimiter.length(), pos = oldPos)
			out.push_back(str.substr(oldPos, pos - oldPos));
		out.push_back(str.substr(oldPos));
	}

	return out;
}

optional<pair<string_view, string_view>> StringUtils::splitOnce(string_view str, string_view delimiter) noexcept {
	const auto pos = str.find(delimiter);
	if (pos == string_view::npos) return nullopt;

	return {{str.substr(0, pos), str.substr(pos + delimiter.size())}};
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

std::map<std::string, std::string> StringUtils::parseKeyValue(const std::string& toParse,
                                                              const char lineDelimiter,
                                                              const char delimiter,
                                                              const char comment) {
	map<string, string> kvMap;
	istringstream values(toParse);

	for (string line; getline(values, line, lineDelimiter);) {
		if (line.find(comment) == 0) continue; // section title

		// clear all non-UNIX end of line chars
		line.erase(remove_if(line.begin(), line.end(), isEndOfLineCharacter), line.end());

		size_t delim_pos = line.find(delimiter);
		if (delim_pos == line.npos || delim_pos == line.length()) {
			LOGW("Invalid line '%s' in key-value", line.c_str());
			continue;
		}

		const string key = line.substr(0, delim_pos);
		string value = line.substr(delim_pos + 1);

		kvMap[key] = value;
	}

	return kvMap;
}

#ifdef HAVE_LIBLINPHONECXX
std::optional<linphone::MediaEncryption> StringUtils::string2MediaEncryption(const std::string& str) {
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
