/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

namespace flexisip::string_utils {

vector<string> split(const string& str, const string& delimiter) noexcept {
	const auto views = split(string_view{str}, string_view{delimiter});

	return {views.begin(), views.end()};
}

vector<string_view> split(string_view str, string_view delimiter) noexcept {
	vector<string_view> out;

	if (!str.empty()) {
		size_t pos = 0, oldPos = 0;
		for (; (pos = str.find(delimiter, pos)) != string::npos; oldPos = pos + delimiter.length(), pos = oldPos)
			out.push_back(str.substr(oldPos, pos - oldPos));
		out.push_back(str.substr(oldPos));
	}

	return out;
}

optional<pair<string_view, string_view>> splitOnce(string_view str, string_view delimiter) noexcept {
	const auto pos = str.find(delimiter);
	if (pos == string_view::npos) return nullopt;

	return {{str.substr(0, pos), str.substr(pos + delimiter.size())}};
}

string strip(const char* str, char c) noexcept {
	auto start = str, end = const_cast<const char*>(index(str, '\0'));
	strip(start, end, c);
	return string{start, end};
}

string strip(const string& str, char c) noexcept {
	auto start = str.cbegin(), end = str.cend();
	strip(start, end, c);
	return string{start, end};
}

string stripAll(const char* str, char c) {
	const char* start = str;
	const char* end = index(str, '\0');
	while (end > start && *end == c)
		end--;
	while (end > start && *start == c)
		start++;
	return string(start, end - start);
}

string stripAll(const string& str, char c) {
	auto start = str.cbegin();
	auto end = str.cend();
	stripAll(start, end, c);
	return string(start, end);
}

void stripAll(string::const_iterator& start, string::const_iterator& end, char c) {
	while (end > start && *(end - 1) == c)
		end--;
	while (end > start && *start == c)
		start++;
}

optional<string_view> removePrefix(const string_view& str, const string_view& prefix) {
	if (!startsWith(str, prefix)) {
		return nullopt;
	}
	return str.substr(prefix.size());
}

string& searchAndReplace(string& str, const string& key, const string& value) noexcept {
	auto index = str.find(key);
	while (index != string::npos) {
		str.replace(index, key.size(), value);
		index = str.find(key, index + value.size());
	}
	return str;
}

string transform(const string& str, const map<char, string>& transMap) noexcept {
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

map<string, string>
parseKeyValue(const string& toParse, const char lineDelimiter, const char delimiter, const char comment) {
	map<string, string> kvMap;
	istringstream values(toParse);

	for (string line; getline(values, line, lineDelimiter);) {
		if (line.find(comment) == 0) continue; // section title

		// clear all non-UNIX end of line chars
		line.erase(remove_if(line.begin(), line.end(), isEndOfLineCharacter), line.end());

		size_t delim_pos = line.find(delimiter);
		if (delim_pos == line.npos || delim_pos == line.length()) {
			SLOGW << "Invalid line '" << line << "' in key-value";
			continue;
		}

		const string key = line.substr(0, delim_pos);
		string value = line.substr(delim_pos + 1);

		kvMap[key] = value;
	}

	return kvMap;
}

bool iequals(string_view a, string_view b) {
	return equal(a.begin(), a.end(), b.begin(), b.end(), [](char a, char b) {
		return tolower(static_cast<unsigned char>(a)) == tolower(static_cast<unsigned char>(b));
	});
}

#ifdef HAVE_LIBLINPHONECXX
optional<linphone::MediaEncryption> string2MediaEncryption(const string& str) {
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

bool startsWith(const std::string_view& str, const std::string_view& prefix) noexcept {
	// https://stackoverflow.com/a/40441240
	return str.rfind(prefix, 0) == 0;
}
bool endsWith(const std::string& str, const std::string& suffix) noexcept {
	return str.size() >= suffix.size() && str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}
} // namespace flexisip::string_utils