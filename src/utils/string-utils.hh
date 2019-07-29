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

#pragma once

#include <sstream>
#include <string>
#include <vector>

class StringUtils {
public:
	static std::vector<std::string> split (const std::string &str, const std::string &delimiter);

	static std::string unquote(const std::string & str){
		return strip(str, '"');
	}
	static std::string strip(const char *str, char c);
	static std::string strip(const std::string &str, char c);
	static void strip(std::string::const_iterator &start, std::string::const_iterator &end, char c);

	static std::string stripAll(const char *str, char c = ' ');
	static std::string stripAll(const std::string &str, char c = ' ');
	static void stripAll(std::string::const_iterator &start, std::string::const_iterator &end, char c = ' ');

	/**
	 * @brief Check whether the string 'str' starts with 'prefix' and returned the subsequent
	 * part of the string.
	 * @throw invalid_argument when 'str' doesn't start with 'prefix'.
	 */
	static std::string removePrefix(const std::string &str, const std::string &prefix);

	template <class Iterable>
	static std::string toString(const Iterable &iterable) {
		std::ostringstream os;
		os << "{ ";
		for (auto it = iterable.cbegin(); it != iterable.cend(); it++) {
			if (it != iterable.cbegin()) os << ", ";
			os << "'" << *it << "'";
		}
		os << " }";
		return os.str();
	}
};
