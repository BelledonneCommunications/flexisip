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

#include <algorithm>
#include <sstream>
#include <string>
#include <vector>

class StringUtils {
public:
	/**
	 * Splits the string by using a delimiter and returns each substrings into a vector.
	 * @param[in] str The string to split. An empty string results to an empty vector.
	 * @param[in] delimiter The delimiter which encloses each substrings. An empty delimiter,
	 * results to a vector containing the entire string (one element).
	 */
	static std::vector<std::string> split (const std::string &str, const std::string &delimiter) noexcept;

	/* Remove surrounding double-quotes, if present */
	static std::string unquote(const std::string &str) noexcept {return strip(str, '"');}

	/* Remove the surrounding given character, if present. */
	static std::string strip(const char *str, char c) noexcept;
	static std::string strip(const std::string &str, char c) noexcept;

	template <typename It>
	static void strip(It &start, It &end, typename std::iterator_traits<It>::value_type c) noexcept {
		if (end - start < 2) return;
		if (*start != c || *(end-1) != c) return;
		start++;
		end--;
	}

	template <typename It, typename UnaryPredicate>
	static void stripAll(It &begin, It &end, UnaryPredicate predicate) noexcept {
		begin = std::find_if_not(begin, end, predicate);
		if (begin == end) return;
		std::reverse_iterator<It> rbegin{end}, rend{begin};
		rbegin = std::find_if_not(rbegin, rend, predicate);
		end = rbegin.base();
	}

	/**
	 * @brief Check whether the string 'str' starts with 'prefix' and returned the subsequent
	 * part of the string.
	 * @throw invalid_argument when 'str' doesn't start with 'prefix'.
	 */
	static std::string removePrefix(const std::string &str, const std::string &prefix);

	template <typename Iterable>
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

	template <typename Iterable, typename Callable>
	static std::string toString(const Iterable &iterable, const Callable &format) {
		std::ostringstream os;
		os << "{ ";
		for (auto it = iterable.cbegin(); it != iterable.cend(); it++) {
			if (it != iterable.cbegin()) os << ", ";
			os << "'" << format(*it) << "'";
		}
		os << " }";
		return os.str();
	}
};
