/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <algorithm>
#include <cctype>
#include <map>
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
	static std::vector<std::string> split(const std::string& str, const std::string& delimiter) noexcept;

	/* Remove surrounding double-quotes, if present */
	static std::string unquote(const std::string& str) noexcept {
		return strip(str, '"');
	}

	/**
	 * Compare string a and string b ignoring case.
	 */
	static bool iequals(const std::string& a, const std::string& b) {
		return std::equal(a.begin(), a.end(), b.begin(), b.end(),
		                  [](char a, char b) { return tolower(a) == tolower(b); });
	}

	/* Remove the surrounding given character, if present. */
	static std::string strip(const char* str, char c) noexcept;
	static std::string strip(const std::string& str, char c) noexcept;

	template <typename It>
	static void strip(It& start, It& end, typename std::iterator_traits<It>::value_type c) noexcept {
		if (end - start < 2) return;
		if (*start != c || *(end - 1) != c) return;
		start++;
		end--;
	}

	template <typename It, typename UnaryPredicate>
	static void stripAll(It& begin, It& end, UnaryPredicate predicate) noexcept {
		begin = std::find_if_not(begin, end, predicate);
		if (begin == end) return;
		std::reverse_iterator<It> rbegin{end}, rend{begin};
		rbegin = std::find_if_not(rbegin, rend, predicate);
		end = rbegin.base();
	}

	static std::string stripAll(const char* str, char c = ' ');
	static std::string stripAll(const std::string& str, char c = ' ');
	static void stripAll(std::string::const_iterator& start, std::string::const_iterator& end, char c = ' ');

	/**
	 * @brief Check whether the string 'str' starts with 'prefix' and returned the subsequent
	 * part of the string.
	 * @throw invalid_argument when 'str' doesn't start with 'prefix'.
	 */
	static std::string removePrefix(const std::string& str, const std::string& prefix);

	/**
	 * Replace any occurence of 'key' in 'str' by 'value'.
	 */
	static std::string& searchAndReplace(std::string& str, const std::string& key, const std::string& value) noexcept;

	/**
	 * Apply a modifying function on each character of
	 * the input string and return the result.
	 * @param str The string to modify.
	 * @param func A callable object that takes a character as
	 * argument and returns the modified character.
	 * @return The modified string.
	 */
	template <typename StrT, typename FuncT>
	static std::string transform(StrT&& str, FuncT&& func) noexcept {
		auto transStr = std::forward<StrT>(str);
		for (auto& c : transStr)
			c = func(c);
		return transStr;
	}

	/**
	 * Replace any character listed in 'transMap' keys by the according value.
	 */
	static std::string transform(const std::string& str, const std::map<char, std::string>& transMap) noexcept;

	/**
	 * Return the lower-case version of a string.
	 */
	template <typename StrT>
	static std::string toLower(StrT&& str) noexcept {
		return transform(std::forward<StrT>(str), [](const char& c) { return std::tolower(c); });
	}

	/**
	 * Return the upper-case version of a string.
	 */
	template <typename StrT>
	static std::string toUpper(StrT&& str) noexcept {
		return transform(std::forward<StrT>(str), [](const char& c) { return std::toupper(c); });
	}

	template <typename Iterable>
	static std::string toString(const Iterable& iterable) {
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
	static std::string toString(const Iterable& iterable, const Callable& format) {
		std::ostringstream os;
		os << "{ ";
		for (auto it = iterable.cbegin(); it != iterable.cend(); it++) {
			if (it != iterable.cbegin()) os << ", ";
			os << "'" << format(*it) << "'";
		}
		os << " }";
		return os.str();
	}

	// Returns 'true' if 'str' starts with 'prefix'.
	static bool startsWith(const std::string& str, const std::string& prefix) noexcept {
		return str.compare(0, prefix.size(), prefix) == 0;
	}

	// Returns 'true' if 'str' ends with 'prefix'.
	static bool endsWith(const std::string& str, const std::string& suffix) noexcept {
		return str.size() >= suffix.size() && str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
	}

	/**
	 * Concat all strings from the args parameter into one whitespace separated string.
	 *
	 * @tparam StringList Any container type with iterator available.
	 * @param args A container of strings to concat.
	 * @param fromIndex If you want not to start at the beginning of args. If fromIndex => args.size(), return an empty
	 * string.
	 * @return A string, can be empty, no trailing whitespace added.
	 */
	template <class StringList>
	static std::string join(const StringList& args, size_t fromIndex = 0) {
		std::string ret{""};
		if (args.size() <= fromIndex) {
			return ret;
		}

		auto iter = args.begin();
		std::advance(iter, fromIndex);
		for (; iter != args.end(); iter++) {
			ret.append(*iter).append(" ");
		}

		if (!ret.empty()) {
			ret.resize(ret.size() - 1);
		}

		return ret;
	}
};
