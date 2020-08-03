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

#include <cstring>
#include <string>

/**
 * @brief Defines some utility static methods around URI strings.
 */
class UriUtils {
public:

	/* Constants to use with escape() method */

	static constexpr const char *uriReserved = "!\"#$%&'()*+,/:;<=>?@[\\]^`{|}"; /**< Default reserved characters for generic URI */
	static constexpr const char *uriUserInfoReserved = "\"#%/<>?@[\\]^`{|}"; /**< Reserved characters for UserInfo part of generic URI, i.e. the part before '@' character */
	static constexpr const char *uriQueryReserved = "\"#%<>[\\]^`{|}"; /** Reserved characters for the query part of generic URI, i.e. the part between '?' and '#' */

	static constexpr const char *httpReserved = uriReserved; /**< Default reserved character for HTTP URI */
	static constexpr const char *httpQueryKeyValReserved = "\"#%&/<=>?[\\]^`{|}"; /**< Reserved characters for key or value of query elements in HTTP URI */

	static constexpr const char *sipReserved = "\"#$%&+,/:;<=>?@[\\]^`{|}"; /**< Default reserved character for SIP URI */
	static constexpr const char *sipUserReseverd = "\"#%:<>@[\\]^`{|}"; /**< Reserved characters for user in SIP URI */
	static constexpr const char *sipPasswordReserved = "\"#%/:;<>?@[\\]^`{|}"; /**< Reserved characters for passwords in SIP URI */
	static constexpr const char *sipUriParamValueReserved = "\"#&,;<=>@\\^`{|}%"; /**< Characters to be escaped for SIP URI param name and value. */

	/**
	 * @brief Escape all the characters in str that match one character of reserved.
	 *
	 * Each matching character is replaced by the escapement sequence
	 * defined in RFC 3986, i.e. a '%' character followed by two hexadecimal
	 * digits.
	 *
	 * @param[in] str The string to process.
	 * @param[in] reserved The set of characters that will be escaped in str. One
	 * of constants defined above may be used.
	 * @return A copy of str with all reserved characters escaped.
	 */
	static std::string escape(const char *str, const char *reserved) noexcept;
	static std::string escape(const std::string &str, const char *reserved) noexcept {return escape(str.c_str(), reserved);}

	/**
	 * @brief Replace each "% HEXDIG HEXDIG" sequence by the matching ASCII character.
	 */
	static std::string unescape(const char *str) noexcept {return unescape(str, strlen(str));}
	static std::string unescape(const std::string &str) noexcept {return unescape(str.c_str(), str.size());}

	/**
	 * @brief Return the value of a given param from a string that contains a list
	 * of 'param=value' elements separated by semi-colon character.
	 * @param paramList The string containing the list of parameter.
	 * @param paramName The name of the parameter whose value is to be gotten.
	 * @return The value of the parameter. If the parameter exists but has no value, then the return string is empty.
	 * @throw std::out_of_range The given paramter could not be found.
	 */
	static std::string getParamValue(const char *paramList, const char *paramName);
	static std::string getParamFromParamList(const std::string &paramList, const std::string &paramName) {return getParamValue(paramList.c_str(), paramName.c_str());}

	/**
	 * @brief Translate a UUID given by +sip.instance parameter into an
	 * UUID ready for GRUU generation.
	 *
	 * In other words, this function strips the input string from
	 * double-quotes and then '< >' characters. The return string is
	 * empty if the input string doesn't match the expected format.
	 */
	static std::string uniqueIdToGr(const std::string &uid) noexcept;

	/**
	 * @brief Format an UUID extracted for a GRUU into
	 * a string ready to used as vaule of +sip.instance parameter.
	 */
	static std::string grToUniqueId(const std::string &gr) noexcept;

private:
	static std::string unescape(const char *str, size_t n) noexcept;

	static constexpr size_t _bufferSize = 255;
};
