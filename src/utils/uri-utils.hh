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

#pragma once

#include <arpa/inet.h>

#include <cstring>
#include <optional>
#include <string>

#include <sofia-sip/url.h>

namespace flexisip {

/**
 * @brief Defines some utility functions around URI strings.
 */
namespace uri_utils {
/* Constants to use with escape() method */

/**< Default reserved characters for generic URI */
static constexpr const char* uriReserved = "!\"#$%&'()*+,/:;<=>?@[\\]^`{|}";

/**< Reserved characters for UserInfo part of generic URI, i.e. the part before '@' character */
static constexpr const char* uriUserInfoReserved = "\"#%/<>?@[\\]^`{|}";

/** Reserved characters for the query part of generic URI, i.e. the part between '?' and '#' */
static constexpr const char* uriQueryReserved = "\"#%<>[\\]^`{|}";

/**< Default reserved character for HTTP URI */
static constexpr const char* httpReserved = uriReserved;

/**< Reserved characters for key or value of query elements in HTTP URI */
static constexpr const char* httpQueryKeyValReserved = "\"#%&/<=>?[\\]^`{|}";

/**< Default reserved character for SIP URI */
static constexpr const char* sipReserved = "\"#$%&+,/:;<=>?@[\\]^`{|}";

/**< Reserved characters for user in SIP URI */
static constexpr const char* sipUserReserved = "\"#%:<>@[\\]^`{|}";

/**< Reserved characters for passwords in SIP URI */
static constexpr const char* sipPasswordReserved = "\"#%/:;<>?@[\\]^`{|}";

/**< Characters to be escaped for SIP URI param name and value. */
static constexpr const char* sipUriParamValueReserved = "\"#&,;<=>@\\^`{|}%";

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
std::string escape(const char* str, const char* reserved) noexcept;
inline std::string escape(const std::string& str, const char* reserved) noexcept {
	return escape(str.c_str(), reserved);
}

/**
 * @brief Replace each "% HEXDIG HEXDIG" sequence by the matching ASCII character.
 */
std::string unescape(const char* str) noexcept;
std::string unescape(const std::string& str) noexcept;

/**
 * @brief Return the value of a given param from a string that contains a list
 * of 'param=value' elements separated by semi-colon character.
 * @param paramList The string containing the list of parameter.
 * @param paramName The name of the parameter to seek.
 * @param defaultValue The string to return if the parameter doesn't exist or has no value.
 */
std::string getParamValue(const char* paramList, const char* paramName, const char* defaultValue = "") noexcept;

inline std::string getParamValue(const std::string& paramList, const std::string& paramName) noexcept {
	return getParamValue(paramList.c_str(), paramName.c_str());
}
std::string inline getParamValue(const std::string& paramList,
                                 const std::string& paramName,
                                 const std::string& defaultValue) noexcept {
	return getParamValue(paramList.c_str(), paramName.c_str(), defaultValue.c_str());
}

std::optional<std::string_view> getParamValueOpt(const char* paramList, const char* paramName) noexcept;
/**
 * @brief Translate a UUID given by +sip.instance parameter into an
 * UUID ready for GRUU generation.
 *
 * In other words, this function strips the input string from
 * double-quotes and then '< >' characters. The return string is
 * empty if the input string doesn't match the expected format.
 */
std::string uniqueIdToGr(const std::string& uid) noexcept;

/**
 * @brief Format an UUID extracted for a GRUU into
 * a string ready to used as vaule of +sip.instance parameter.
 */
std::string grToUniqueId(const std::string& gr) noexcept;

bool isIpv4Address(const char* str);
/**
 * @return true if str is a valid IPv6 address (hex notation or reference).
 */
bool isIpv6Address(const char* str);
/**
 * @warning this function will return false for IP6 references (i.e., IP6 addresses inside '[' ']').
 */
bool isIpv6HexAddress(const char* str);
/**
 * @warnig returns false if str is not a valid IP6 reference (i.e., hex notation without square brackets).
 */
bool isIpv6Reference(const char* str);

bool isIpAddress(const char* str);

std::optional<std::string> getConferenceId(const url_t& url) noexcept;

}; // namespace uri_utils

// NOLINTNEXTLINE(misc-unused-alias-decls) Deprecated alias to transition existing code smoothly
namespace UriUtils = uri_utils;

} // namespace flexisip