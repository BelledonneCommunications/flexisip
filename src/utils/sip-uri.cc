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
#include <sstream>
#include <stdexcept>
#include <string_view>

#include "sofia-sip/url.h"

#include "flexisip/configmanager.hh"

#include "exceptions/bad-configuration.hh"
#include "flexisip/utils/sip-uri.hh"
#include "utils/string-utils.hh"

using namespace std;

namespace sofiasip {

Url::Url(std::string_view str) {
	if (str.empty()) return;
	_url = url_make(_home.home(), str.data());
	if (_url == nullptr) THROW_LINE(InvalidUrlError, std::string(str), "not an URI");
	canonizeScheme();
}

Url::Url(const url_t* src) noexcept {
	_url = url_hdup(_home.home(), src);
	canonizeScheme();
}

Url::Url(const Url& src) noexcept {
	_url = url_hdup(_home.home(), src.get());
	_urlAsStr = src._urlAsStr;
}

Url::Url(Url&& src) noexcept : _home(std::move(src._home)), _url(src._url), _urlAsStr(std::move(src._urlAsStr)) {
	src._url = nullptr;
}

void Url::canonizeScheme() {
	const auto type = getType();
	switch (type) {
		case _url_none:
		case url_invalid:
		case url_unknown:
			// nothing to do
			break;
		default:
			_url->url_scheme = url_scheme(type);
	}
}

Url& Url::operator=(const Url& src) noexcept {
	_home.reset();
	_url = url_hdup(_home.home(), src.get());
	_urlAsStr = src._urlAsStr;
	return *this;
}

Url& Url::operator=(Url&& src) noexcept {
	_home = std::move(src._home);
	_url = src._url, src._url = nullptr;
	_urlAsStr = std::move(src._urlAsStr);
	return *this;
}

const std::string& Url::str() const noexcept {
	if (_urlAsStr.empty() && _url) {
		sofiasip::Home home;
		_urlAsStr = url_as_string(home.home(), _url);
	}
	return _urlAsStr;
}

Url Url::replace(const char* url_t::*attribute, std::string_view value) const {
	if (empty()) throw UrlModificationError{"url is empty, cannot replace attribute"};
	auto url = *_url;
	url.*attribute = value.empty() ? nullptr : value.data();
	return Url{&url};
}

std::string Url::getParam(const string& paramName) const {
	if (hasParam(paramName)) {
		char tmp[256] = {0};
		url_param(_url->url_params, paramName.c_str(), tmp, sizeof(tmp) - 1);
		return tmp;
	}
	return "";
}

bool Url::getBoolParam(const string& paramName, bool defaultValue) const {
	if (hasParam(paramName)) {
		char tmp[256] = {0};
		url_param(_url->url_params, paramName.c_str(), tmp, sizeof(tmp) - 1);
		try {
			bool ret = flexisip::ConfigBoolean::parse(tmp);
			return ret;
		} catch (flexisip::FlexisipException& e) {
			throw flexisip::FlexisipException{"invalid value for URI parameter '" + paramName + "' (" + e.what() + ")"};
		}
	}
	return defaultValue;
}

bool Url::compareAll(const Url& other) const {
	return url_cmp_all(_url, other._url) == 0;
}

TlsConfigInfo Url::getTlsConfigInfo() const {
	TlsConfigInfo tlsConfigInfo{};
	tlsConfigInfo.certifDir = getParam("tls-certificates-dir");

	tlsConfigInfo.certifFile = getParam("tls-certificates-file");
	tlsConfigInfo.certifPrivateKey = getParam("tls-certificates-private-key");
	tlsConfigInfo.certifCaFile = getParam("tls-certificates-ca-file");

	if (!tlsConfigInfo.certifDir.empty() && !tlsConfigInfo.certifFile.empty()) {
		throw flexisip::BadConfiguration{
		    "transport can't use tls-certificates-dir AND tls-certificates-file/tls-certificates-private-key"};
	} else if (tlsConfigInfo.certifFile.empty() != tlsConfigInfo.certifPrivateKey.empty()) {
		throw flexisip::BadConfiguration{"if you specified tls-certificates-file in transport you MUST specify "
		                                 "tls-certificates-private-key too and vice versa"};
	} else if (!tlsConfigInfo.certifDir.empty()) {
		tlsConfigInfo.mode = TlsMode::OLD;

		return tlsConfigInfo;
	} else if (!tlsConfigInfo.certifFile.empty()) {
		tlsConfigInfo.mode = TlsMode::NEW;

		return tlsConfigInfo;
	}

	return tlsConfigInfo;
}

void Url::removeParam(const string& paramName) {
	_url->url_params = url_strip_param_string(su_strdup(_home.home(), _url->url_params), paramName.c_str());
}

bool operator==(const TlsConfigInfo& lhs, const TlsConfigInfo& rhs) {
	if (lhs.mode == TlsMode::NONE && rhs.mode == TlsMode::NONE) {
		return true;
	} else if (lhs.mode == TlsMode::OLD && rhs.mode == TlsMode::OLD) {
		if (lhs.certifDir == rhs.certifDir) {
			return true;
		}
		return false;
	} else if (lhs.mode == TlsMode::NEW && rhs.mode == TlsMode::NEW) {
		if (lhs.certifFile == rhs.certifFile && lhs.certifPrivateKey == rhs.certifPrivateKey &&
		    lhs.certifCaFile == rhs.certifCaFile) {
			return true;
		}
		return false;
	}

	return false;
}

} // namespace sofiasip

namespace flexisip {

namespace {
std::pair<bool, std::string> isValidSipUriWithMessage(const sofiasip::Url& url) noexcept {
	const auto* pUrl = url.get();
	if (pUrl == nullptr) return std::pair(true, "");
	if (pUrl->url_scheme == nullptr) return std::pair(false, "no scheme found");
	const auto schemeType = url.getType();
	if (schemeType != url_sip && schemeType != url_sips) {
		ostringstream os;
		os << "invalid scheme (" << pUrl->url_scheme << ")";
		return std::pair(false, os.str());
	}
	if (pUrl->url_host == nullptr || pUrl->url_host[0] == '\0') {
		return std::pair(false, "no host found");
	}
	// SIP URIs with two '@' results in host part being "something@somewhere"
	if (strchr(pUrl->url_host, '@') != nullptr) {
		return std::pair(false, "forbidden '@' character found in host part");
	}
	return std::pair(true, "");
}
} // namespace

bool isValidSipUri(const url_t* url) {
	return isValidSipUriWithMessage(sofiasip::Url(url)).first;
}

SipUri::SipUri(std::string_view str) : sofiasip::Url(str) {
	checkUrl(*this);
}

SipUri::SipUri(const url_t* src) : sofiasip::Url(src) {
	checkUrl(*this);
}

SipUri::SipUri(const sofiasip::Url& src) : SipUri(src.get()) {
}

SipUri::SipUri(std::string_view userInfo, std::string_view hostport, Params params)
    : SipUri([&]() {
	      const string userInformation{userInfo.empty() ? "" : userInfo.data() + "@"s};

	      if (string_utils::toLower(params.getParameter("transport")) == "tls") {
		      params.removeParameter("transport");
		      return "sips:" + userInformation + hostport.data() + params.toString();
	      }

	      if (string_utils::toLower(params.getParameter("transport")) == "udp") params.removeParameter("transport");
	      return "sip:" + userInformation + hostport.data() + params.toString();
      }()) {
}

SipUri::SipUri(sofiasip::Url&& src) {
	checkUrl(src);
	static_cast<sofiasip::Url*>(this)->operator=(std::move(src));
}

SipUri SipUri::replaceUser(std::string_view newUser) const {
	return SipUri(Url::replace(&url_t::url_user, newUser));
}

SipUri SipUri::replaceHost(std::string_view newHost) const {
	return SipUri(Url::replace(&url_t::url_host, newHost));
}

SipUri SipUri::replacePort(std::string_view newPort) const {
	return SipUri(Url::replace(&url_t::url_port, newPort));
}

void SipUri::checkUrl(const sofiasip::Url& url) {
	auto [ok, msg] = isValidSipUriWithMessage(url);
	if (!ok) throw sofiasip::InvalidUrlError(url.str(), msg);
}

SipUri::Params::Params(const char* parameters) {
	if (parameters == nullptr) return;

	auto value = std::string();
	auto name = std::string();
	auto* current = &name;
	auto store = [&params = mParams, &value, &name] {
		if (name.empty()) {
			value.clear();
			return;
		}
		params.emplace(std::move(name), std::move(value));
	};
	for (; *parameters; parameters++) {
		switch (*parameters) {
			case ';':
				store();
				current = &name;
				break;
			case '=':
				current = &value;
				break;
			default:
				current->push_back(std::tolower(*parameters));
				break;
		}
	}
	store();
}

bool SipUri::Params::operator==(const SipUri::Params& other) const {
	// "A user, ttl, or method uri-parameter appearing in only one URI never matches, even if it contains the default
	// value"
	static const std::unordered_set<string> shouldBothHave = {"user", "ttl", "method"};

	for (const auto& pair : mParams) {
		const auto& name = pair.first;
		std::string theirs;
		try {
			theirs = other.mParams.at(name);
		} catch (const std::out_of_range& _) {
			// "A URI that includes an maddr parameter will not match a URI that contains no maddr parameter."
			if (shouldBothHave.count(name) || name == "maddr") return false;
			// "All other uri-parameters appearing in only one URI are ignored when comparing the URIs."
			continue;
		}
		if (theirs != pair.second) return false;
	}
	for (const auto& name : shouldBothHave) {
		if (other.mParams.count(name) && !mParams.count(name)) return false;
	}
	return true;
}

std::string SipUri::Params::getParameter(const std::string& name) const {
	if (const auto iterator = mParams.find(name); iterator != mParams.end()) return iterator->second;
	return {};
}

bool SipUri::Params::removeParameter(const std::string& name) {
	return mParams.erase(name) > 0;
}

std::string SipUri::Params::toString() const {
	std::string result{};
	for (const auto& [name, value] : mParams)
		result.append(";").append(name).append("=").append(value);
	return result;
}

bool SipUri::Params::empty() const {
	return mParams.empty();
}

SipUri::Headers::Headers(const char* c) {
	if (!c) return;

	enum Parsing { Name, Value };
	enum Case { Sensitive, Insensitive, ForcedSensitive, ForcedInsensitive };

	auto value = std::string();
	auto name = std::string();
	auto state = Parsing::Name;
	auto store = [&headers = mHeaders, &value, &name] {
		if (name.empty()) {
			value.clear();
			return;
		}
		headers.emplace(std::move(name), std::move(value));
	};
	// "Unless otherwise stated in the definition of a particular header field, field values,
	// parameter names, and parameter values are case-insensitive."
	auto caseSensitive = Case::Insensitive;
	for (; *c; c++) {
		switch (*c) {
			case '&':
				store();
				state = Parsing::Name;
				break;
			case '=': {
				switch (state) {
					case Parsing::Name:
						state = Parsing::Value;
						caseSensitive = Case::Insensitive;
						if (name == "call-id" || name == "i") {
							name = "call-id";
							caseSensitive = Case::ForcedSensitive;
						} else if (name == "content-encoding" || name == "e") {
							name = "content-encoding";
							caseSensitive = Case::ForcedInsensitive;
						} else if (name == "contact" || name == "m") {
							name = "contact";
							caseSensitive = Case::ForcedSensitive;
						} else if (name == "from" || name == "f") {
							name = "from";
							caseSensitive = Case::ForcedSensitive;
						} else if (name == "to" || name == "t") {
							name = "to";
							caseSensitive = Case::ForcedSensitive;
						} else if (name == "via" || name == "v") {
							name = "via";
							caseSensitive = Case::ForcedSensitive;
						} else if (name == "date") {
							caseSensitive = Case::ForcedSensitive;
						} else if (name == "content-length" || name == "l") {
							name = "content-length";
						} else if (name == "content-type" || name == "c") {
							name = "content-type";
						} else if (name == "subject" || name == "s") {
							name = "subject";
						} else if (name == "supported" || name == "k") {
							name = "supported";
						}
						break;

					case Parsing::Value:
						value.push_back('=');
						break;
				}
			} break;
			default: {
				switch (state) {
					case Parsing::Name:
						// "When comparing header fields, field names are always case-insensitive"
						name.push_back(std::tolower(*c));
						break;

					case Parsing::Value: {
						switch (caseSensitive) {
							case Case::Insensitive:
								// "Unless specified otherwise, values expressed as quoted strings are case-sensitive"
								if (*c == '"') caseSensitive = Case::Sensitive;
								/* fallthrough */
							case Case::ForcedInsensitive:
								value.push_back(std::tolower(*c));
								break;

							case Case::Sensitive:
								if (*c == '"') caseSensitive = Case::Insensitive;
								/* fallthrough */
							case Case::ForcedSensitive:
								value.push_back(*c);
								break;
						}
					} break;
				}
			} break;
		}
	}
	store();
}

bool SipUri::Headers::operator==(const SipUri::Headers& other) const {
	// "Any present header component MUST be present in both URIs"
	if (mHeaders.size() != other.mHeaders.size()) return false;

	static const std::unordered_set<string> specialChecks = {"contact", "from", "to"};

	for (const auto& pair : mHeaders) {
		const auto& name = pair.first;
		std::string theirs;
		try {
			theirs = other.mHeaders.at(name);
		} catch (const std::out_of_range& _) {
			return false;
		}

		if (specialChecks.count(name)) {
			if (!SipUri(theirs).rfc3261Compare(SipUri(pair.second))) return false;
		} else {
			// TODO: Parse and handle Via properly
			if (name == "via") LOGW << "'Via' SIP Header comparison is not properly implemented";
			if (theirs != pair.second) return false;
		}
	}

	return true;
}

bool SipUri::rfc3261Compare(const url_t* other) const {
	// Handles user, host, and port
	if (url_cmp(_url, other) != 0) return false;

	// uri-parameters
	if (Params(_url->url_params) != Params(other->url_params)) return false;

	// headers
	if (Headers(_url->url_headers) != Headers(other->url_headers)) return false;

	return true;
}

} // namespace flexisip