/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/sofia-wrapper/url.hh"

#include <string_view>

#include "sofia-sip/url.h"

#include "exceptions/bad-configuration.hh"
#include "flexisip/configmanager.hh"
#include "utils/uri-utils.hh"

using namespace std;

namespace sofiasip {

Url::Url(url_type_e type) {
	_url = static_cast<url_t*>(su_alloc(_home.home(), sizeof(url_t)));
	url_init(_url, type);
}

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

Url Url::replace(const char* url_t::* attribute, std::string_view value) const {
	if (empty()) throw UrlModificationError{"url is empty, cannot replace attribute"};
	auto url = *_url;
	url.*attribute = value.empty() ? nullptr : value.data();
	return Url{&url};
}

Url Url::setParam(const std::string& name, const std::string& value) const {
	auto url = Url{_url};
	if (url.hasParam(name)) url.removeParam(name);
	const auto parameter = name + (value.empty() ? "" : ("=" + value));
	url_param_add(url._home.home(), url._url, parameter.c_str());
	return Url{url._url};
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

template <>
string Url::extractParam<string>(const char* param) {
	const auto value = getParam(param);
	if (value.empty()) return {};

	removeParam(param);
	return flexisip::uri_utils::unescape(value);
}

template <>
int Url::extractParam<int>(const char* param) {
	try {
		return stoi(extractParam<string>(param));
	} catch (...) {
		return 0;
	}
}

template <>
uintptr_t Url::extractParam<uintptr_t>(const char* param) {
	try {
		return stoul(extractParam<string>(param), nullptr, 16);
	} catch (...) {
		return 0;
	}
}

template <>
time_t Url::extractParam<time_t>(const char* param) {
	try {
		return stoull(extractParam<string>(param));
	} catch (...) {
		return 0;
	}
}

template <>
bool Url::extractParam<bool>(const char* param) {
	const auto extractedParam = extractParam<string>(param);
	return !extractedParam.empty() && extractedParam.find("yes") != string::npos;
}

bool Url::compareAll(const Url& other) const {
	return url_cmp_all(_url, other._url) == 0;
}

TlsConfigInfo Url::getTlsConfigInfo() const {
	TlsConfigInfo tlsConfigInfo{};
	tlsConfigInfo.certifFile = getParam("tls-certificates-file");
	tlsConfigInfo.certifPrivateKey = getParam("tls-certificates-private-key");
	tlsConfigInfo.certifCaFile = getParam("tls-certificates-ca-file");

	if (tlsConfigInfo.certifFile.empty() != tlsConfigInfo.certifPrivateKey.empty()) {
		throw flexisip::BadConfiguration{"if you specified tls-certificates-file in transport you MUST specify "
		                                 "tls-certificates-private-key too and vice versa"};
	}
	if (!tlsConfigInfo.certifFile.empty()) {
		tlsConfigInfo.mode = TlsMode::FILES;

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
	} else if (lhs.mode == TlsMode::FILES && rhs.mode == TlsMode::FILES) {
		if (lhs.certifFile == rhs.certifFile && lhs.certifPrivateKey == rhs.certifPrivateKey &&
		    lhs.certifCaFile == rhs.certifCaFile) {
			return true;
		}
		return false;
	}

	return false;
}

} // namespace sofiasip