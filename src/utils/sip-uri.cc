/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022  Belledonne Communications SARL, All rights reserved.

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

#include <cstring>
#include <sstream>
#include <stdexcept>

#include "flexisip/configmanager.hh"
#include "flexisip/utils/sip-uri.hh"

#include "sofia-sip/url.h"

using namespace std;

namespace sofiasip {

Url::Url(const std::string &str) {
	if (str.empty()) return;
	_url = url_make(_home.home(), str.c_str());
	if (_url == nullptr) throw InvalidUrlError(str, "not an URI");
}

Url::Url(const url_t *src) noexcept {
	_url = url_hdup(_home.home(), src);
}

Url::Url(const Url &src) noexcept {
	_url = url_hdup(_home.home(), src.get());
	_urlAsStr = src._urlAsStr;
}

Url::Url(Url &&src) noexcept : _home(move(src._home)), _url(src._url), _urlAsStr(move(src._urlAsStr)) {
	src._url = nullptr;
}

Url &Url::operator=(const Url &src) noexcept {
	_home.reset();
	_url = url_hdup(_home.home(), src.get());
	_urlAsStr = src._urlAsStr;
	return *this;
}

Url &Url::operator=(Url &&src) noexcept {
	_home = move(src._home);
	_url = src._url, src._url = nullptr;
	_urlAsStr = move(src._urlAsStr);
	return *this;
}

const std::string &Url::str() const noexcept {
	if (_urlAsStr.empty() && _url) {
		sofiasip::Home home;
		_urlAsStr = url_as_string(home.home(), _url);
	}
	return _urlAsStr;
}

Url Url::replaceUser(const std::string &newUser) const {
	try {
		if (empty()) throw UrlModificationError("empty Url");
		url_t newUrl = *_url;
		newUrl.url_user = newUser.empty() ? nullptr : newUser.c_str();
		return Url(&newUrl);
	} catch (const InvalidUrlError &e) {
		ostringstream msg;
		msg << "replacing user part of '" << str() << "' by '" << newUser << "'";
		throw UrlModificationError(msg.str());
	}
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
			LOGF("Bad value for uri parameter '%s': %s", paramName.c_str(), e.what())
		}
	}
	return defaultValue;
}

TlsConfigInfo Url::getTlsConfigInfo() const {
	TlsConfigInfo tlsConfigInfo{};
	tlsConfigInfo.certifDir = getParam("tls-certificates-dir");

	tlsConfigInfo.certifFile = getParam("tls-certificates-file");
	tlsConfigInfo.certifPrivateKey = getParam("tls-certificates-private-key");
	tlsConfigInfo.certifCaFile = getParam("tls-certificates-ca-file");

	if (!tlsConfigInfo.certifDir.empty() && !tlsConfigInfo.certifFile.empty()) {
		LOGA("Transport can't use tls-certificates-dir AND tls-certificates-file/tls-certificates-private-key");
	} else if (tlsConfigInfo.certifFile.empty() != tlsConfigInfo.certifPrivateKey.empty()) {
		LOGA("If you specified tls-certificates-file in transport you MUST specify "
		     "tls-certificates-private-key too and vice versa");
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

} // end of sofiasip namespace

namespace flexisip {

SipUri::SipUri(const std::string &str): sofiasip::Url(str) {
	checkUrl(*this);
}

SipUri::SipUri(const url_t *src): sofiasip::Url(src) {
	checkUrl(*this);
}

SipUri::SipUri(const sofiasip::Url &src): SipUri(src.get()) {
}

SipUri::SipUri(sofiasip::Url &&src) {
	checkUrl(src);
	static_cast<sofiasip::Url *>(this)->operator=(move(src));
}

SipUri SipUri::replaceUser(const std::string &newUser) const {
	Url url = sofiasip::Url::replaceUser(newUser);
	return SipUri(move(url));
}

void SipUri::checkUrl(const sofiasip::Url &url) {
	const auto *pUrl = url.get();
	if (pUrl == nullptr) return;
	if (pUrl->url_scheme == nullptr) throw sofiasip::InvalidUrlError(url.str(), "no scheme found");
	if (strcmp(pUrl->url_scheme, "sip") != 0 && strcmp(pUrl->url_scheme, "sips") != 0) {
		ostringstream os;
		os << "invalid scheme (" << pUrl->url_scheme << ")";
		throw sofiasip::InvalidUrlError(url.str(), os.str());
	}
	if (pUrl->url_host == nullptr || pUrl->url_host[0] == '\0') {
		throw sofiasip::InvalidUrlError(url.str(), "no host found");
	}
	// SIP URIs with two '@' results in host part being "something@somewhere"
	if (strchr(pUrl->url_host, '@') != nullptr) {
		throw sofiasip::InvalidUrlError(url.str(), "forbidden '@' character found in host part");
	}
}

} // end of flexisip namespace
