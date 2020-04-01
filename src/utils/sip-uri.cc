#include <cstring>
#include <sstream>
#include <stdexcept>

#include <sofia-sip/url.h>

#include <flexisip/utils/sip-uri.hh>

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
		_urlAsStr = url_as_string(nullptr, _url);
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
	if (pUrl->url_scheme == nullptr) throw invalid_argument("no scheme found");
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
