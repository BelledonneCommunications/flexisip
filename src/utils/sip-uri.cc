#include <cstring>
#include <sstream>
#include <stdexcept>

#include <sofia-sip/url.h>

#include "sip-uri.hh"

using namespace std;

namespace sofiasip {

Url::Url(const std::string &str) {
	if (str.empty()) return;
	_url.reset(url_make(nullptr, str.c_str()));
	if (_url == nullptr) throw invalid_argument("parsing failed");
}

Url::Url(const url_t *src) {
	_url.reset(url_hdup(nullptr, src));
}

Url::Url(const Url &src) noexcept {
	_url.reset(url_hdup(nullptr, src.get()));
	_urlAsStr = src._urlAsStr;
}

Url::Url(Url &&src) noexcept = default;

Url::~Url() = default;

Url &Url::operator=(const Url &src) noexcept {
	_url.reset(url_hdup(nullptr, src.get()));
	_urlAsStr = src._urlAsStr;
	return *this;
}

Url &Url::operator=(Url &&src) noexcept = default;

const std::string &Url::str() const noexcept {
	if (_urlAsStr.empty() && _url) {
		_urlAsStr = url_as_string(nullptr, _url.get());
	}
	return _urlAsStr;
}

#define getUrlAttr(attr) _url && _url->attr ? _url->attr : ""

std::string Url::getScheme() const noexcept {
	return getUrlAttr(url_scheme);
}

std::string Url::getUser() const noexcept {
	return getUrlAttr(url_user);
}

std::string Url::getPassword() const noexcept {
	return getUrlAttr(url_password);
}

std::string Url::getHost() const noexcept {
	return getUrlAttr(url_host);
}

std::string Url::getPort() const noexcept {
	return getUrlAttr(url_port);
}

std::string Url::getPath() const noexcept {
	return getUrlAttr(url_path);
}

std::string Url::getParams() const noexcept {
	return getUrlAttr(url_params);
}

std::string Url::getHeaders() const noexcept {
	return getUrlAttr(url_headers);
}

std::string Url::getFragment() const noexcept {
	return getUrlAttr(url_fragment);
}

#undef getUrlAttr

const std::function<void(void *)> Url::suObjectDeleter = [](void *obj){su_free(nullptr, obj);};

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

void SipUri::checkUrl(const sofiasip::Url &url) {
	const auto *pUrl = url.get();
	if (pUrl == nullptr) return;
	if (pUrl->url_scheme == nullptr) throw invalid_argument("no scheme found");
	if (strcmp(pUrl->url_scheme, "sip") != 0 && strcmp(pUrl->url_scheme, "sips") != 0) {
		ostringstream os;
		os << "invalid scheme (" << pUrl->url_scheme << ")";
		throw invalid_argument(os.str());
	}
	if (pUrl->url_host == nullptr || pUrl->url_host[0] == '\0') {
		throw invalid_argument("no host found");
	}
}

} // end of flexisip namespace
