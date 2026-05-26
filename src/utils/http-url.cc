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

#include "flexisip/utils/http-url.hh"

#include <filesystem>

using namespace std;

namespace flexisip {

HttpUrl::HttpUrl(std::string_view str) : HttpUrl(sofiasip::Url(str)) {}

HttpUrl::HttpUrl(const url_t* src) : HttpUrl(sofiasip::Url(src)) {}

HttpUrl::HttpUrl(const sofiasip::Url& src) : sofiasip::Url(src) {
	checkUrl(src);
}

HttpUrl::HttpUrl(sofiasip::Url&& src) {
	checkUrl(src);
	static_cast<sofiasip::Url*>(this)->operator=(std::move(src));
}

HttpUrl::Scheme HttpUrl::getSchemeType() const noexcept {
	return static_cast<Scheme>(getType());
}

HttpUrl HttpUrl::replacePath(std::string_view path) const {
	return HttpUrl{Url::replace(&url_t::url_path, normalizePath(path))};
}

HttpUrl HttpUrl::appendPath(std::string_view path) const {
	return replacePath(getPath() + "/" + path.data());
}

std::string HttpUrl::getAbsolutePath() const {
	return "/" + getPath();
}

std::optional<std::string> HttpUrl::hasParsingError(const sofiasip::Url& url) noexcept {
	const auto* pUrl = url.get();
	if (pUrl == nullptr) return std::nullopt;
	if (pUrl->url_scheme == nullptr) return "no scheme found";

	const auto schemeType = url.getType();
	if (schemeType != url_http && schemeType != url_https) {
		ostringstream os;
		os << "invalid scheme (" << pUrl->url_scheme << ")";
		return os.str();
	}

	if (pUrl->url_host == nullptr || pUrl->url_host[0] == '\0') {
		return "no host found";
	}

	return std::nullopt;
}

void HttpUrl::checkUrl(const sofiasip::Url& url) {
	auto parsingError = hasParsingError(url);
	if (parsingError) throw sofiasip::InvalidUrlError(url.str(), parsingError.value());
}

std::string HttpUrl::normalizePath(std::string_view path) {
	auto normalized = std::filesystem::path{path}.lexically_normal().generic_string();

	if (normalized.starts_with("/")) normalized.erase(0, 1);

	return normalized;
}

} // namespace flexisip