/*a
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include <optional>

#include "flexisip/sofia-wrapper/su-root.hh"

#include "lib/nlohmann-json-3-11-2/json.hpp"
#include "utils/transport/http/http-message-context.hh"
#include "utils/transport/http/http2client.hh"

namespace flexisip {

class RestClient {
public:
	using OnErrorCb = HttpMessageContext::OnErrorCb;
	using OnResponseCb = HttpMessageContext::OnResponseCb;

	explicit RestClient(const std::shared_ptr<Http2Client>& http) : mHttp(http) {
	}
	RestClient(const std::shared_ptr<Http2Client>& http, const HttpHeaders& customsHeaders)
	    : mHttp(http), mCustomHeaders(customsHeaders) {
	}

	void get(const std::string& path, const OnResponseCb& onResponseCb, const OnErrorCb& onErrorCb);

	template <class JsonObject>
	void post(const std::string& path,
	          const JsonObject& jsonObject,
	          const OnResponseCb& onResponseCb,
	          const OnErrorCb& onErrorCb) {
		httpCall(path, "POST", jsonObject, onResponseCb, onErrorCb);
	}
	template <class JsonObject>
	void post(const std::string& path,
	          const JsonObject& jsonObject,
	          const std::string& responseLog,
	          const std::string& errorLog) {
		post(
		    path, jsonObject, [responseLog](const auto&, const auto&) { SLOGI << responseLog; },
		    [errorLog](const auto&) { SLOGE << errorLog; });
	}

	template <class JsonObject>
	void put(const std::string& path,
	         const JsonObject& jsonObject,
	         const OnResponseCb& onResponseCb,
	         const OnErrorCb& onErrorCb) {
		httpCall(path, "PUT", jsonObject, onResponseCb, onErrorCb);
	}
	template <class JsonObject>
	void put(const std::string& path,
	         const JsonObject& jsonObject,
	         const std::string& responseLog,
	         const std::string& errorLog) {
		put(
		    path, jsonObject, [responseLog](const auto&, const auto&) { SLOGI << responseLog; },
		    [errorLog](const auto&) { SLOGE << errorLog; });
	}

	template <class JsonObject>
	void patch(const std::string& path,
	           const JsonObject& jsonObject,
	           const OnResponseCb& onResponseCb,
	           const OnErrorCb& onErrorCb) {
		httpCall(path, "PATCH", jsonObject, onResponseCb, onErrorCb);
	}
	template <class JsonObject>
	void patch(const std::string& path,
	           const JsonObject& jsonObject,
	           const std::string& responseLog,
	           const std::string& errorLog) {
		patch(
		    path, jsonObject, [responseLog](const auto&, const auto&) { SLOGI << responseLog; },
		    [errorLog](const auto&) { SLOGE << errorLog; });
	}

private:
	void httpCall(const std::string& path,
	              const std::string& method,
	              const std::optional<nlohmann::json>& jsonObject,
	              const OnResponseCb& onResponseCb,
	              const OnErrorCb& onErrorCb);

	std::shared_ptr<Http2Client> mHttp;
	HttpHeaders mCustomHeaders{};
};

} // namespace flexisip
