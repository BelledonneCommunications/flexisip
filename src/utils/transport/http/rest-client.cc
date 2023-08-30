/*
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

#include "rest-client.hh"

using namespace std;
using namespace nlohmann;
using namespace flexisip;

void RestClient::httpCall(const string& path,
                          const string& method,
                          const optional<json>& jsonObject,
                          const OnResponseCb& onResponseCb,
                          const OnErrorCb& onErrorCb) {
	const auto body = jsonObject ? to_string(jsonObject.value()) : "";
	const auto bodySize = to_string(body.size());

	HttpHeaders headers;
	headers.add(":method", method);
	headers.add(":scheme", "https");
	headers.add(":path", path);
	headers.concat(mCustomHeaders);
	headers.add("content-length", bodySize);

	auto request = make_shared<Http2Client::HttpRequest>(headers, body);

	mHttp->send(request, onResponseCb, onErrorCb);
}

void RestClient::get(const string& path,
                     const RestClient::OnResponseCb& onResponseCb,
                     const RestClient::OnErrorCb& onErrorCb) {
	httpCall(path, "GET", nullopt, onResponseCb, onErrorCb);
}
