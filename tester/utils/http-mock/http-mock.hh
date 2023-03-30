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

#pragma once

#include <future>
#include <optional>
#include <queue>
#include <string>

#include <nghttp2/asio_http2_server.h>

namespace ssl = boost::asio::ssl;

namespace flexisip {

class Request {
public:
	std::string body;
	std::string method;
	std::string path;
	nghttp2::asio_http2::header_map headers;
};

/**
 * A simple HTTP2/2 mock server
 */
class HttpMock {
public:
	HttpMock(const std::initializer_list<std::string> endpoints, std::atomic_int* requestReceivedCount = nullptr);
	~HttpMock() {
		forceCloseServer();
	}

	int serveAsync(const std::string& port = "0");
	void forceCloseServer();
	std::shared_ptr<Request> popRequestReceived();

private:
	void handleRequest(const nghttp2::asio_http2::server::request&, const nghttp2::asio_http2::server::response&);

	nghttp2::asio_http2::server::http2 mServer{};
	ssl::context mCtx;
	mutable std::recursive_mutex mMutex{};
	std::queue<std::shared_ptr<Request>> mRequestsReceived{};
	std::atomic<int>* mRequestReceivedCount{nullptr};
};

} // namespace flexisip
