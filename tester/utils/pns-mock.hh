/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

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

#pragma once

#include <string>

#include <nghttp2/asio_http2_server.h>

namespace flexisip {
namespace pushnotification {

/**
 * A simple HTTP2/2 server with the only purpose of mocking Push Notification Service for testing.
 */
class PnsMock {
public:
	PnsMock() = default;

	/**
	 * Expose a mock server answering every request with the same code and body passed as parameters.
	 * Aimed to be used asynchronously.
	 *
	 * @param code The HTTP status code to return.
	 * @param body The response body to return.
	 * @param reqBodyPattern Match the received request against this regex pattern.
	 * @param barrier A std::promise used as a barrier to notified caller when the server is started.
	 * @param timeout Simulate a response timeout if set to true.
	 *
	 * @return True if the received request match reqBodyPattern, false otherwise.
	 */
	bool exposeMock(int code, const std::string& body, const std::string& reqBodyPattern, std::promise<bool>&& barrier,
	                bool timeout = false);
	void forceCloseServer();

private:
	nghttp2::asio_http2::server::http2 mServer{};

	std::function<void(const nghttp2::asio_http2::server::request&, const nghttp2::asio_http2::server::response&)>
	handleRequest(int code, const std::string& body, const std::string& reqBodyPattern, bool& assert, bool timeout);
};

} // namespace pushnotification
} // namespace flexisip
