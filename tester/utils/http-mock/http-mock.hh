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
#include <mutex>
#include <optional>
#include <queue>
#include <string>

#include "server/http2/http2-server.hh"

namespace ssl = boost::asio::ssl;

namespace flexisip::tester::http_mock {

class Request {
public:
	std::string body;
	std::string method;
	std::string path;
	std::string authority;
	HeaderMap headers;
};

class HttpMock;

using HttpMockHandler =
    std::function<void(HttpMock& httpMock, const server::Request& req, const server::Response& res)>;
/**
 * A simple HTTP2/2 mock server
 */
class HttpMock {
public:
	static constexpr auto kDefaultResponse = "200 OK";
	static constexpr auto kDefaultError = "404 NotFound";

	HttpMock();
	explicit HttpMock(const std::map<std::string, HttpMockHandler>& handlers);
	HttpMock(const std::initializer_list<std::string> endpoints);
	~HttpMock() {
		forceCloseServer();
	}

	/**
	 * Add an handler for this mock.
	 * MUST be called before 'serverAsync'.
	 * @param path Custom path that the mock server will serve.
	 * @param handler Custom handler for the provided path.
	 */
	void addHandler(const std::string& path, const HttpMockHandler& handler);

	/**
	 * Add an endpoint for this mock.
	 * MUST be called before 'serverAsync'.
	 * @param path Custom path that the mock server will serve.
	 * @param response Custom response for the provided path.
	 */
	void addEndpoint(const std::string& path, const std::string& response = "");

	/**
	 * Set the IP address that will be bind.
	 * MUST be called before 'serverAsync' otherwise the mock will listen to 127.0.0.1.
	 * @param ipAddress
	 */
	void setListeningAddress(const std::string& ipAddress);

	int serveAsync(const std::string& port = "0");
	void forceCloseServer();
	std::shared_ptr<Request> popRequestReceived();

	// Stops processing until the lock is released (lock_guard destructed)
	std::lock_guard<std::recursive_mutex> pauseProcessing();

	/**
	 * Specify a response to a GET request
	 * return false if the endpoint is unknown and the response cannot be added
	 */
	bool addResponseToGET(const std::string& endpoint, const std::string& response);

	int getFirstPort() const;

	int getRequestReceivedCount() const;
	void resetRequestReceivedCount();

private:
	void handleRequest(const server::Request&, const server::Response&, const std::string& endpoint);

	static constexpr std::string_view mLogPrefix{"HttpMock"};
	server::Http2 mServer{};
	ssl::context mCtx;
	mutable std::recursive_mutex mMutex{};
	std::queue<std::shared_ptr<Request>> mRequestsReceived{};
	std::map<std::string, std::string> mGETResponse;
	std::string mAddress = "127.0.0.1";
	std::atomic_int mRequestReceivedCount{0};
};

} // namespace flexisip::tester::http_mock
