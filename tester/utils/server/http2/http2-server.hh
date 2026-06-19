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

#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio/ssl/context.hpp>

namespace flexisip::tester::http_mock {

class HeaderValue {
public:
	HeaderValue() = default;
	explicit HeaderValue(std::string value, bool sensitive = false);

	const std::string& getValue() const;
	bool getSensitive() const;

private:
	std::string mValue{};
	bool mSensitive{false};
};

using HeaderMap = std::multimap<std::string, HeaderValue>;

namespace server {

class UriRef {
public:
	UriRef() = default;
	explicit UriRef(std::string path);

	const std::string& getPath() const;

private:
	std::string mPath{};
};

namespace detail {
class RequestState;
class ResponseState;
class Http2ServerImpl;
} // namespace detail

class Request {
public:
	using DataCb = std::function<void(const uint8_t*, std::size_t)>;

	Request() = default;
	explicit Request(std::shared_ptr<detail::RequestState> state);

	const std::string& getMethod() const;
	const HeaderMap& getHeaders() const;
	const UriRef& getUri() const;
	void onData(DataCb cb) const;

private:
	std::shared_ptr<detail::RequestState> mState{};
};

class Response {
public:
	Response() = default;
	explicit Response(std::shared_ptr<detail::ResponseState> state);

	void writeHead(unsigned int statusCode, HeaderMap headers = {}) const;
	void send(std::string body = {}) const;

private:
	std::shared_ptr<detail::ResponseState> mState{};
};

using RequestCb = std::function<void(const Request&, const Response&)>;

class Http2 {
public:
	Http2();
	~Http2();

	void handle(const std::string& pattern, RequestCb cb);
	int listenAndServe(boost::system::error_code& ec,
	                   boost::asio::ssl::context& ctx,
	                   const std::string& address,
	                   const std::string& port);

	void stop();
	void join();

	std::vector<uint16_t> getPorts() const;

private:
	std::shared_ptr<detail::Http2ServerImpl> mImpl{};
};

} // namespace server
} // namespace flexisip::tester::http_mock
