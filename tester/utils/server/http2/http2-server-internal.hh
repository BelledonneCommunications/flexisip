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

#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <nghttp2/nghttp2.h>

#include "server/http2/http2-server.hh"

#include <boost/asio/ip/tcp.hpp>

namespace flexisip::tester::http_mock::server::detail {

class Http2Session;

class RequestState {
public:
	/**
	 * Add a callback to be executed once the request body is available.
	 * @note If the request body is already complete, the callback will be executed immediately.
	 */
	void registerNewCallback(Request::DataCb cb);
	/**
	 * Append data to the request body.
	 */
	void appendData(const uint8_t* data, size_t length);
	/**
	 * Trigger the execution of all registered data callbacks once the flag 'END_STREAM' is received for the request
	 * body (request body is complete and available).
	 */
	void onRequestBodyReceiptFinished();

	const std::string& getMethod() const;
	const HeaderMap& getHeaders() const;
	const UriRef& getUri() const;

	void setMethod(std::string method);
	void setUri(UriRef uri);
	void addHeader(std::string name, HeaderValue value);

private:
	std::string mMethod{};
	HeaderMap mHeaders{};
	UriRef mUri{};
	std::mutex mCallbacksMutex{};
	std::vector<Request::DataCb> mDataCallbacks{};
	std::string mBody{};
	bool mBodyComplete{false};
};

class ResponseState : public std::enable_shared_from_this<ResponseState> {
public:
	void setSession(std::weak_ptr<Http2Session> session);
	void setStreamId(int32_t streamId);

	void writeHead(unsigned int code);
	void sendResponse(std::optional<std::string> responseBody = std::nullopt);

private:
	friend class Http2Session;

	std::weak_ptr<Http2Session> mSession{};
	int32_t mStreamId{-1};
	unsigned int mStatusCode{200};
	std::string mBody{};
	size_t mBodyOffset{0};
	bool mEnded{false};
	std::mutex mStateMutex{};
};

class StreamState {
public:
	StreamState();

	std::shared_ptr<RequestState> mRequestState{};
	std::shared_ptr<ResponseState> mResponseState{};
	Request mRequestHandle;
	Response mResponseHandle;
	bool mHandlerInvoked{false};
};

class Http2ServerImpl : public std::enable_shared_from_this<Http2ServerImpl> {
public:
	Http2ServerImpl();
	~Http2ServerImpl();

	void handle(const std::string& pattern, RequestCb cb);

	int listenAndServe(boost::system::error_code& ec,
	                   boost::asio::ssl::context& ctx,
	                   const std::string& address,
	                   const std::string& port);

	void stop();
	void join();

	std::vector<uint16_t> getPorts() const;

	std::optional<RequestCb> findHandler(const std::string& path) const;

	void registerSession(const std::shared_ptr<Http2Session>& session);

private:
	void doAccept(boost::asio::ssl::context& ctx);

	static constexpr std::string_view mLogPrefix{"Http2ServerImpl"};
	std::shared_ptr<boost::asio::io_context> mIoContext{};
	boost::asio::executor_work_guard<boost::asio::io_context::executor_type> mWorkGuard;
	mutable std::mutex mMutex{};
	std::mutex mJoinMutex{};
	boost::asio::ip::tcp::acceptor mAcceptor;
	std::map<std::string, RequestCb> mHandlers{};
	std::set<std::shared_ptr<Http2Session>> mSessions{};
	std::vector<uint16_t> mPorts{};
	std::thread mThread{};
	bool mStarted{false};
	std::atomic_bool mStopping{false};
};

} // namespace flexisip::tester::http_mock::server::detail
