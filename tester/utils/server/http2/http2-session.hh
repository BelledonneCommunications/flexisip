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

#include <atomic>
#include <memory>
#include <mutex>
#include <string_view>
#include <thread>
#include <unordered_map>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <nghttp2/nghttp2.h>

#include "server/http2/http2-server-internal.hh"

namespace flexisip::tester::http_mock::server::detail {

class Http2Session : public std::enable_shared_from_this<Http2Session> {
public:
	Http2Session(boost::asio::ip::tcp::socket socket,
	             boost::asio::ssl::context& ctx,
	             std::weak_ptr<Http2ServerImpl> server);
	~Http2Session();

	void start();
	void stop();
	void join();
	void submitResponse(const std::shared_ptr<ResponseState>& responseState);

private:
	struct NgHttp2SessionDeleter {
		void operator()(nghttp2_session* session) const noexcept;
	};
	using NgHttp2SessionPtr = std::unique_ptr<nghttp2_session, NgHttp2SessionDeleter>;

	static constexpr std::string_view mLogPrefix{"Http2Server::Session"};

	static ssize_t sendCallback(nghttp2_session*, const uint8_t* data, size_t length, int, void* userData);
	static int onBeginHeaders(nghttp2_session*, const nghttp2_frame* frame, void* userData);
	static int onHeader(nghttp2_session*,
	                    const nghttp2_frame* frame,
	                    const uint8_t* name,
	                    size_t nameLength,
	                    const uint8_t* value,
	                    size_t valueLength,
	                    uint8_t flags,
	                    void* userData);
	static int onFrameRecv(nghttp2_session*, const nghttp2_frame* frame, void* userData);
	static int onDataChunkRecv(
	    nghttp2_session*, uint8_t flags, int32_t streamId, const uint8_t* data, size_t length, void* userData);
	static int onStreamClose(nghttp2_session*, int32_t streamId, uint32_t errorCode, void* userData);
	static ssize_t readResponseBody(nghttp2_session*,
	                                int32_t streamId,
	                                uint8_t* buffer,
	                                size_t length,
	                                uint32_t* dataFlags,
	                                nghttp2_data_source* source,
	                                void* userData);

	void run();
	void sendPendingFrames();
	void onStreamEnded(int32_t streamId);
	void dispatchHandler(int32_t streamId);

	boost::asio::ssl::stream<boost::asio::ip::tcp::socket> mStream;
	std::weak_ptr<Http2ServerImpl> mServer;
	std::thread mThread{};
	std::atomic_bool mStopping{false};
	std::mutex mSessionMutex{};
	std::mutex mJoinMutex{};
	NgHttp2SessionPtr mSession{};
	std::unordered_map<int32_t, std::shared_ptr<StreamState>> mStreams{};
	std::atomic_int mOpenStreams{0};
};

} // namespace flexisip::tester::http_mock::server::detail
