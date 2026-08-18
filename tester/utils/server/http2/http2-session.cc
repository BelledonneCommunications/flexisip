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

#include "server/http2/http2-session.hh"

#include <algorithm>
#include <array>
#include <cstring>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio/ssl/error.hpp>
#include <nghttp2/nghttp2.h>
#include <openssl/ssl.h>

#include "flexisip/logmanager.hh"
#include "server/http2/http2-server.hh"
#include "utils/string-utils.hh"

using namespace std;
namespace asio = boost::asio;
namespace ssl = boost::asio::ssl;

namespace flexisip::tester::http_mock::server::detail {

namespace {

string extractPath(const string& pathWithQuery) {
	const auto queryPos = pathWithQuery.find('?');
	return queryPos == string::npos ? pathWithQuery : pathWithQuery.substr(0, queryPos);
}

vector<nghttp2_nv> makeHeaders(const vector<pair<string, string>>& input) {
	vector<nghttp2_nv> result;
	result.reserve(input.size());
	for (const auto& [name, value] : input) {
		result.push_back(nghttp2_nv{
		    reinterpret_cast<uint8_t*>(const_cast<char*>(name.data())),
		    reinterpret_cast<uint8_t*>(const_cast<char*>(value.data())),
		    name.size(),
		    value.size(),
		    NGHTTP2_NV_FLAG_NONE,
		});
	}
	return result;
}

} // namespace

Http2Session::Http2Session(boost::asio::ip::tcp::socket socket, ssl::context& ctx, weak_ptr<Http2ServerImpl> server)
    : mStream(std::move(socket), ctx), mServer(std::move(server)) {}

Http2Session::~Http2Session() {
	stop();
}

void Http2Session::start() {
	auto self = shared_from_this();
	mThread = thread([self]() { self->run(); });
}

void Http2Session::stop() {
	if (mStopping.exchange(true)) return;

	boost::system::error_code ec;
	mStream.lowest_layer().cancel(ec);
	mStream.lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
	mStream.lowest_layer().close(ec);
}

void Http2Session::join() {
	std::unique_lock lock(mJoinMutex);

	if (mThread.joinable()) {
		mThread.join();
	}
}

void Http2Session::submitResponse(const shared_ptr<ResponseState>& responseState) {
	lock_guard<mutex> lock(mSessionMutex);
	if (!mSession) return;

	vector<pair<string, string>> headers = {
	    {":status", to_string(responseState->mStatusCode)},
	    {"content-length", to_string(responseState->mBody.size())},
	};
	auto headerNameValues = makeHeaders(headers);
	const int submitResult = [&]() {
		if (responseState->mBody.empty()) {
			return nghttp2_submit_response(mSession.get(), responseState->mStreamId, headerNameValues.data(),
			                               headerNameValues.size(), nullptr);
		}
		nghttp2_data_provider provider{};
		provider.source.ptr = responseState.get();
		provider.read_callback = &Http2Session::readResponseBody;
		return nghttp2_submit_response(mSession.get(), responseState->mStreamId, headerNameValues.data(),
		                               headerNameValues.size(), &provider);
	}();
	if (submitResult < 0) {
		LOGE_CTX(mLogPrefix) << "failed to submit HTTP/2 response: " << nghttp2_strerror(submitResult);
		return;
	}
	sendPendingFrames();
}

void Http2Session::NgHttp2SessionDeleter::operator()(nghttp2_session* session) const noexcept {
	nghttp2_session_del(session);
}

ssize_t Http2Session::sendCallback(nghttp2_session*, const uint8_t* data, size_t length, int, void* userData) {
	auto& self = *static_cast<Http2Session*>(userData);
	boost::system::error_code ec;
	const auto written = asio::write(self.mStream, asio::buffer(data, length), ec);
	if (ec) {
		LOGE_CTX(mLogPrefix, "sendCallback") << "HTTP/2 server write failed: " << ec.message();
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
	return static_cast<ssize_t>(written);
}

int Http2Session::onBeginHeaders(nghttp2_session*, const nghttp2_frame* frame, void* userData) {
	if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) return 0;
	auto& self = *static_cast<Http2Session*>(userData);
	auto stream = make_shared<StreamState>();
	stream->mResponseState->setSession(self.shared_from_this());
	stream->mResponseState->setStreamId(frame->hd.stream_id);
	self.mOpenStreams.fetch_add(1);
	self.mStreams[frame->hd.stream_id] = std::move(stream);
	return 0;
}

int Http2Session::onHeader(nghttp2_session*,
                           const nghttp2_frame* frame,
                           const uint8_t* name,
                           size_t nameLength,
                           const uint8_t* value,
                           size_t valueLength,
                           uint8_t,
                           void* userData) {
	if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) return 0;
	auto& self = *static_cast<Http2Session*>(userData);
	auto streamIt = self.mStreams.find(frame->hd.stream_id);
	if (streamIt == self.mStreams.end()) return 0;

	const string headerName(reinterpret_cast<const char*>(name), nameLength);
	const string headerValue(reinterpret_cast<const char*>(value), valueLength);
	if (headerName == ":method") {
		streamIt->second->mRequestState->setMethod(headerValue);
	} else if (headerName == ":path") {
		streamIt->second->mRequestState->setUri(UriRef{extractPath(headerValue)});
	} else if (headerName == ":authority") {
		streamIt->second->mRequestState->setAuthority(headerValue);
	} else if (!headerName.empty() && headerName[0] != ':') {
		streamIt->second->mRequestState->addHeader(string_utils::toLower(headerName), HeaderValue{headerValue});
	}
	return 0;
}

int Http2Session::onFrameRecv(nghttp2_session*, const nghttp2_frame* frame, void* userData) {
	auto& self = *static_cast<Http2Session*>(userData);
	if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
		self.dispatchHandler(frame->hd.stream_id);
		if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
			self.onStreamEnded(frame->hd.stream_id);
		}
		return 0;
	}
	if (frame->hd.type == NGHTTP2_DATA && (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
		self.onStreamEnded(frame->hd.stream_id);
	}
	return 0;
}

int Http2Session::onDataChunkRecv(
    nghttp2_session*, uint8_t, int32_t streamId, const uint8_t* data, size_t length, void* userData) {
	auto& self = *static_cast<Http2Session*>(userData);
	const auto streamIt = self.mStreams.find(streamId);
	if (streamIt == self.mStreams.end()) return 0;
	streamIt->second->mRequestState->appendData(data, length);
	return 0;
}

int Http2Session::onStreamClose(nghttp2_session*, int32_t streamId, uint32_t, void* userData) {
	auto& self = *static_cast<Http2Session*>(userData);
	self.mStreams.erase(streamId);
	self.mOpenStreams.fetch_sub(1);
	return 0;
}

ssize_t Http2Session::readResponseBody(nghttp2_session*,
                                       int32_t,
                                       uint8_t* buffer,
                                       size_t length,
                                       uint32_t* dataFlags,
                                       nghttp2_data_source* source,
                                       void*) {
	auto* responseState = static_cast<ResponseState*>(source->ptr);
	const auto remaining = responseState->mBody.size() - responseState->mBodyOffset;
	const auto bytesToCopy = min(length, remaining);
	memcpy(buffer, responseState->mBody.data() + responseState->mBodyOffset, bytesToCopy);
	responseState->mBodyOffset += bytesToCopy;
	if (responseState->mBodyOffset >= responseState->mBody.size()) {
		*dataFlags |= NGHTTP2_DATA_FLAG_EOF;
	}
	return static_cast<ssize_t>(bytesToCopy);
}

void Http2Session::run() {
	boost::system::error_code ec;
	mStream.handshake(ssl::stream_base::server, ec);
	if (ec) {
		if (ec != asio::error::operation_aborted) {
			LOGE_CTX(mLogPrefix) << "HTTP/2 mock handshake failed: " << ec.message();
		}
		return;
	}

	const unsigned char* negotiatedProto = nullptr;
	unsigned int negotiatedProtoLength = 0;
	SSL_get0_alpn_selected(mStream.native_handle(), &negotiatedProto, &negotiatedProtoLength);
	if (negotiatedProtoLength != 2 || memcmp(negotiatedProto, "h2", 2) != 0) {
		LOGE_CTX(mLogPrefix) << "HTTP/2 mock did not negotiate h2";
		return;
	}

	nghttp2_session_callbacks* callbacks = nullptr;
	nghttp2_session_callbacks_new(&callbacks);
	nghttp2_session_callbacks_set_send_callback(callbacks, &Http2Session::sendCallback);
	nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, &Http2Session::onBeginHeaders);
	nghttp2_session_callbacks_set_on_header_callback(callbacks, &Http2Session::onHeader);
	nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, &Http2Session::onFrameRecv);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, &Http2Session::onDataChunkRecv);
	nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, &Http2Session::onStreamClose);

	nghttp2_session* rawSession = nullptr;
	const auto newResult = nghttp2_session_server_new(&rawSession, callbacks, this);
	nghttp2_session_callbacks_del(callbacks);
	if (newResult != 0) {
		LOGE_CTX(mLogPrefix) << "failed to create HTTP/2 server session: " << nghttp2_strerror(newResult);
		return;
	}
	mSession.reset(rawSession);

	array<nghttp2_settings_entry, 1> settings = {
	    nghttp2_settings_entry{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 1000},
	};
	if (const auto submitResult =
	        nghttp2_submit_settings(mSession.get(), NGHTTP2_FLAG_NONE, settings.data(), settings.size());
	    submitResult < 0) {
		LOGE_CTX(mLogPrefix) << "failed to submit HTTP/2 settings: " << nghttp2_strerror(submitResult);
		return;
	}
	sendPendingFrames();

	array<uint8_t, 16 * 1024> buffer{};
	while (!mStopping) {
		const auto bytesRead = mStream.read_some(asio::buffer(buffer), ec);
		if (ec) {
			if (ec != asio::error::eof && ec != asio::ssl::error::stream_truncated &&
			    ec != asio::error::operation_aborted) {
				LOGE_CTX(mLogPrefix) << "HTTP/2 mock read failed: " << ec.message();
			}
			break;
		}
		const auto recvResult = nghttp2_session_mem_recv(mSession.get(), buffer.data(), bytesRead);
		if (recvResult < 0) {
			LOGE_CTX(mLogPrefix) << "HTTP/2 mock receive failed: " << nghttp2_strerror(recvResult);
			break;
		}
		sendPendingFrames();
	}
	stop();
}

void Http2Session::sendPendingFrames() {
	if (!mSession) return;
	if (const auto result = nghttp2_session_send(mSession.get()); result < 0) {
		LOGE_CTX(mLogPrefix) << "HTTP/2 mock send failed: " << nghttp2_strerror(result);
	}
}

void Http2Session::onStreamEnded(int32_t streamId) {
	const auto streamIt = mStreams.find(streamId);
	if (streamIt == mStreams.end()) return;
	streamIt->second->mRequestState->onRequestBodyReceiptFinished();
}

void Http2Session::dispatchHandler(int32_t streamId) {
	const auto streamIt = mStreams.find(streamId);
	if (streamIt == mStreams.end()) return;
	auto& stream = *streamIt->second;
	if (stream.mHandlerInvoked) return;
	stream.mHandlerInvoked = true;

	const auto requestState = stream.mRequestState;
	const auto handler = [server = mServer.lock(), path = requestState->getUri().getPath()]() -> optional<RequestCb> {
		if (!server) return nullopt;
		return server->findHandler(path);
	}();
	if (!handler.has_value()) {
		stream.mResponseHandle.writeHead(404);
		stream.mResponseHandle.send();
		return;
	}
	(*handler)(stream.mRequestHandle, stream.mResponseHandle);
}

} // namespace flexisip::tester::http_mock::server::detail
