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

#include <algorithm>
#include <array>
#include <nghttp2/nghttp2.h>
#include <sstream>

#include <nghttp2/nghttp2ver.h>

#include "flexisip/logmanager.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

#include "http2client.hh"

using namespace std;

namespace flexisip {

// Needed before c++17
constexpr std::chrono::seconds Http2Client::mIdleTimeout;

string Http2Client::BadStateError::formatWhatArg(State state) noexcept {
	return string{"bad state ["} + to_string(unsigned(state)) + "]";
}

Http2Client::Http2Client(sofiasip::SuRoot& root, decltype(mConn)&& connection, SessionSettings&& sessionSettings)
    : mConn(std::move(connection)), mRoot(root), mIdleTimer(root.getCPtr(), mIdleTimeout),
      mSessionSettings(std::move(sessionSettings)) {

	ostringstream os{};
	os << "Http2Client[" << this << "]";
	mLogPrefix = os.str();

	SLOGD << mLogPrefix << ": constructing Http2Client with TlsConnection[" << mConn.get() << "]";
}

Http2Client::Http2Client(sofiasip::SuRoot& root,
                         const string& host,
                         const string& port,
                         SessionSettings&& sessionSettings)
    : Http2Client(root, make_unique<TlsConnection>(host, port, true), std::move(sessionSettings)) {
}

Http2Client::Http2Client(sofiasip::SuRoot& root,
                         const string& host,
                         const string& port,
                         const string& trustStorePath,
                         const string& certPath,
                         SessionSettings&& sessionSettings)
    : Http2Client(
          root, make_unique<TlsConnection>(host, port, trustStorePath, certPath, true), std::move(sessionSettings)) {
}

void Http2Client::sendAllPendingRequests() {
	for (auto it = mPendingHttpContexts.begin(); it != mPendingHttpContexts.end();
	     it = mPendingHttpContexts.erase(it)) {
		send(it->get()->getRequest(), it->get()->getOnResponseCb(), it->get()->getOnErrorCb());
	}
}

void Http2Client::discardAllPendingRequests() {
	for (auto it = mPendingHttpContexts.begin(); it != mPendingHttpContexts.end();
	     it = mPendingHttpContexts.erase(it)) {
		it->get()->getOnErrorCb()(it->get()->getRequest());
	}
}

void Http2Client::discardAllActiveRequests() {
	for (auto it = mActiveHttpContexts.begin(); it != mActiveHttpContexts.end(); it = mActiveHttpContexts.erase(it)) {
		const auto& context = it->second;
		context->getOnErrorCb()(context->getRequest());
	}
}

void Http2Client::send(const shared_ptr<HttpRequest>& request,
                       const OnResponseCb& onResponseCb,
                       const OnErrorCb& onErrorCb) {

	auto logPrefix = mLogPrefix;

	SLOGD << logPrefix << ": sending request[" << request << "]:\n" << request->toString();

	auto context = make_shared<HttpMessageContext>(request, onResponseCb, onErrorCb, *mRoot.getCPtr(), mRequestTimeout);

	if (mState == State::Disconnected) {
		SLOGD << logPrefix << ": not connected. Trying to connect...";
		this->tlsConnect();
	}
	if (mState != State::Connected) {
		mPendingHttpContexts.emplace_back(std::move(context));
		return;
	}

	auto streamId =
	    nghttp2_submit_request(mHttpSession.get(), nullptr, request->getHeaders().makeCHeaderList().data(),
	                           request->getHeaders().getHeadersList().size(), request->getCDataProvider(), nullptr);
	if (streamId < 0) {
		SLOGE << logPrefix << ": push request submit failed. reason=[" << nghttp2_strerror(streamId) << "]";
		onErrorCb(request);
		return;
	}

	logPrefix = mLogPrefix + "[" + to_string(streamId) + "]";

	// the emplace MUST be called before nghttp2_session_send for the timeout mechanic to work properly.
	// In fact if you watch the Http2Client::resetTimeoutTimer the context need to be in map for the timer to be
	// reset/start properly.
	mActiveHttpContexts.emplace(streamId, std::move(context));
	auto status = sendAll();
	if (status < 0) {
		SLOGE << logPrefix << ": push request sending failed. reason=[" << nghttp2_strerror(status) << "]";
		mActiveHttpContexts.erase(streamId);
		onErrorCb(request);
		return;
	}

	SLOGD << logPrefix << ": request[" << request << "] submitted";
}

void Http2Client::tlsConnect() {
	if (mState != State::Disconnected) {
		throw BadStateError(mState);
	}
	setState(State::Connecting);

	mConn->connectAsync(*mRoot.getCPtr(), [weakThis = weak_ptr<Http2Client>{this->shared_from_this()}]() {
		if (auto sharedThis = weakThis.lock()) {
			sharedThis->onTlsConnectCb();
		}
	});
}

void Http2Client::onTlsConnectCb() {
	if (mConn->isConnected()) {
		http2Setup();
	} else {
		discardAllPendingRequests();
		setState(State::Disconnected);
	}
}

void Http2Client::http2Setup() {
	auto sendCb = [](nghttp2_session* session, const uint8_t* data, size_t length, [[maybe_unused]] int flags,
	                 void* user_data) noexcept {
		auto thiz = static_cast<Http2Client*>(user_data);
		return thiz->doSend(*session, data, length);
	};
	auto recvCb = [](nghttp2_session* session, uint8_t* buf, size_t length, [[maybe_unused]] int flags,
	                 void* user_data) noexcept {
		auto thiz = static_cast<Http2Client*>(user_data);
		return thiz->doRecv(*session, buf, length);
	};
	auto frameSentCb = [](nghttp2_session* session, const nghttp2_frame* frame, void* user_data) noexcept {
		auto thiz = static_cast<Http2Client*>(user_data);
		thiz->onFrameSent(*session, *frame);
		return 0;
	};
	auto frameRecvCb = [](nghttp2_session* session, const nghttp2_frame* frame, void* user_data) noexcept {
		auto thiz = static_cast<Http2Client*>(user_data);
		thiz->onFrameRecv(*session, *frame);
		return 0;
	};
	auto onHeaderRecvCb = [](nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t namelen,
	                         const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data) noexcept {
		auto thiz = static_cast<Http2Client*>(user_data);
		string nameStr{reinterpret_cast<const char*>(name), namelen};
		string valueStr{reinterpret_cast<const char*>(value), valuelen};
		thiz->onHeaderRecv(*session, *frame, nameStr, valueStr, flags);
		return 0;
	};
	auto onDataChunkRecvCb = [](nghttp2_session* session, uint8_t flags, int32_t stream_id, const uint8_t* data,
	                            size_t len, void* user_data) noexcept {
		auto thiz = static_cast<Http2Client*>(user_data);
		thiz->onDataReceived(*session, flags, stream_id, data, len);
		return 0;
	};
	auto onStreamClosedCb = [](nghttp2_session* session, int32_t stream_id, uint32_t error_code,
	                           void* user_data) noexcept {
		auto thiz = static_cast<Http2Client*>(user_data);
		thiz->onStreamClosed(*session, stream_id, error_code);
		return 0;
	};

	nghttp2_session_callbacks* cbs;
	nghttp2_session_callbacks_new(&cbs);
	nghttp2_session_callbacks_set_send_callback(cbs, sendCb);
	nghttp2_session_callbacks_set_recv_callback(cbs, recvCb);
	nghttp2_session_callbacks_set_on_frame_send_callback(cbs, frameSentCb);
	nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, frameRecvCb);
	nghttp2_session_callbacks_set_on_header_callback(cbs, onHeaderRecvCb);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, onDataChunkRecvCb);
	nghttp2_session_callbacks_set_on_stream_close_callback(cbs, onStreamClosedCb);

	unique_ptr<nghttp2_session_callbacks, void (*)(nghttp2_session_callbacks*)> cbsPtr{cbs,
	                                                                                   nghttp2_session_callbacks_del};

	nghttp2_session* session;
	nghttp2_session_client_new(&session, cbs, this);
	NgHttp2SessionPtr httpSession{session};

	int status;
	if ((status = mSessionSettings.submitTo(session)) != 0) {
		SLOGE << mLogPrefix << ": submitting settings failed [status=" << to_string(status) << "]";
		disconnect();
		return;
	}

	mHttpSession = std::move(httpSession);

	su_wait_create(&mPollInWait, mConn->getFd(), SU_WAIT_IN);
	su_root_register(mRoot.getCPtr(), &mPollInWait, onPollInCb, this, su_pri_normal);
	resetIdleTimer();

	setState(State::Connected);
	sendAllPendingRequests();
}

ssize_t Http2Client::doSend([[maybe_unused]] nghttp2_session& session, const uint8_t* data, size_t length) noexcept {
	length = min(length, size_t(numeric_limits<int>::max()));
	auto nwritten = mConn->write(data, int(length));
	if (nwritten < 0) {
		SLOGE << mLogPrefix << ": error while writting into socket[" << nwritten << "]";
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
	if (nwritten == 0 && length > 0) return NGHTTP2_ERR_WOULDBLOCK;
	return nwritten;
}

ssize_t Http2Client::doRecv([[maybe_unused]] nghttp2_session& session, uint8_t* data, size_t length) noexcept {
	length = min(length, size_t(numeric_limits<int>::max()));
	auto nread = mConn->read(data, length);
	if (nread < 0) {
		SLOGE << mLogPrefix << ": error while reading socket. " << strerror(errno);
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
	if (nread == 0 && length > 0) return NGHTTP2_ERR_WOULDBLOCK;
	return nread;
}

/**
 * Synchronously called by nghttp2_session_send
 */
void Http2Client::onFrameSent([[maybe_unused]] nghttp2_session& session, const nghttp2_frame& frame) noexcept {
	SLOGD << mLogPrefix << "[" << frame.hd.stream_id << "]: " << Http2Tools::frameTypeToString(frame.hd.type)
	      << " frame sent (" << frame.hd.length << "B)";
	resetTimeoutTimer(frame.hd.stream_id);
	resetIdleTimer();
}

void Http2Client::onFrameRecv([[maybe_unused]] nghttp2_session& session, const nghttp2_frame& frame) noexcept {
	auto logPrefix = mLogPrefix + "[" + to_string(frame.hd.stream_id) + "]: ";
	SLOGD << logPrefix << Http2Tools::frameTypeToString(frame.hd.type) << " frame received (" << frame.hd.length
	      << "B)";
	resetTimeoutTimer(frame.hd.stream_id);
	resetIdleTimer();

	switch (frame.hd.type) {
		case NGHTTP2_WINDOW_UPDATE: { // Remote says we're clear for another window.
			resumeSending(logPrefix);
		} break;
		case NGHTTP2_SETTINGS:
			if ((frame.hd.flags & NGHTTP2_FLAG_ACK) == 0) {
				SLOGD << logPrefix << "server settings received";
			}
			break;
		case NGHTTP2_GOAWAY: {
			ostringstream msg{};
			msg << logPrefix << "GOAWAY frame received, errorCode=[" << frame.goaway.error_code << "], lastStreamId=["
			    << frame.goaway.last_stream_id << "]:";
			if (frame.goaway.opaque_data_len > 0) {
				msg << endl;
				msg.write(reinterpret_cast<const char*>(frame.goaway.opaque_data), frame.goaway.opaque_data_len);
			} else {
				msg << " <empty>";
			}
			SLOGD << msg.str();
			SLOGD << "Scheduling connection closing";
			mLastSID = frame.goaway.last_stream_id;
			break;
		}
	}
}

void Http2Client::onHeaderRecv([[maybe_unused]] nghttp2_session& session,
                               const nghttp2_frame& frame,
                               const string& name,
                               const string& value,
                               uint8_t flags) noexcept {
	const auto& streamId = frame.hd.stream_id;
	auto logPrefix = string{mLogPrefix} + "[" + to_string(streamId) + "]";
	// SLOGD << logPrefix << ": receiving HTTP2 header [" << name << " = " << value << "]";

	auto contextIterator = mActiveHttpContexts.find(streamId);
	if (contextIterator != mActiveHttpContexts.end()) {
		contextIterator->second->getResponse()->getHeaders().add(name, value, flags);
	} else {
		SLOGE << logPrefix << ": receiving header for an unknown stream. Just ignoring";
	}
}

void Http2Client::onDataReceived([[maybe_unused]] nghttp2_session& session,
                                 [[maybe_unused]] uint8_t flags,
                                 int32_t streamId,
                                 const uint8_t* data,
                                 size_t datalen) noexcept {
	string stringData(reinterpret_cast<const char*>(data), datalen);

	auto logPrefix = string{mLogPrefix} + "[" + to_string(streamId) + "]";

	//	ostringstream msg{};
	//	msg << logPrefix << ": " << datalen << "B of data received on stream[" << streamId << "]:\n";
	//	msg << stringData;
	//	SLOGD << msg.str();

	auto contextIterator = mActiveHttpContexts.find(streamId);
	if (contextIterator != mActiveHttpContexts.end()) {
		contextIterator->second->getResponse()->appendBody(stringData);
	} else {
		SLOGE << logPrefix << "Data received for a unknown context";
	}
}

int Http2Client::onPollInCb(su_root_magic_t*, su_wait_t* w, su_wakeup_arg_t* arg) noexcept {
	auto thiz = static_cast<Http2Client*>(arg);

	if (w->revents & SU_WAIT_HUP) {
		SLOGD << thiz->mLogPrefix << ": peer has hung up";
		thiz->disconnect();
		return 0;
	}
	if (w->revents & SU_WAIT_ERR) {
		SLOGE << thiz->mLogPrefix << ": socket error";
		thiz->disconnect();
		return 0;
	}

	auto status = nghttp2_session_recv(thiz->mHttpSession.get());
	if (status < 0) {
		SLOGE << thiz->mLogPrefix << ": error while receiving HTTP2 data[" << nghttp2_strerror(status)
		      << "]. Disconnecting";
		thiz->disconnect();
		return 0;
	}
	if (thiz->mLastSID >= 0) {
		SLOGD << thiz->mLogPrefix << ": closing connection after receiving GOAWAY frame. Last processed stream is ["
		      << thiz->mLastSID << "]";
		thiz->disconnect();
	}
	return 0;
}

void Http2Client::onStreamClosed([[maybe_unused]] nghttp2_session& session,
                                 int32_t stream_id,
                                 uint32_t error_code) noexcept {
	auto logPrefix = mLogPrefix + "[" + to_string(stream_id) + "]";

	shared_ptr<HttpMessageContext> context = nullptr;
	auto contextMapIterator = mActiveHttpContexts.find(stream_id);
	if (contextMapIterator != mActiveHttpContexts.cend()) {
		context = contextMapIterator->second;
	}
	if (NGHTTP2_NO_ERROR == error_code) {
		SLOGD << logPrefix << ": stream closed without error";
		if (context != nullptr) {
			try {
				context->getResponse()->getStatusCode(); // throw an exception if the status code is invalid.
				SLOGD << logPrefix << ": response received for HttpRequest[" << context->getRequest() << "]:\n"
				      << context->getResponse()->toString();
				context->getOnResponseCb()(context->getRequest(), context->getResponse());
				mActiveHttpContexts.erase(contextMapIterator);
			} catch (const runtime_error& e) {
				SLOGD << "Error during status code evaluation : " << e.what();
				context->getOnErrorCb()(context->getRequest());
			}
		}

		auto queueSize = getOutboundQueueSize();
		if (0 < queueSize) {
			// When nghttp2 reaches a maximum number of concurrent streams, it starts queueing up messages.
			// A stream has just closed, we should start sending those queued up messages
			mRoot.addToMainLoop([weakThis = this->weak_from_this(), previousSize = queueSize,
			                     logPrefix = std::move(logPrefix)]() {
				auto sharedThis = weakThis.lock();
				if (!sharedThis || sharedThis->getOutboundQueueSize() < previousSize)
					return; // Something triggered a resend in the meantime. Nothing to do. (If the queue is still not
					        // empty, it's probably stuck again, and we should wait anyway for another stream to close)
				sharedThis->resumeSending(logPrefix);
			});
		}
	} else {
		SLOGD << logPrefix << ": stream closed with error code [" << error_code
		      << "] : " << nghttp2_http2_strerror(error_code);
		if (context != nullptr) {
			context->getOnErrorCb()(context->getRequest());
			mActiveHttpContexts.erase(contextMapIterator);
		}
	}
}

void Http2Client::resumeSending(const std::string& logPrefix) {
	const auto status = sendAll();
	if (status < 0) {
		SLOGE << logPrefix << "failure while trying to catch up queued frames. reason=[" << nghttp2_strerror(status)
		      << "]";
	}
}

void Http2Client::disconnect() {
	SLOGD << mLogPrefix << ": disconnecting";
	if (mState == State::Disconnected) {
		return;
	}
	discardAllPendingRequests();
	discardAllActiveRequests();
	su_root_unregister(mRoot.getCPtr(), &mPollInWait, onPollInCb, this);
	mHttpSession.reset();
	mConn->disconnect();
	mLastSID = -1;
	mTimeoutTimers.clear();
	setState(State::Disconnected);
}

void Http2Client::onConnectionIdle() noexcept {
	SLOGD << mLogPrefix << ": connection is idle";
	disconnect();
}

void Http2Client::setState(State state) noexcept {
	if (mState == state) return;
	SLOGD << mLogPrefix << ": switching state from [" << mState << "] to [" << state << "]";
	mState = state;
}

void Http2Client::resetTimeoutTimer(int32_t streamId) {
	auto contextMapIterator = mActiveHttpContexts.find(streamId);
	if (contextMapIterator != mActiveHttpContexts.cend()) {
		contextMapIterator->second->getTimeoutTimer().set([this, streamId]() { onRequestTimeout(streamId); });
	}
}

void Http2Client::onRequestTimeout(int32_t streamId) {
	auto contextMapIterator = mActiveHttpContexts.find(streamId);
	if (contextMapIterator != mActiveHttpContexts.cend()) {
		auto context = contextMapIterator->second;
		SLOGD << mLogPrefix << ": closing stream[" << streamId << "] after request timeout.";
		context->getOnErrorCb()(context->getRequest());
		// Cancel any unsent frames
		nghttp2_submit_rst_stream(mHttpSession.get(), nghttp2_flag::NGHTTP2_FLAG_NONE, streamId,
		                          nghttp2_error_code::NGHTTP2_CANCEL);
		mActiveHttpContexts.erase(contextMapIterator);
	}
}

const char* Http2Tools::frameTypeToString(uint8_t frameType) noexcept {
	switch (frameType) {
		case NGHTTP2_DATA:
			return "DATA";
		case NGHTTP2_HEADERS:
			return "HEADERS";
		case NGHTTP2_PRIORITY:
			return "PRIORITY";
		case NGHTTP2_RST_STREAM:
			return "RST_STREAM";
		case NGHTTP2_SETTINGS:
			return "SETTINGS";
		case NGHTTP2_PUSH_PROMISE:
			return "PUSH_PROMISE";
		case NGHTTP2_PING:
			return "PING";
		case NGHTTP2_GOAWAY:
			return "GOAWAY";
		case NGHTTP2_WINDOW_UPDATE:
			return "WINDOW_UPDATE";
		case NGHTTP2_CONTINUATION:
			return "CONTINUATION";
#if NGHTTP2_VERSION_NUM >= 0x010a00 // v1.10.0
		case NGHTTP2_ALTSVC:
			return "ALTSVC";
#endif
#if NGHTTP2_VERSION_NUM >= 0x012100 // v1.33.0
		case NGHTTP2_ORIGIN:
			return "ORIGIN";
#endif
	}
	return "UNKNOWN";
}

string Http2Tools::printFlags(uint8_t flags) noexcept {
	array<const char*, 4> flagsAsStr{};

	auto len = 0;
	if (flags & NGHTTP2_FLAG_END_STREAM) flagsAsStr.at(len++) = "END_STREAM";
	if (flags & NGHTTP2_FLAG_END_HEADERS) flagsAsStr.at(len++) = "END_HEADERS";
	if (flags & NGHTTP2_FLAG_ACK) flagsAsStr.at(len++) = "ACK";
	if (flags & NGHTTP2_FLAG_PADDED) flagsAsStr.at(len++) = "PADDED";

	string res{};
	for (auto i = 0; i < len; ++i) {
		if (i != 0) res += " | ";
		res += flagsAsStr.at(i);
	}
	return res;
}

ostream& operator<<(ostream& os, flexisip::Http2Client::State state) noexcept {
	switch (state) {
		case flexisip::Http2Client::State::Disconnected:
			return os << "Disconnected";
		case flexisip::Http2Client::State::Connected:
			return os << "Connected";
		case flexisip::Http2Client::State::Connecting:
			return os << "Connecting";
	};
	return os << "Unknown";
}

ostream& operator<<(ostream& os, const nghttp2_frame& frame) noexcept {
	os << Http2Tools::frameTypeToString(frame.hd.type) << endl;
	os << "streamId: " << frame.hd.stream_id << endl;
	os << hex << showbase;
	os << "flags: " << int(frame.hd.flags) << " [" << Http2Tools::printFlags(frame.hd.flags) << "]" << endl;
	os << dec << noshowbase;
	switch (frame.hd.type) {
		case NGHTTP2_HEADERS:
			os << endl;
			// this if/else clause only works for sending HEADER request
			if (frame.headers.nvlen > 0) {
				for (unsigned i = 0; i < frame.headers.nvlen; ++i) {
					const auto& nva = frame.headers.nva[i];
					os << nva.name << ": " << nva.value << endl;
				}
			} else {
				os << "<empty>" << endl;
			}
			break;
		case NGHTTP2_RST_STREAM: {
			const auto& error_code = frame.rst_stream.error_code;
			os << "errorCode: " << error_code;
#if NGHTTP2_VERSION_NUM >= 0x010900 // v1.9.0
			os << "[" << nghttp2_http2_strerror(error_code) << "]";
#endif
			os << endl;
			break;
		}
		case NGHTTP2_SETTINGS:
			os << endl;
			if (frame.settings.niv > 0) {
				for (unsigned i = 0; i < frame.settings.niv; ++i) {
					const auto& iv = frame.settings.iv[i];
					os << iv.settings_id << " : " << iv.value << endl;
				}
			} else {
				os << "<empty>" << endl;
			}
			break;
		case NGHTTP2_GOAWAY:
			os << "lastStreamId: " << frame.goaway.last_stream_id << endl;
			os << "errorCode: " << frame.goaway.error_code << endl;
			os << endl;
			if (frame.goaway.opaque_data) {
				os.write(reinterpret_cast<char*>(frame.goaway.opaque_data), frame.goaway.opaque_data_len);
				os << endl;
			} else {
				os << "<empty>" << endl;
			}
			break;
		default:
			break;
	};
	return os;
}

} /* namespace flexisip */
