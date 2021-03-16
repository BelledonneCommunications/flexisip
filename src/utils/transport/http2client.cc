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

#include <algorithm>
#include <sstream>

#include <nghttp2/nghttp2ver.h>

#include "flexisip/logmanager.hh"

#include "ng_data_provider.hh"

#include "http2client.hh"

using namespace std;

namespace flexisip {

string Http2Client::BadStateError::formatWhatArg(State state) noexcept {
	return string{"bad state ["} + to_string(unsigned(state)) + "]";
}

Http2Client::Http2Client(su_root_t &root, const std::string &host, const std::string &port, const SSL_METHOD *method)
	: mRoot{root}, mIdleTimer{&root, sIdleTimeout * 1000} {
	mConn = make_unique<TlsConnection>(host, port, SSLv23_client_method());
	ostringstream os{};
	os << "Http2Client[" << this << "]";
	mLogPrefix = os.str();
	SLOGD << mLogPrefix << ": constructing Http2Client with TlsConnection[" << mConn.get() << "]";
}

Http2Client::Http2Client(su_root_t &root, const std::string &host, const std::string &port,
						 TlsConnection::SSLCtxUniquePtr &&ctx)
	: mRoot{root}, mIdleTimer{&root, sIdleTimeout * 1000} {
	mConn = make_unique<TlsConnection>(host, port, move(ctx));
	ostringstream os{};
	os << "Http2Client[" << this << "]";
	mLogPrefix = os.str();
	SLOGD << mLogPrefix << ": constructing Http2Client with TlsConnection[" << mConn.get() << "]";
}

void Http2Client::sendAllPendingReRequests() {
	for (auto it = pendingRequests.begin(); it != pendingRequests.end(); it = pendingRequests.erase(it)) {
		this->send(it->get()->getRequest(), it->get()->getOnResponseCb(), it->get()->getOnErrorCb());
	}
}

void Http2Client::send(const std::shared_ptr<HttpRequest> &request, const OnResponseCb &onResponseCb,
					   const OnErrorCb &onErrorCb) {
	shared_ptr<HttpMessageContext> context =
		make_shared<HttpMessageContext>(move(request), onResponseCb, onErrorCb);
	if (mState != State::Connected) {
		this->connect();
		pendingRequests.emplace_back(move(context));
		return;
	}

	NgDataProvider dataProv{request->getBody()};
	auto streamId =
		nghttp2_submit_request(mHttpSession.get(), nullptr, request->getHeaderStore().makeHeaderList().data(),
							   request->getHeaderStore().getMHList().size(), dataProv.getCStruct(), nullptr);
	if (streamId < 0) {
		SLOGE << mLogPrefix << ": push request submit failed. reason=[" << nghttp2_strerror(streamId) << "]";
		onErrorCb(request, streamId, nghttp2_strerror(streamId));//TODO
		return;
	}

	auto logPrefix = string{mLogPrefix} + "[" + to_string(streamId) + "]";

	ostringstream msg{};
	msg << logPrefix << ": sending request " << request->toString() << endl;
	SLOGD << msg.str();

	auto status = nghttp2_session_send(mHttpSession.get());
	if (status < 0) {
		SLOGE << logPrefix << ": push request sending failed. reason=[" << nghttp2_strerror(status) << "]";
		onErrorCb(request, status, nghttp2_strerror(status));//TODO
		return;
	}

	activeHttpContexts.emplace(streamId, move(context));
	resetIdleTimer();
}

void Http2Client::connect() {
	if (mState != State::Disconnected || mState != State::Connecting) {
		throw BadStateError(mState);
	}
	if (mState == State::Connecting) {
		return;
	}

	try {
		mConn->connect();
		if (!mConn->isConnected())
			throw runtime_error{"TLS connection failed"};

		auto sendCb = [](nghttp2_session *session, const uint8_t *data, size_t length, int flags,
						 void *user_data) noexcept {
			auto thiz = static_cast<Http2Client *>(user_data);
			return thiz->sendCb(*session, data, length);
		};
		auto recvCb = [](nghttp2_session *session, uint8_t *buf, size_t length, int flags, void *user_data) noexcept {
			auto thiz = static_cast<Http2Client *>(user_data);
			return thiz->recv(*session, buf, length);
		};
		auto frameSentCb = [](nghttp2_session *session, const nghttp2_frame *frame, void *user_data) noexcept {
			auto thiz = static_cast<Http2Client *>(user_data);
			thiz->onFrameSent(*session, *frame);
			return 0;
		};
		auto frameRecvCb = [](nghttp2_session *session, const nghttp2_frame *frame, void *user_data) noexcept {
			auto thiz = static_cast<Http2Client *>(user_data);
			thiz->onFrameRecv(*session, *frame);
			return 0;
		};
		auto onHeaderRecvCb = [](nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name,
								 size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags,
								 void *user_data) noexcept {
			auto thiz = static_cast<Http2Client *>(user_data);
			string nameStr{reinterpret_cast<const char *>(name), namelen};
			string valueStr{reinterpret_cast<const char *>(value), valuelen};
			thiz->onHeaderRecv(*session, *frame, nameStr, valueStr, flags);
			return 0;
		};
		auto onDataChunkRecvCb = [](nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data,
									size_t len, void *user_data) noexcept {
			auto thiz = static_cast<Http2Client *>(user_data);
			thiz->onDataReceived(*session, flags, stream_id, data, len);
			return 0;
		};
		auto onStreamClosedCb = [](nghttp2_session *session, int32_t stream_id, uint32_t error_code,
								   void *user_data) noexcept {
			auto thiz = static_cast<Http2Client *>(user_data);
			thiz->onStreamClosed(*session, stream_id, error_code);
			return 0;
		};

		nghttp2_session_callbacks *cbs;
		nghttp2_session_callbacks_new(&cbs);
		nghttp2_session_callbacks_set_send_callback(cbs, sendCb);
		nghttp2_session_callbacks_set_recv_callback(cbs, recvCb);
		nghttp2_session_callbacks_set_on_frame_send_callback(cbs, frameSentCb);
		nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, frameRecvCb);
		nghttp2_session_callbacks_set_on_header_callback(cbs, onHeaderRecvCb);
		nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, onDataChunkRecvCb);
		nghttp2_session_callbacks_set_on_stream_close_callback(cbs, onStreamClosedCb);
		;

		unique_ptr<nghttp2_session_callbacks, void (*)(nghttp2_session_callbacks *)> cbsPtr{
			cbs, nghttp2_session_callbacks_del};

		nghttp2_session *session;
		nghttp2_session_client_new(&session, cbs, this);
		NgHttp2SessionPtr httpSession{session};

		int status;
		if ((status = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, nullptr, 0)) < 0) {
			throw runtime_error{"submitting settings failed [status=" + to_string(status) + "]"};
		}
		if ((status = nghttp2_session_send(session)) < 0) {
			throw runtime_error{"sending SETTINGS frame failed [status=" + to_string(status) + "]"};
		}

		mLastSID = 0;
		mHttpSession = move(httpSession);
		su_wait_create(&mPollInWait, mConn->getFd(), SU_WAIT_IN);
		su_root_register(&mRoot, &mPollInWait, onPollInCb, this, su_pri_normal);

		resetIdleTimer();

	} catch (const runtime_error &e) {
		SLOGE << mLogPrefix << ": " << e.what();
		disconnect();
	}
}

ssize_t Http2Client::sendCb(nghttp2_session &session, const uint8_t *data, size_t length) noexcept {
	length = min(length, size_t(numeric_limits<int>::max()));
	auto nwritten = mConn->write(data, int(length));
	if (nwritten < 0) {
		SLOGE << mLogPrefix << ": error while writting into socket[" << nwritten << "]";
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
	if (nwritten == 0 && length > 0)
		return NGHTTP2_ERR_WOULDBLOCK;
	return nwritten;
}

ssize_t Http2Client::recv(nghttp2_session &session, uint8_t *data, size_t length) noexcept {
	length = min(length, size_t(numeric_limits<int>::max()));
	auto nread = mConn->read(data, length);
	if (nread < 0) {
		SLOGE << mLogPrefix << ": error while reading socket. " << strerror(errno);
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
	if (nread == 0 && length > 0)
		return NGHTTP2_ERR_WOULDBLOCK;
	return nread;
}

void Http2Client::onFrameSent(nghttp2_session &session, const nghttp2_frame &frame) noexcept {
	// 	SLOGD << mLogPrefix << "[" << frame.hd.stream_id << "]: frame sent (" << frame.hd.length << "B):\n" << frame;
}

void Http2Client::onFrameRecv(nghttp2_session &session, const nghttp2_frame &frame) noexcept {
	// 	SLOGD << mLogPrefix << "[" << frame.hd.stream_id << "]: frame received (" << frame.hd.length << "B):\n" <<
	// frame;
	switch (frame.hd.type) {
		case NGHTTP2_SETTINGS:
			if (mState == State::Connecting && (frame.hd.flags & NGHTTP2_FLAG_ACK) == 0) {
				SLOGD << mLogPrefix << ": server settings received";
				setState(State::Connected);
				SLOGD << mLogPrefix << ": sending all pending PNRs";
				sendAllPendingReRequests();
			}
			break;
		case NGHTTP2_GOAWAY: {
			ostringstream msg{};
			msg << mLogPrefix << ": GOAWAY frame received, errorCode=[" << frame.goaway.error_code
				<< "], lastStreamId=[" << frame.goaway.last_stream_id << "]:";
			if (frame.goaway.opaque_data_len > 0) {
				msg << endl;
				msg.write(reinterpret_cast<const char *>(frame.goaway.opaque_data), frame.goaway.opaque_data_len);
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

void Http2Client::onHeaderRecv(nghttp2_session &session, const nghttp2_frame &frame, const std::string &name,
							   const std::string &value, uint8_t flags) noexcept {
	const auto &streamId = frame.hd.stream_id;
	auto logPrefix = string{mLogPrefix} + "[" + to_string(streamId) + "]";
	SLOGD << logPrefix << ": receiving HTTP2 header [" << name << " = " << value << "]";

	auto contextIterator = activeHttpContexts.find(streamId);
	if (contextIterator != activeHttpContexts.end()) {
		contextIterator->second->getResponse()->getHeaderStore().add(name, value, flags);
	} else {
		SLOGE << logPrefix << ": receiving header for an unknown stream. Just ignoring";
	}
}

void Http2Client::onDataReceived(nghttp2_session &session, uint8_t flags, int32_t streamId, const uint8_t *data,
								 size_t datalen) noexcept {
	string stringData(reinterpret_cast<const char *>(data), datalen);

	auto logPrefix = string{mLogPrefix} + "[" + to_string(streamId) + "]";

	ostringstream msg{};
	msg << logPrefix << ": " << datalen << "B of data received on stream[" << streamId << "]:\n";
	msg << stringData;
	SLOGD << msg.str();

	auto contextIterator = activeHttpContexts.find(streamId);
	if (contextIterator != activeHttpContexts.end()) {
		contextIterator->second->getResponse()->appendBody(stringData);
	} else {
		SLOGE << logPrefix << "Data received for a unknown context";
	}
}

int Http2Client::onPollInCb(su_root_magic_t *, su_wait_t *, su_wakeup_arg_t *arg) noexcept {
	auto thiz = static_cast<Http2Client *>(arg);
	auto status = nghttp2_session_recv(thiz->mHttpSession.get());
	if (status < 0) {
		SLOGE << thiz->mLogPrefix << ": error while receiving HTTP2 data[" << nghttp2_strerror(status)
			  << "]. Disconnecting";
		thiz->disconnect();
		return 0;
	}
	if (thiz->mLastSID >= 0)
		thiz->processGoAway();
	return 0;
}

void Http2Client::processGoAway() {
	SLOGD << mLogPrefix << ": closing connection after receiving GOAWAY frame. Last processed stream is [" << mLastSID
		  << "]";

	// move back all the non-treated PNRs into the pending queue
	for (auto it = activeHttpContexts.begin(); it != activeHttpContexts.end(); it = activeHttpContexts.erase(it)) {
		const auto unfinishedContext = it->second;
		pendingRequests.emplace_back(move(unfinishedContext));
	}

	// disconnect and connect again if there still are PNRs to process
	disconnect();
	if (!pendingRequests.empty()) {
		SLOGD << mLogPrefix << ": Requests are pending. Connecting to server again";
		connect();
	}
}

void Http2Client::onStreamClosed(nghttp2_session &session, int32_t stream_id, uint32_t error_code) noexcept {
	auto logPrefix = mLogPrefix + "[" + to_string(stream_id) + "]";

	std::shared_ptr<HttpMessageContext> context = nullptr;
	auto contextMapIterator = activeHttpContexts.find(stream_id);
	if (contextMapIterator != activeHttpContexts.cend()) {
		context = contextMapIterator->second;
	}
	if (NGHTTP2_NO_ERROR == error_code) {
		SLOGD << logPrefix << ": stream closed without error";
		if (context != nullptr) {
			context->getOnResponseCb()(move(context->getRequest()), move(context->getResponse()));
			activeHttpContexts.erase(contextMapIterator);
		}
	} else {
		ostringstream msg{};
		msg << logPrefix << ": stream closed with error code [" << error_code << "]";
		SLOGD << msg.str();
		if (context != nullptr) {
			context->getOnErrorCb()(move(context->getRequest()), error_code, msg.str());
			activeHttpContexts.erase(contextMapIterator);
		}
	}
}

void Http2Client::disconnect() {
	SLOGD << mLogPrefix << ": disconnecting from APNS";
	if (mState == State::Disconnected)
		return;
	su_root_unregister(&mRoot, &mPollInWait, onPollInCb, this);
	mHttpSession.reset();
	mConn->disconnect();
	setState(State::Disconnected);
	mLastSID = -1;
	activeHttpContexts.clear();
}

void Http2Client::onConnectionIdle() noexcept {
	SLOGD << mLogPrefix << ": connection is idle";
	disconnect();
}

void Http2Client::setState(State state) noexcept {
	if (mState == state)
		return;
	SLOGD << mLogPrefix << ": switching state from [" << mState << "] to [" << state << "]";
	mState = state;
}
} /* namespace flexisip */

std::ostream &operator<<(std::ostream &os, flexisip::Http2Client::State state) noexcept {
	switch (state) {
		case flexisip::Http2Client::State::Disconnected: return os << "Disconnected";
		case flexisip::Http2Client::State::Connecting: return os << "Connecting";
		case flexisip::Http2Client::State::Connected: return os << "Connected";
	};
	return os << "Unknown";
}
