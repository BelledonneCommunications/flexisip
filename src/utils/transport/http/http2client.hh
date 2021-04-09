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

#include <functional>
#include <list>
#include <map>

#include <nghttp2/nghttp2.h>
#include <openssl/ssl.h>
#include <sofia-sip/su_wait.h>

#include <flexisip/utils/timer.hh>

#include "http-message-context.hh"
#include "http-message.hh"
#include "http-response.hh"
#include "utils/transport/tls-connection.hh"

namespace flexisip {

class Http2Client {
public:
	enum class State : uint8_t { Disconnected, Connected };

	class BadStateError : public std::logic_error {
	public:
		BadStateError(State state) : logic_error(formatWhatArg(state)) {
		}

	private:
		static std::string formatWhatArg(State state) noexcept;
	};

	Http2Client(su_root_t& root, const std::string& host, const std::string& port);
	Http2Client(su_root_t& root, const std::string& host, const std::string& port, const std::string& trustStorePath,
	            const std::string& certPath);
	virtual ~Http2Client() = default;

	using HttpRequest = HttpMessage;
	using OnErrorCb = HttpMessageContext::OnErrorCb;
	using OnResponseCb = HttpMessageContext::OnResponseCb;
	void send(const std::shared_ptr<HttpRequest>& request, const OnResponseCb& onResponseCb,
	          const OnErrorCb& onErrorCb);

	std::string getHost() const {
		return mConn->getPort() == "443" ? mConn->getHost() : mConn->getHost() + ":" + mConn->getPort();
	}

	bool isIdle() const {
		return mActiveHttpContexts.empty();
	}

	/**
	 * Set the request timeout with a new value, but request timeout MUST be inferior to Http2Client::sIdleTimeout to
	 * work properly.
	 * The new timeout is valid only for future requests.
	 */
	Http2Client& setRequestTimeout(unsigned requestTimeout) {
		this->mRequestTimeout = requestTimeout;
		return *this;
	}

	void enableInsecureTestMode() {
		mConn->enableInsecureTestMode();
	}

private:
	struct NgHttp2SessionDeleter {
		void operator()(nghttp2_session* ptr) const noexcept {
			nghttp2_session_del(ptr);
		}
	};

	/* Private methods */
	ssize_t doSend(nghttp2_session& session, const uint8_t* data, size_t length) noexcept;
	ssize_t doRecv(nghttp2_session& session, uint8_t* data, size_t length) noexcept;
	void onFrameSent(nghttp2_session& session, const nghttp2_frame& frame) noexcept;
	void onFrameRecv(nghttp2_session& session, const nghttp2_frame& frame) noexcept;
	void onHeaderRecv(nghttp2_session& session, const nghttp2_frame& frame, const std::string& name,
	                  const std::string& value, uint8_t flags) noexcept;
	void onDataReceived(nghttp2_session& session, uint8_t flags, int32_t streamId, const uint8_t* data,
	                    size_t datalen) noexcept;
	void onStreamClosed(nghttp2_session& session, int32_t stream_id, uint32_t error_code) noexcept;

	static int onPollInCb(su_root_magic_t*, su_wait_t*, su_wakeup_arg_t* arg) noexcept;

	void resetIdleTimer() noexcept {
		mIdleTimer.set([this]() { onConnectionIdle(); });
	}
	void onConnectionIdle() noexcept;

	void onRequestTimeout(int32_t streamId);
	void resetTimeoutTimer(int32_t streamId);

	void connect(std::shared_ptr<HttpMessageContext>& context);
	void disconnect();

	void setState(State state) noexcept;

	State mState{State::Disconnected};
	std::unique_ptr<TlsConnection> mConn{};
	su_root_t& mRoot;
	su_wait_t mPollInWait{0};
	sofiasip::Timer mIdleTimer;
	std::string mLogPrefix{};
	int32_t mLastSID{-1};
	/**
	 * Delay (in second) for one request timeout, default is 30
	 */
	unsigned mRequestTimeout = 30;

	using NgHttp2SessionPtr = std::unique_ptr<nghttp2_session, NgHttp2SessionDeleter>;
	NgHttp2SessionPtr mHttpSession{};

	using HttpContextMap = std::map<int32_t, std::shared_ptr<HttpMessageContext>>;
	HttpContextMap mActiveHttpContexts;

	using TimeoutTimerMap = std::map<int32_t, std::shared_ptr<sofiasip::Timer>>;
	TimeoutTimerMap mTimeoutTimers;

	/**
	 * Delay (in second) before the connection with the distant HTTP2 server is closed because of inactivity.
	 */
	static constexpr unsigned sIdleTimeout = 60;
};

class Http2Tools {
public:
	static const char* frameTypeToString(uint8_t frameType) noexcept;
	static std::string printFlags(uint8_t flags) noexcept;
};

} // namespace flexisip

std::ostream& operator<<(std::ostream& os, const ::nghttp2_frame& frame) noexcept;
std::ostream& operator<<(std::ostream& os, flexisip::Http2Client::State state) noexcept;
