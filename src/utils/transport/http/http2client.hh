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

#include <functional>
#include <list>
#include <map>

#include <nghttp2/nghttp2.h>
#include <openssl/ssl.h>
#include <sofia-sip/su_wait.h>

#include <flexisip/sofia-wrapper/timer.hh>

#include "http-message-context.hh"
#include "http-message.hh"
#include "http-response.hh"
#include "utils/transport/tls-connection.hh"

namespace flexisip {

/**
 * An HTTTP/2 client over a tls connection.
 * Can be used to established one connection to a remote remote server and send multiple request over this connection.
 * Tls connection and http/2 connection handling is done by the Http2Client.
 */
class Http2Client : public std::enable_shared_from_this<Http2Client> {
public:
	enum class State : uint8_t { Disconnected, Connected, Connecting };

	class BadStateError : public std::logic_error {
	public:
		BadStateError(State state) : logic_error(formatWhatArg(state)) {
		}

	private:
		static std::string formatWhatArg(State state) noexcept;
	};

	class SessionSettings {
	public:
		SessionSettings(uint32_t maxConcurrentStreams = 1000)
		    : mSettings{{{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, maxConcurrentStreams}}} {
		}

		int submitTo(nghttp2_session* session) {
			return nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, mSettings.data(), mSettings.size());
		}

	private:
		std::array<nghttp2_settings_entry, 1> mSettings;
	};

	template <typename... Args>
	static std::shared_ptr<Http2Client> make(Args&&... args) {
		// new because make_shared need a public constructor.
		return std::shared_ptr<Http2Client>{new Http2Client{std::forward<Args>(args)...}};
	};
	virtual ~Http2Client() = default;

	using HttpRequest = HttpMessage;
	using OnErrorCb = HttpMessageContext::OnErrorCb;
	using OnResponseCb = HttpMessageContext::OnResponseCb;
	/**
	 * Send a request to the remote server. OnResponseCb is called if the server return a complete answer. OnErrorCb is
	 * called if any unexpected errors occurred (like connection errors or timeouts).
	 * If an HTTP/2 connection is already active between you and the remote server this connection is re-used. Else a
	 * new connection is automatically created.
	 *
	 * @param request A std::shared_ptr pointing to a HttpMessage object, the message to send.
	 * @param onResponseCb The callback called when a complete answer is received.
	 * @param onErrorCb The callback called when an unexpected error occurred.
	 */
	void
	send(const std::shared_ptr<HttpRequest>& request, const OnResponseCb& onResponseCb, const OnErrorCb& onErrorCb);

	void onTlsConnectCb();

	std::string getHost() const {
		return mConn->getPort() == "443" ? mConn->getHost() : mConn->getHost() + ":" + mConn->getPort();
	}

	/**
	 * Test whether the client is processing an HTTP request.
	 * A request is under processing when it has been sent to the HTTP server
	 * or it has been queued until the connection on the server is completed.
	 * @return True when the client isn't processing any request.
	 */
	bool isIdle() const {
		return mActiveHttpContexts.empty() && mPendingHttpContexts.empty();
	}

	/**
	 * Set the request timeout with a new value, but request timeout MUST be inferior to Http2Client::sIdleTimeout to
	 * work properly.
	 * The new timeout is valid only for future requests.
	 */
	Http2Client& setRequestTimeout(std::chrono::seconds requestTimeout) {
		this->mRequestTimeout = requestTimeout;
		return *this;
	}

	void enableInsecureTestMode() {
		mConn->enableInsecureTestMode();
	}

	const std::unique_ptr<TlsConnection>& getConnection() const {
		return mConn;
	}

	/**
	 * Number of requests pending to be sent by the nghttp2 session
	 */
	size_t getOutboundQueueSize() {
		if (!mHttpSession) return 0;
		return nghttp2_session_get_outbound_queue_size(mHttpSession.get());
	}

private:
	struct NgHttp2SessionDeleter {
		void operator()(nghttp2_session* ptr) const noexcept {
			nghttp2_session_del(ptr);
		}
	};

	// Constructors must be private because Http2Client extends enable_shared_from_this. Use make instead.
	Http2Client(sofiasip::SuRoot& root, std::unique_ptr<TlsConnection>&& connection, SessionSettings&& sessionSettings);
	Http2Client(sofiasip::SuRoot& root,
	            const std::string& host,
	            const std::string& port,
	            SessionSettings&& sessionSettings = SessionSettings());
	Http2Client(sofiasip::SuRoot& root,
	            const std::string& host,
	            const std::string& port,
	            const std::string& trustStorePath,
	            const std::string& certPath,
	            SessionSettings&& sessionSettings = SessionSettings());

	/* Private methods */
	void sendAllPendingRequests();
	void discardAllPendingRequests();
	void discardAllActiveRequests();

	ssize_t doSend(nghttp2_session& session, const uint8_t* data, size_t length) noexcept;
	ssize_t doRecv(nghttp2_session& session, uint8_t* data, size_t length) noexcept;
	void onFrameSent(nghttp2_session& session, const nghttp2_frame& frame) noexcept;
	void onFrameRecv(nghttp2_session& session, const nghttp2_frame& frame) noexcept;
	void onHeaderRecv(nghttp2_session& session,
	                  const nghttp2_frame& frame,
	                  const std::string& name,
	                  const std::string& value,
	                  uint8_t flags) noexcept;
	void onDataReceived(
	    nghttp2_session& session, uint8_t flags, int32_t streamId, const uint8_t* data, size_t datalen) noexcept;
	void onStreamClosed(nghttp2_session& session, int32_t stream_id, uint32_t error_code) noexcept;

	static int onPollInCb(su_root_magic_t*, su_wait_t*, su_wakeup_arg_t* arg) noexcept;

	void resetIdleTimer() noexcept {
		mIdleTimer.set([this]() { onConnectionIdle(); });
	}
	void onConnectionIdle() noexcept;

	void onRequestTimeout(int32_t streamId);
	void resetTimeoutTimer(int32_t streamId);

	void tlsConnect();
	void http2Setup();
	void disconnect();

	int sendAll() {
		return nghttp2_session_send(mHttpSession.get());
	}

	void setState(State state) noexcept;

	// Private attributes
	State mState{State::Disconnected};
	std::unique_ptr<TlsConnection> mConn{};
	sofiasip::SuRoot& mRoot;
	su_wait_t mPollInWait{0};
	sofiasip::Timer mIdleTimer;
	std::string mLogPrefix{};
	int32_t mLastSID{-1};

	using NgHttp2SessionPtr = std::unique_ptr<nghttp2_session, NgHttp2SessionDeleter>;
	NgHttp2SessionPtr mHttpSession{};
	SessionSettings mSessionSettings{};

	using HttpContextList = std::vector<std::shared_ptr<HttpMessageContext>>;
	HttpContextList mPendingHttpContexts{};

	using HttpContextMap = std::map<int32_t, std::shared_ptr<HttpMessageContext>>;
	HttpContextMap mActiveHttpContexts{};

	using TimeoutTimerMap = std::map<int32_t, std::shared_ptr<sofiasip::Timer>>;
	TimeoutTimerMap mTimeoutTimers;

	/**
	 * Delay (in second) for one request timeout, default is 30. Must be inferior to Http2Client::sIdleTimeout.
	 */
	std::chrono::seconds mRequestTimeout{30};

	/**
	 * Delay (in second) before the connection with the distant HTTP2 server is closed because of inactivity.
	 */
	constexpr static std::chrono::seconds mIdleTimeout{60};
};

class Http2Tools {
public:
	static const char* frameTypeToString(uint8_t frameType) noexcept;
	static std::string printFlags(uint8_t flags) noexcept;
};

std::ostream& operator<<(std::ostream& os, const ::nghttp2_frame& frame) noexcept;
std::ostream& operator<<(std::ostream& os, flexisip::Http2Client::State state) noexcept;
} // namespace flexisip
