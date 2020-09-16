/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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

#include <unordered_map>

#include <nghttp2/nghttp2.h>

#include "pushnotification.hh"
#include "pushnotificationclient.hh"

namespace flexisip {
namespace pushnotification {

class AppleRequest : public Request {
public:
	AppleRequest(const PushInfo &pinfo);

	const std::string &getDeviceToken() const noexcept {return mDeviceToken;}

	const std::vector<char> &getData() override {return mPayload;}
	std::string isValidResponse(const std::string &str) override {return std::string{};}
	bool isServerAlwaysResponding() override {return false;}

protected:
	void checkDeviceToken() const;

	std::string mDeviceToken;
	std::vector<char> mPayload{};
	unsigned int mTtl{0};
	int mStatusCode{0};
	std::string mReason{};

	static constexpr std::size_t MAXPAYLOAD_SIZE = 2048;
	static constexpr std::size_t DEVICE_BINARY_SIZE = 32;

	friend class AppleClient;
};

class AppleClient : public Client {
public:
	enum class State : uint8_t {
		Disconnected,
		Connecting,
		Connected
	};

	class BadStateError : public std::logic_error {
	public:
		BadStateError(State state) : logic_error(formatWhatArg(state)) {}

	private:
		static std::string formatWhatArg(State state) noexcept;
	};

	AppleClient(su_root_t &root, std::unique_ptr<TlsConnection> &&conn) : mRoot{root}, mConn{std::move(conn)} {}

	bool sendPush(const std::shared_ptr<Request> &req) override;
	bool isIdle() const noexcept override {return true;}

private:
	struct NgHttp2SessionDeleter {
		void operator()(nghttp2_session *ptr) const noexcept {nghttp2_session_del(ptr);}
	};
	using NgHttp2SessionPtr = std::unique_ptr<nghttp2_session, NgHttp2SessionDeleter>;

	class HeaderStore {
	public:
		using HeaderMap = std::map<std::string, std::pair<std::string, uint8_t>>;
		using HeaderList = std::vector<nghttp2_nv>;

		HeaderStore() noexcept = default;
		template <typename T> HeaderStore(T &&hMap) noexcept : mMap{std::forward<T>(hMap)} {}
		HeaderStore(const HeaderStore &) noexcept = default;
		HeaderStore(HeaderStore &&) noexcept = default;

		HeaderMap &map() noexcept {return mMap;}
		HeaderList makeHeaderList() const noexcept;

	private:
		HeaderMap mMap{};
	};

	class DataProvider {
	public:
		DataProvider(const std::vector<char> &data) noexcept;
		DataProvider(const std::string &data) noexcept;

		const nghttp2_data_provider *getCStruct() const noexcept {return &mDataProv;}

	private:
		ssize_t read(uint8_t *buf, size_t length, uint32_t *data_flags) noexcept;

		nghttp2_data_provider mDataProv{{0}};
		std::stringstream mData{};
	};

	void connect();
	void disconnect();

	bool sendAllPendingPNRs();

	State getState() const noexcept {return mState;}
	void setState(State state) noexcept;

	ssize_t send(nghttp2_session &session, const uint8_t *data, size_t length) noexcept;
	ssize_t recv(nghttp2_session &session, uint8_t *data, size_t length) noexcept;

	void onFrameSent(nghttp2_session &session, const nghttp2_frame &frame) noexcept;
	void onFrameRecv(nghttp2_session &session, const nghttp2_frame &frame) noexcept;
	void onHeaderRecv(nghttp2_session &session, const nghttp2_frame &frame,
					  const std::string &name, const std::string &value, uint8_t flags) noexcept;
	void onDataReceived(nghttp2_session &session, uint8_t flags, int32_t streamId, const uint8_t *data, size_t datalen) noexcept;
	void onStreamClosed(nghttp2_session &session, int32_t stream_id, uint32_t error_code) noexcept;

	static int onPollInCb(su_root_magic_t *, su_wait_t *, su_wakeup_arg_t *arg) noexcept;
	static std::vector<nghttp2_nv> makeNgHttp2Headers(const std::map<std::string, std::pair<std::string, nghttp2_data_flag>>);

	su_root_t &mRoot;
	su_wait_t mPollInWait{0};
	std::unique_ptr<TlsConnection> mConn{};
	NgHttp2SessionPtr mHttpSession{};
	std::unordered_map<int32_t, std::shared_ptr<AppleRequest>> mPNRs{};
	std::queue<std::shared_ptr<AppleRequest>> mPendingPNRs{};
	State mState{State::Disconnected};
};

class Http2Tools {
public:
	static const char *frameTypeToString(uint8_t frameType) noexcept;
	static std::string printFlags(uint8_t flags) noexcept;
};

std::ostream &operator<<(std::ostream &os, const nghttp2_frame &frame) noexcept;

}
}
