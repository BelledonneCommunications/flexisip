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

#include <nghttp2/nghttp2.h>

#include "pushnotification.hh"
#include "pushnotificationclient.hh"

namespace flexisip {
namespace pushnotification {

class AppleRequest : public Request {
public:
	AppleRequest(const PushInfo &pinfo);

	std::string getDeviceTokenAsString() const noexcept;

	const std::vector<char> &getData() override;
	std::string isValidResponse(const std::string &str) override;
	bool isServerAlwaysResponding() override {return false;}

protected:
	struct Item{
		uint8_t mId{0};
		std::vector<char> mData;

		void clear() noexcept {mData.clear();}
	};

	int formatDeviceToken(const std::string &deviceToken);
	void createPushNotification();
	std::size_t writeItem(std::size_t pos, const Item &item);

	static constexpr std::size_t MAXPAYLOAD_SIZE = 2048;
	static constexpr std::size_t DEVICE_BINARY_SIZE = 32;
	std::vector<char> mBuffer;
	std::vector<char> mDeviceToken;
	std::string mPayload;
	unsigned int mTtl{0};
	static uint32_t sIdentifier;
};

class AppleClient : public Client {
public:
	AppleClient(su_root_t *root, std::unique_ptr<TlsConnection> &&conn) : mRoot{root}, mConn{std::move(conn)} {}

	bool sendPush(const std::shared_ptr<Request> &req) override;
	bool isIdle() const noexcept override {return true;}

private:
	struct NgHttp2SessionDeleter {
		void operator()(nghttp2_session *ptr) const noexcept {nghttp2_session_del(ptr);}
	};
	using NgHttp2SessionPtr = std::unique_ptr<nghttp2_session, NgHttp2SessionDeleter>;

	class DataProvider {
	public:
		DataProvider(const std::vector<char> &data) noexcept;

		const nghttp2_data_provider *getCStruct() const noexcept {return &mDataProv;}

	private:
		ssize_t read(uint8_t *buf, size_t length, uint32_t *data_flags) noexcept;

		nghttp2_data_provider mDataProv{{0}};
		std::stringstream mData{};
	};

	void connect();
	void disconnect();
	bool isConnected() const noexcept {return mHttpSession != nullptr;}

	ssize_t send(const uint8_t *data, size_t length) noexcept;
	ssize_t recv(uint8_t *data, size_t length) noexcept;

	void onFrameSent(const nghttp2_frame *frame) noexcept;
	void onFrameRecv(const nghttp2_frame *frame) noexcept;
	void onDataReceived(int32_t streamId, const uint8_t *data, size_t datalen) noexcept;

	static int onPollInCb(su_root_magic_t *, su_wait_t *, su_wakeup_arg_t *arg) noexcept;

	static const char *frameTypeToString(uint8_t frameType) noexcept;

	su_root_t *mRoot{nullptr};
	su_wait_t mPollInWait{0};
	std::unique_ptr<TlsConnection> mConn{};
	NgHttp2SessionPtr mHttpSession{};
};

}
}
