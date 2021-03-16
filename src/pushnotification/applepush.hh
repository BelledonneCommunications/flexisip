/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2020  Belledonne Communications SARL, All rights reserved.

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

#include <map>
#include <queue>
#include <unordered_map>

#include <nghttp2/nghttp2.h>
#include <sofia-sip/su_wait.h>

#include "flexisip/utils/timer.hh"

#include "../utils/transport/tls-connection.hh"
#include "client.hh"
#include "request.hh"

namespace flexisip {
namespace pushnotification {

class AppleRequest : public Request {
  public:
	AppleRequest(const PushInfo &pinfo);

	const std::string &getDeviceToken() const noexcept {
		return mDeviceToken;
	}

	const std::vector<char> &getData() override {
		return mPayload;
	}
	std::string isValidResponse(const std::string &str) override {
		return std::string{};
	}
	bool isServerAlwaysResponding() override {
		return false;
	}

  protected:
	void checkDeviceToken() const;

	std::string mDeviceToken{};
	std::vector<char> mPayload{};
	ApplePushType mPayloadType = ApplePushType::Unknown;
	int mStatusCode = 0;
	std::string mReason{};

	static constexpr std::size_t MAXPAYLOAD_SIZE = 2048;
	static constexpr std::size_t DEVICE_BINARY_SIZE = 32;

	friend class AppleClient;
};

class AppleClient : public Client {
  public:
	enum class State : uint8_t { Disconnected, Connecting, Connected };

	AppleClient(su_root_t &root);

	bool sendPush(const std::shared_ptr<Request> &req) override;
	bool isIdle() const noexcept override {
		return mPNRs.empty();
	}

  private:
	/* Private classes and structs */
	class PnrContext {
	  public:
		PnrContext(AppleClient &client, const std::shared_ptr<AppleRequest> &pnr, unsigned timeout /* s */) noexcept;
		PnrContext(const PnrContext &) = delete;
		PnrContext(PnrContext &&) noexcept = default;

		const std::shared_ptr<AppleRequest> &getPnr() const noexcept {
			return mPnr;
		}

	  private:
		std::shared_ptr<AppleRequest> mPnr{};
		std::unique_ptr<sofiasip::Timer> mTimer{};
	};

	/* Private methods */
	void connect();
	void disconnect();

	bool sendAllPendingPNRs();
	void processGoAway();


	static std::vector<nghttp2_nv>
	makeNgHttp2Headers(const std::map<std::string, std::pair<std::string, nghttp2_data_flag>>);

	/* Private attributes */
	std::unordered_map<int32_t, PnrContext> mPNRs{};
	std::queue<std::shared_ptr<AppleRequest>> mPendingPNRs{};
	std::string mLogPrefix{};
	su_root_t &mRoot;
	su_wait_t mPollInWait{0};

	static constexpr unsigned sPnrTimeout =
		5; // Delay (in second) before a PNR is marked as failed because of missing response from the APNS.
};

class Http2Tools {
  public:
	static const char *frameTypeToString(uint8_t frameType) noexcept;
	static std::string printFlags(uint8_t flags) noexcept;
};

} // namespace pushnotification
} // namespace flexisip

std::ostream &operator<<(std::ostream &os, const ::nghttp2_frame &frame) noexcept;
