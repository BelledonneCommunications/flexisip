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

#include <condition_variable>
#include <ctime>
#include <functional>
#include <mutex>
#include <queue>
#include <sstream>
#include <thread>
#include <vector>

#include "../utils/transport/tls-connection.hh"
#include <openssl/ssl.h>

#include "client.hh"
#include "request.hh"

namespace flexisip {
namespace pushnotification {

class Service;

class Transport {
  public:
	using OnSuccessCb = std::function<void(Request &)>;
	using OnErrorCb = std::function<void(Request &, const std::string &)>;

	Transport() = default;
	Transport(const Transport &) = delete;
	Transport(Transport &&) = delete;
	virtual ~Transport() = default;

	/**
	 * @return
	 * 	 0: success
	 *	-1: failure
	 *	-2: failure due to stale socket. You may try to send the push again.
	 */
	virtual int sendPush(Request &req, bool hurryUp, const OnSuccessCb &onSuccess, const OnErrorCb &onError) = 0;
};

class TlsTransport : public Transport {
  public:
	TlsTransport(std::unique_ptr<TlsConnection> &&connection) noexcept : Transport{}, mConn{std::move(connection)} {
	}
	int sendPush(Request &req, bool hurryUp, const OnSuccessCb &onSuccess, const OnErrorCb &onError) override;

  private:
	struct BIODeleter {
		void operator()(BIO *bio) noexcept {
			BIO_free_all(bio);
		}
	};
	using BIOUniquePtr = std::unique_ptr<BIO, BIODeleter>;

	std::unique_ptr<TlsConnection> mConn{};
	time_t mLastUse{0};
};

class LegacyClient : public Client {
  public:
	LegacyClient(std::unique_ptr<Transport> &&transport, const std::string &name, const Service &service,
				 unsigned maxQueueSize);
	~LegacyClient() override;

	bool sendPush(const std::shared_ptr<Request> &req) override;

	bool isIdle() const noexcept override {
		return mThreadWaiting;
	}

  protected:
	void run();
	void onError(Request &req, const std::string &msg);
	void onSuccess(Request &req);

	std::string mName{};
	const Service &mService;
	std::unique_ptr<Transport> mTransport{};
	std::queue<std::shared_ptr<Request>> mRequestQueue{};
	unsigned mMaxQueueSize{0};

  private:
	std::thread mThread{};
	std::mutex mMutex{};
	std::condition_variable mCondVar{};

	bool mThreadRunning{false};
	bool mThreadWaiting{false};
};

} // namespace pushnotification
} // namespace flexisip
