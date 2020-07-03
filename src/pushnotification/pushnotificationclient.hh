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

#include <condition_variable>
#include <ctime>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

#include <openssl/ssl.h>

#include "pushnotification.hh"

namespace flexisip {

class PushNotificationService;

class PushNotificationTransport {
public:
	using OnSuccessCb = std::function<void(PushNotificationRequest &)>;
	using OnErrorCb = std::function<void(PushNotificationRequest &, const std::string &)>;

	virtual ~PushNotificationTransport() = default;

	/**
	* @return
	* 	 0: success
	*	-1: failure
	*	-2: failure due to stale socket. You may try to send the push again.
	*/
	virtual int sendPush(PushNotificationRequest &req, bool hurryUp, const OnSuccessCb &onSuccess, const OnErrorCb &onError) = 0;
};

class PushNotificationTransportTls : public PushNotificationTransport {
public:
	struct SSLCtxDeleter {
		void operator()(SSL_CTX *ssl) {SSL_CTX_free(ssl);}
	};
	using SSLCtxUniquePtr = std::unique_ptr<SSL_CTX, SSLCtxDeleter>;

	PushNotificationTransportTls(SSLCtxUniquePtr &&ctx, const std::string &host, const std::string &port, bool isSecure);
	~PushNotificationTransportTls() override = default;

	int sendPush(PushNotificationRequest &req, bool hurryUp, const OnSuccessCb &onSuccess, const OnErrorCb &onError) override;

private:
	struct BIODeleter {
		void operator()(BIO *bio) {BIO_free_all(bio);}
	};
	using BIOUniquePtr = std::unique_ptr<BIO, BIODeleter>;

	void recreateConnection();

	BIOUniquePtr mBio{nullptr};
	SSLCtxUniquePtr mCtx{nullptr};
	std::string mHost{}, mPort{};
	time_t mLastUse{0};
	bool mIsSecure{false};
};

class PushNotificationClient {
	public:
		PushNotificationClient(std::unique_ptr<PushNotificationTransport> &&transport,
							   const std::string &name, const PushNotificationService &service, unsigned maxQueueSize);
		virtual ~PushNotificationClient();

		virtual bool sendPush(const std::shared_ptr<PushNotificationRequest> &req);

		bool isIdle() const noexcept {return mThreadWaiting;}

	protected:
		void run();
		void onError(PushNotificationRequest &req, const std::string &msg);
		void onSuccess(PushNotificationRequest &req);

		std::string mName{};
		const PushNotificationService &mService;
		std::unique_ptr<PushNotificationTransport> mTransport{};
		std::queue<std::shared_ptr<PushNotificationRequest>> mRequestQueue{};
		unsigned mMaxQueueSize{0};

	private:
		std::thread mThread{};
		std::mutex mMutex{};
		std::condition_variable mCondVar{};

		bool mThreadRunning{false};
		bool mThreadWaiting{false};
};

}
