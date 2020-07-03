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

class PushNotificationClient {
	public:
		PushNotificationClient(const std::string &name, const PushNotificationService &service,
			 				   SSL_CTX *ctx, const std::string &host, const std::string &port,
							   unsigned maxQueueSize, bool isSecure);
		virtual ~PushNotificationClient();

		virtual bool sendPush(const std::shared_ptr<PushNotificationRequest> &req);

		bool isIdle() const noexcept {return mThreadWaiting;}

	protected:
		void run();
		/**
		 * @return
		 * 	+  0: success
		 *	+ -1: failure
		 *	+ -2: failure due to stale socket. You may try to send the push again.
		 */
		int sendPushToServer(const std::shared_ptr<PushNotificationRequest> &req, bool hurryUp);
		void recreateConnection();
		void onError(PushNotificationRequest &req, const std::string &msg);
		void onSuccess(PushNotificationRequest &req);

		const PushNotificationService &mService;
		BIO * mBio{nullptr};
		SSL_CTX * mCtx{nullptr};
		std::queue<std::shared_ptr<PushNotificationRequest>> mRequestQueue{};
		std::string mName{};
		std::string mHost{}, mPort{};
		unsigned mMaxQueueSize{0};
		time_t mLastUse{0};
		bool mIsSecure{false};

	private:
		std::thread mThread{};
		std::mutex mMutex{};
		std::condition_variable mCondVar{};

		bool mThreadRunning{false};
		bool mThreadWaiting{false};
};

}
