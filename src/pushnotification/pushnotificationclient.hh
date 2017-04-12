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

#include <queue>
#include <vector>
#include <ctime>
#include <mutex>
#include <thread>

#include <openssl/ssl.h>

#include "pushnotificationservice.hh"

class PushNotificationClient {
	public:
		PushNotificationClient(const std::string &name, PushNotificationService *service,
			 				   SSL_CTX * ctx,
							   const std::string &host, const std::string &port,
							   int maxQueueSize, bool isSecure);
		virtual ~PushNotificationClient();
		virtual int sendPush(const std::shared_ptr<PushNotificationRequest> &req);
		bool isIdle();
		void run();

	protected:
		void sendPushToServer(const std::shared_ptr<PushNotificationRequest> &req);
		void recreateConnection();
		void onError(std::shared_ptr<PushNotificationRequest> req, const std::string &msg);
		void onSuccess(std::shared_ptr<PushNotificationRequest> req);

	protected:
		PushNotificationService *mService;
		BIO * mBio;
		SSL_CTX * mCtx;
		std::queue<std::shared_ptr<PushNotificationRequest>> mRequestQueue;
		std::string mName;
		std::string mHost, mPort;
		int mMaxQueueSize;
		time_t mLastUse;
		bool mIsSecure;
	private:
		std::thread mThread;
		std::mutex mMutex;
		std::condition_variable mCondVar;

		bool mThreadRunning;
		bool mThreadWaiting;
};
