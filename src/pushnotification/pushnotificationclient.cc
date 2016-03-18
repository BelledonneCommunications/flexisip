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

#include "pushnotificationclient.hh"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <poll.h>

	PushNotificationClient::PushNotificationClient(const string &name, PushNotificationService *service,
		SSL_CTX * ctx, const std::string &host, const std::string &port, int maxQueueSize, bool isSecure) :
	mThread(), mThreadRunning(false), mThreadWaiting(true),  mBio(NULL),
	mName(name), mService(service), mCtx(ctx), mHost(host), mPort(port),
	mMaxQueueSize(maxQueueSize), mLastUse(0), mIsSecure(isSecure) {}



	PushNotificationClient::~PushNotificationClient() {
		if (mThreadRunning) {
			mThreadRunning = false;
			mMutex.lock();
			if (mThreadWaiting) mCondVar.notify_one();
			mMutex.unlock();
			mThread.join();
		}

		if (mBio) {
			BIO_free_all(mBio);
		}
		if (mCtx) {
			SSL_CTX_free(mCtx);
		}
	}
	int PushNotificationClient::sendPush(const std::shared_ptr<PushNotificationRequest> &req) {
		if (!mThreadRunning) {
			// start thread only when we have at least one push to send
			mThreadRunning = true;
			mThread = std::thread(&PushNotificationClient::run, this);
		}
		mMutex.lock();

		int size = mRequestQueue.size();
		if (size >= mMaxQueueSize) {
			SLOGW << "PushNotificationClient " << mName << " PNR " << req.get() << " queue full, push lost";
			onError(req, "Error queue full");
			mMutex.unlock();
			return 0;
		} else {
			mRequestQueue.push(req);
			/*client is running, it will pop the queue as soon he is finished with current request*/
			SLOGD << "PushNotificationClient " << mName << " PNR " << req.get() << " running, queue_size=" << size;

			if (mThreadWaiting) mCondVar.notify_one();
			mMutex.unlock();
			return 1;
		}
	}

	bool PushNotificationClient::isIdle() {
		return mRequestQueue.empty();
	}

	void PushNotificationClient::recreateConnection() {

		/* Setup the connection */
		if (mBio) {
			BIO_free_all(mBio);
		}

		/* Create and setup the connection */
		std::string hostname = mHost + ":" + mPort;
		SSL * ssl = NULL;

		if (mIsSecure) {
			mBio = BIO_new_connect(hostname.c_str());

			/* Set the SSL_MODE_AUTO_RETRY flag */
			BIO_get_ssl(mBio, &ssl);
			SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
			SSL_set_options(ssl, SSL_OP_ALL);
			BIO_set_nbio(mBio, 1);
		} else {
			mBio = BIO_new_connect(hostname.c_str());
		}

		int sat = BIO_do_connect(mBio);
		while (sat <= 0 && BIO_should_retry(mBio)) {
			sat = BIO_do_connect(mBio);
		}

		if (sat <= 0) {
			SLOGE << "Error attempting to connect to " << hostname << ": " << sat << " - " << strerror( errno);
			ERR_print_errors_fp(stderr);
			BIO_free_all(mBio);
			mBio = NULL;
			return;
		}

		/* Check the certificate */
		if(ssl && (SSL_get_verify_mode(ssl) == SSL_VERIFY_PEER && SSL_get_verify_result(ssl) != X509_V_OK))
		{
			SLOGE << "Certificate verification error: " << X509_verify_cert_error_string(SSL_get_verify_result(ssl));
			BIO_free_all(mBio);
			mBio = NULL;
			return;
		}
	}

	void PushNotificationClient::sendPushToServer(const std::shared_ptr<PushNotificationRequest> &req) {
		if (mLastUse == 0 || !mBio) {
			recreateConnection();
		/*the client was inactive possibly for a long time. In such case, close and re-create the socket.*/
		} else if (getCurrentTime() - mLastUse > 60) {
			SLOGD << "PushNotificationClient " << mName << " PNR " << req.get() << " previous was "
			<< getCurrentTime() - mLastUse << " secs ago, re-creating connection with server.";
			recreateConnection();
		}

		if (!mBio) {
			onError(req, "Cannot create connection to server");
			return;
		}

		/* send push to the server */
		mLastUse = getCurrentTime();
		auto buffer = req->getData();
		const char* request = std::string(buffer.begin(),buffer.end()).c_str();
		int wcount = BIO_write(mBio, buffer.data(), buffer.size());

		SLOGD << "PushNotificationClient " << mName << " PNR " << req.get() << " sent " << wcount << "/" << buffer.size() << " data";
		if (wcount <= 0) {
			onError(req, "Cannot send to server");
			return;
		}

		/* wait for server response */
		char r[1024];
		SLOGD << "PushNotificationClient " << mName << " PNR " << req.get() << " waiting for server response";
		if (BIO_pending(mBio) <= 0) {
			int fdSocket;
			if (BIO_get_fd(mBio, &fdSocket) < 0) {
				SLOGE << "PushNotificationClient " << mName << " PNR " << req.get() << " could not retrieve the socket";
				onError(req, "Broken socket");
				return;
			}
			pollfd polls = {0};
			polls.fd = fdSocket;
			polls.events = POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI;

			int nRet = poll(&polls, 1, 1000);
			// this is specific to iOS which does not send a response in case of success
			if (nRet <= 0) {
				SLOGD << "PushNotificationClient " << mName << " PNR " << req.get() << " nothing read, assuming success";
			}
		}
		while (true) {
			int p = BIO_read(mBio, r, 1023);
			if(p <= 0) {
				break;
			} else {
				SLOGD << "PushNotificationClient " << mName << " PNR " << req.get() << " read " << p << " data:\n" << r;
				string responsestr(r, p);
				if (!req->isValidResponse(responsestr)) {
					onError(req, "Invalid server response");
					return;
				}
			}
			r[p] = 0;
		}
	}

	void PushNotificationClient::run() {
		std::unique_lock<std::mutex> lock(mMutex);
		while (mThreadRunning) {
			if (!isIdle()) {
				SLOGD << "PushNotificationClient " << mName << " next, queue_size=" << mRequestQueue.size();
				auto req = mRequestQueue.front();
				mRequestQueue.pop();
				lock.unlock();

				// send push to the server and wait for its answer
				sendPushToServer(req);

				lock.lock();
			} else {
				mThreadWaiting = true;
				mCondVar.wait(lock);
				mThreadWaiting = false;
			}
		}
	}


	void PushNotificationClient::onError(shared_ptr<PushNotificationRequest> req, const string &msg) {
		SLOGD << "PushNotificationClient " << mName << " PNR " << req.get() << " failed: " << msg;
		if (mService->mCountFailed) {
			mService->mCountFailed->incr();
		}
		recreateConnection();
	}

	void PushNotificationClient::onSuccess(shared_ptr<PushNotificationRequest> req) {
		if (mService->mCountSent) {
			mService->mCountSent->incr();
		}
	}

