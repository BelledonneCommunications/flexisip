/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023  Belledonne Communications SARL, All rights reserved.

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

#include <algorithm>
#include <limits>
#include <sstream>

#include <poll.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <flexisip/common.hh>
#include <flexisip/logmanager.hh>

#include "pushnotification/request.hh"
#include "pushnotification/service.hh"

#include "legacy-client.hh"

using namespace std;

namespace flexisip {
namespace pushnotification {

int TlsTransport::sendPush(LegacyRequest& req, bool hurryUp, const OnSuccessCb& onSuccess, const OnErrorCb& onError) {
	if (mLastUse == 0 || !mConn->isConnected()) {
		mConn->resetConnection();
		/*the client was inactive possibly for a long time. In such case, close and re-create the socket.*/
	} else if (getCurrentTime() - mLastUse > 60) {
		SLOGD << "PushNotificationTransportTls PNR " << &req << " previous was " << getCurrentTime() - mLastUse
		      << " secs ago, re-creating connection with server.";
		mConn->resetConnection();
	}

	if (!mConn->isConnected()) {
		onError(req, "Cannot create connection to server");
		return -1;
	}

	/* send push to the server */
	mLastUse = getCurrentTime();
	const auto& buffer = req.getData(mUrl, mMethod);
	int wcount = mConn->write(buffer);

	SLOGD << "PushNotificationTransportTls PNR " << &req << " sent " << wcount << "/" << buffer.size() << " data";
	if (wcount <= 0) {
		SLOGE << "PushNotificationTransportTls PNR " << &req << " failed to send to server.";
		onError(req, "Cannot send to server");
		mConn->resetConnection();
		return -2;
	}

	/* wait for server response */
	SLOGD << "PushNotificationTransportTls PNR " << &req << " waiting for server response";
	/* if the server response is NOT immediate, wait for something to read on the socket first */
	if (!req.isServerAlwaysResponding()) {
		int fdSocket;
		if (BIO_get_fd(mConn->getBIO(), &fdSocket) < 0) {
			SLOGE << "PushNotificationTransportTls PNR " << &req << " could not retrieve the socket";
			onError(req, "Broken socket");
			return -2;
		}
		pollfd polls = {0};
		polls.fd = fdSocket;
		polls.events = POLLIN;

		int timeout =
		    hurryUp ? 0
		            : 1000; /*if there are many pending push notification request in our queue, we will not wait
	  the answer from the server (we are in the case where there is an answer ONLY if the push request had an error*/
		int nRet = poll(&polls, 1, timeout);
		// this is specific to iOS which does not send a response in case of success
		if (nRet == 0) { // poll timeout, we shall not expect a response.
			SLOGD << "PushNotificationTransportTls PNR " << &req << " nothing read, assuming success";
			onSuccess(req);
			return 0;
		} else if (nRet == -1) {
			SLOGD << "PushNotificationTransportTls PNR " << &req << " poll error (" << strerror(errno)
			      << "), assuming success";
			onSuccess(req);
			mConn->resetConnection(); // our socket is not going so well if we go here.
			return 0;
		} else if ((polls.revents & POLLIN) == 0) {
			SLOGD << "PushNotificationTransportTls PNR " << &req << "error reading response, closing connection";
			mConn->resetConnection();
			return -2;
		}
	}

	string responseStr{};
	int nbRead = mConn->readAll(responseStr);
	if (nbRead <= 0) {
		SLOGE << "PushNotificationTransportTls PNR " << &req << "error reading mandatory response: " << responseStr;
		mConn->resetConnection();
		return -2;
	}

	SLOGD << "PushNotificationTransportTls PNR " << &req << " read " << nbRead << " data:\n" << responseStr;
	string error = req.isValidResponse(responseStr);
	if (!error.empty()) {
		onError(req, "Invalid server response: " + error);
		// on iOS at least, when an error happens, the socket is semi-broken (server ignore all future requests),
		// so we force to recreate the connection
		mConn->resetConnection();
		return -1;
	}
	onSuccess(req);
	return 0;
}

LegacyClient::LegacyClient(std::unique_ptr<Transport>&& transport,
                           const string& name,
                           unsigned maxQueueSize,
                           const Service* service)
    : Client{service}, mName{name}, mTransport{std::move(transport)}, mMaxQueueSize{maxQueueSize} {
}

LegacyClient::~LegacyClient() {
	if (mThreadRunning) {
		mThreadRunning = false;
		mMutex.lock();
		if (mThreadWaiting) mCondVar.notify_one();
		mMutex.unlock();
		mThread.join();
	}
}

void LegacyClient::sendPush(const std::shared_ptr<Request>& req) {
	auto legacyReq = dynamic_pointer_cast<LegacyRequest>(req);

	if (!mThreadRunning) {
		// start thread only when we have at least one push to send
		mThreadRunning = true;
		mThreadWaiting = false;
		mThread = std::thread(&LegacyClient::run, this);
	}
	mMutex.lock();

	auto size = mRequestQueue.size();
	if (size >= mMaxQueueSize) {
		mMutex.unlock();
		SLOGW << "LegacyClient PushNotificationClient " << mName << " PNR " << legacyReq.get()
		      << " queue full, push lost";
		onError(*legacyReq, "Error queue full");
		legacyReq->setState(Request::State::Failed);
	} else {
		legacyReq->setState(Request::State::InProgress);
		mRequestQueue.push(legacyReq);
		/*client is running, it will pop the queue as soon he is finished with current request*/
		SLOGD << "LegacyClient PushNotificationClient " << mName << " PNR " << legacyReq.get()
		      << " running, queue_size=" << size;

		if (mThreadWaiting) mCondVar.notify_one();
		mMutex.unlock();
	}
}

void LegacyClient::run() noexcept {
	std::unique_lock<std::mutex> lock(mMutex);
	while (mThreadRunning) {
		if (!mRequestQueue.empty()) {
			size_t size = mRequestQueue.size();
			SLOGD << "LegacyClient PushNotificationClient " << mName << " next, queue_size=" << size;
			auto req = mRequestQueue.front();
			mRequestQueue.pop();
			lock.unlock();

			// send push to the server and wait for its answer
			auto _onSuccess = [this](auto& req) { this->onSuccess(req); };
			auto _onError = [this](auto& req, const std::string& msg) { this->onError(req, msg); };
			bool hurryUp = size > 2;
			try {
				if (mTransport->sendPush(*req, hurryUp, _onSuccess, _onError) == -2) {
					SLOGD << "LegacyClient PushNotificationClient " << mName << " PNR " << req.get()
					      << ": try to send again";
					mTransport->sendPush(*req, hurryUp, _onSuccess, _onError);
				}
			} catch (const exception& e) {
				SLOGE << "LegacyClient[" << this << "]: cannot send PNR[" << req.get() << "]: " << e.what();
				_onError(*req, e.what());
			}

			lock.lock();
		} else {
			mThreadWaiting = true;
			mCondVar.wait(lock);
			mThreadWaiting = false;
		}
	}
}

void LegacyClient::onError(LegacyRequest& req, const string& msg) {
	SLOGW << "LegacyClient PushNotificationClient " << mName << " PNR " << &req << " failed: " << msg;
	req.setState(Request::State::Failed);
	incrFailedCounter();
}

void LegacyClient::onSuccess(LegacyRequest& req) {
	req.setState(Request::State::Successful);
	incrSentCounter();
}

} // namespace pushnotification
} // namespace flexisip
