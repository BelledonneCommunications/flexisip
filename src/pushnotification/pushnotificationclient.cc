/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2012  Belledonne Communications SARL.

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
#include "common.hh"

#include <boost/bind.hpp>

using namespace ::std;
using namespace ::boost;

PushNotificationClient::PushNotificationClient(const string &name, PushNotificationService *service, std::shared_ptr<boost::asio::ssl::context> ctx, const std::string &host, const std::string &port, int maxQueueSize, bool isSecure) :
		mService(service), mResolver(mService->getService()), mSocket(mService->getService(), *ctx), mContext(ctx), mName(name), mHost(host), mPort(port), mMaxQueueSize(maxQueueSize), mIsSecure(isSecure) {
	mLastUse=0;
}

int PushNotificationClient::sendRequest(const std::shared_ptr<PushNotificationRequest> &req) {
	int size = mRequestQueue.size();
	if (size >= mMaxQueueSize) {
		LOGW("PushNotificationClient(%s) queue full, push notification is lost", mName.c_str());
		return 0;
	}
	mRequestQueue.push(req);
	if (size == 0) {
		/*the client was inactive possibly for a long time. In such case, close and re-create the socket.*/
		if (mLastUse!=0){
			if (getCurrentTime()-mLastUse>60){
				LOGD("Re-creating connection with server.");
				mSocket.lowest_layer().close();
			}
		}
		next();
	} else {
		/*client is running, it will pop the queue as soon he is finished with current request*/
		LOGD("PushNotificationClient(%s) running, queue_size=%d", mName.c_str(), size);
	}
	return 1;
}

bool PushNotificationClient::isIdle() {
	return mRequestQueue.empty();
}

bool PushNotificationClient::next() {
	bool hasNext = !mRequestQueue.empty();
	LOGD("PushNotificationClient(%s) next, queue_size=%d", mName.c_str(), (int)mRequestQueue.size());
	if (hasNext) {
		if (!mSocket.lowest_layer().is_open()) {
			connect();
		} else {
			send();
		}
	}
	return hasNext;
}

void PushNotificationClient::connect() {
	asio::ip::tcp::resolver::query query(mHost, mPort);
	mResolver.async_resolve(query, bind(&PushNotificationClient::handle_resolve, this, asio::placeholders::error, asio::placeholders::iterator));
}

void PushNotificationClient::handle_resolve(const system::error_code& error, asio::ip::tcp::resolver::iterator endpoint_iterator) {
	if (!error) {
		LOGD("PushNotificationClient(%s) resolved", mName.c_str());
		asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
		mSocket.lowest_layer().async_connect(endpoint, bind(&PushNotificationClient::handle_connect, this, asio::placeholders::error, ++endpoint_iterator));
	} else {
		LOGE("PushNotificationClient(%s) resolve failed: %s(%d)", mName.c_str(), error.message().c_str(), error.value());
		onError();
	}
}

void PushNotificationClient::handle_connect(const system::error_code& error, asio::ip::tcp::resolver::iterator endpoint_iterator) {
	if (!error) {
		LOGD("PushNotificationClient(%s) connected", mName.c_str());
		if (mIsSecure) {
			mSocket.async_handshake(asio::ssl::stream_base::client, bind(&PushNotificationClient::handle_handshake, this, asio::placeholders::error));
		} else {
			LOGD("PushNotificationClient(%s) handshake skipped", mName.c_str());
			send();
		}
	} else if (endpoint_iterator != asio::ip::tcp::resolver::iterator()) {
		mSocket.lowest_layer().close();
		asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
		mSocket.lowest_layer().async_connect(endpoint, bind(&PushNotificationClient::handle_connect, this, asio::placeholders::error, ++endpoint_iterator));
	} else {
		LOGE("PushNotificationClient(%s) connect failed: %s(%d)", mName.c_str(), error.message().c_str(), error.value());
		onError();
	}
}

void PushNotificationClient::handle_handshake(const system::error_code& error) {
	if (!error) {
		LOGD("PushNotificationClient(%s) handshake done", mName.c_str());
		send();
	} else {
		LOGE("PushNotificationClient(%s) handshake failed: %s(%d)", mName.c_str(), error.message().c_str(), error.value());
		ERR_print_errors_fp(stderr);
		onError();
	}
}

void PushNotificationClient::send() {
	LOGD("PushNotificationClient(%s) send data", mName.c_str());
	mLastUse=getCurrentTime();
	if (mIsSecure) {
		asio::async_write(mSocket, asio::buffer(mRequestQueue.front()->getData()), bind(&PushNotificationClient::handle_write, this, asio::placeholders::error, asio::placeholders::bytes_transferred));
	} else {
		asio::async_write(mSocket.next_layer(), asio::buffer(mRequestQueue.front()->getData()), bind(&PushNotificationClient::handle_write, this, asio::placeholders::error, asio::placeholders::bytes_transferred));
	}
}

void PushNotificationClient::handle_write(const system::error_code& error, size_t bytes_transferred) {
	if (!error) {
		LOGD("PushNotificationClient(%s) write done", mName.c_str());
		mResponse.resize(512);
		if (mIsSecure) {
			asio::async_read(mSocket, asio::buffer(mResponse),bind(&PushNotificationClient::handle_read, this, asio::placeholders::error, asio::placeholders::bytes_transferred));
		} else {
			mSocket.next_layer().async_read_some(asio::buffer(mResponse),bind(&PushNotificationClient::handle_read, this, asio::placeholders::error, asio::placeholders::bytes_transferred));
		}
		onSuccess();
	} else {
		LOGE("PushNotificationClient(%s) write failed", mName.c_str());
		onError();
	}
}

void PushNotificationClient::handle_read(const boost::system::error_code& error, size_t bytes_transferred){
	if (!error) {
		ostringstream response;
		response<<(&mResponse[0]);
		LOGD("PushNotificationClient(%s) read done: %s", mName.c_str(),response.str().c_str());
	} else {
		LOGE("PushNotificationClient(%s) read failed", mName.c_str());
	}
}

void PushNotificationClient::onError() {
	LOGD("PushNotificationClient(%s) disconnected", mName.c_str());
	if (!mRequestQueue.empty()) mRequestQueue.pop();
	mSocket.lowest_layer().close();
	(*mService->mCountFailed)++;
	onEnd();
}

void PushNotificationClient::onSuccess() {
	mRequestQueue.pop();
	(*mService->mCountSent)++;
	onEnd();
}

void PushNotificationClient::onEnd() {
	if (!next()) {
		LOGD("PushNotificationClient(%s) idle", mName.c_str());
		mService->clientEnded();
	}
}
