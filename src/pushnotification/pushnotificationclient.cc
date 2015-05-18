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
#include "common.hh"

#include <boost/bind.hpp>

using namespace ::std;
namespace asio = boost::asio;
namespace ip = asio::ip;

typedef boost::system::error_code err_code;
typedef ip::tcp::resolver::iterator TcpResIt;


PushNotificationClient::PushNotificationClient(const string &name, PushNotificationService *service, std::shared_ptr<boost::asio::ssl::context> ctx, const std::string &host, const std::string &port, int maxQueueSize, bool isSecure) :
		mService(service), mResolver(mService->getService()),
		mSocket(mService->getService(), *ctx), mContext(ctx), mRequestQueue(),
		mName(name), mHost(host), mPort(port),
		mMaxQueueSize(maxQueueSize), mIsSecure(isSecure) {
	mLastUse=0;
}

int PushNotificationClient::sendRequest(const std::shared_ptr<PushNotificationRequest> &req) {
	int size = mRequestQueue.size();
	if (size >= mMaxQueueSize) {
		SLOGW << "PushNotificationClient " << mName << " PNR " << req.get() << " queue full, push lost";
		req->getCallBack()->onError("Error queue full");
		return 0;
	}

	mRequestQueue.push(req);
	if (size == 0) {
		/*the client was inactive possibly for a long time. In such case, close and re-create the socket.*/
		if (mLastUse!=0 && (getCurrentTime() - mLastUse > 60)){
			SLOGD << "PushNotificationClient " << mName << " PNR " << req.get() << " re-creating connection with server.";
			mSocket.lowest_layer().close();
		}
		next();
	} else {
		/*client is running, it will pop the queue as soon he is finished with current request*/
		SLOGD << "PushNotificationClient " << mName << " PNR " << req.get() << " running, queue_size=" << size;
	}
	return 1;
}

bool PushNotificationClient::isIdle() {
	return mRequestQueue.empty();
}

bool PushNotificationClient::next() {
	bool hasNext = !mRequestQueue.empty();
	SLOGD << "PushNotificationClient " << mName << " next, queue_size=" << mRequestQueue.size();
	if (hasNext) {
		if (!mSocket.lowest_layer().is_open()) {
			connect(mRequestQueue.front());
		} else {
			send(mRequestQueue.front());
		}
	}
	return hasNext;
}

void PushNotificationClient::connect(shared_ptr<PushNotificationRequest> req) {
	auto fn (bind(&PushNotificationClient::handle_resolve, this, req, asio::placeholders::error, asio::placeholders::iterator));
	if (mName == "google") {
		// ipv6 filtering by google is broken
		mResolver.async_resolve(ip::tcp::resolver::query(ip::tcp::v4(), mHost, mPort), fn);
	} else {
		mResolver.async_resolve(ip::tcp::resolver::query(mHost, mPort), fn);
	}
}

void PushNotificationClient::handle_resolve(shared_ptr<PushNotificationRequest> req, const err_code & error, TcpResIt endpoint_iterator) {
	if (!error) {
		SLOGD << "PushNotificationClient " << mName << " PNR " << req.get() << " resolved";
		ip::tcp::endpoint endpoint = *endpoint_iterator;
		mSocket.lowest_layer().async_connect(endpoint, bind(&PushNotificationClient::handle_connect, this, req, asio::placeholders::error, ++endpoint_iterator));
	} else {
		SLOGE << "PushNotificationClient " << mName << " PNR " << req.get() << " resolve failed: " << error.message();
		onError(req);
	}
}

void PushNotificationClient::handle_connect(shared_ptr<PushNotificationRequest> req, const err_code & error, TcpResIt endpoint_iterator) {
	if (!error) {
		SLOGD << "PushNotificationClient " << mName << " PNR " << req.get() << " connected";
		if (mIsSecure) {
			mSocket.async_handshake(asio::ssl::stream_base::client, bind(&PushNotificationClient::handle_handshake, this, req, asio::placeholders::error));
		} else {
			SLOGD << "PushNotificationClient " << mName << " PNR " << req.get() << " handshake skipped";
			send(req);
		}
	} else if (endpoint_iterator != TcpResIt()) {
		mSocket.lowest_layer().close();
		ip::tcp::endpoint endpoint = *endpoint_iterator;
		mSocket.lowest_layer().async_connect(endpoint, bind(&PushNotificationClient::handle_connect, this, req, asio::placeholders::error, ++endpoint_iterator));
	} else {
		SLOGE << "PushNotificationClient " << mName << " PNR " << req.get() << " connect failed: " << error.message();
		onError(req);
	}
}

void PushNotificationClient::handle_handshake(shared_ptr<PushNotificationRequest> req, const err_code & error) {
	if (!error) {
		SLOGD << "PushNotificationClient " << mName << " PNR " << req.get() << " handshake done";
		send(req);
	} else {
		SLOGE << "PushNotificationClient " << mName << " PNR " << req.get() << " handshake failed: " << error.message();
		ERR_print_errors_fp(stderr);
		onError(req);
	}
}

void PushNotificationClient::send(shared_ptr<PushNotificationRequest> req) {
	SLOGD << "PushNotificationClient " << mName << " PNR " << req.get() << " send data";
	mLastUse=getCurrentTime();
	auto fn=bind(&PushNotificationClient::handle_write, this, req, asio::placeholders::error, asio::placeholders::bytes_transferred);
	auto buffer = asio::buffer(req->getData());
	if (mIsSecure) {
		asio::async_write(mSocket, buffer, fn);
	} else {
		asio::async_write(mSocket.next_layer(),buffer, fn);
	}
}

void PushNotificationClient::handle_write(shared_ptr< PushNotificationRequest > req, const boost::system::error_code &error, size_t bytes_transferred) {
	if (!error) {
		SLOGD << "PushNotificationClient " << mName << " PNR " << req.get() << " write done";
		mResponse.resize(512);
		if (!req->mustReadServerResponse()) {
			SLOGD << "PushNotificationClient " << mName << " PNR " << req.get() << " not reading response";
			onSuccess(req);
			return;
		}
		auto fn=bind(&PushNotificationClient::handle_read, this, req, asio::placeholders::error, asio::placeholders::bytes_transferred);
		if (mIsSecure) {
			mSocket.async_read_some(asio::buffer(mResponse), fn);
			//asio::async_read(mSocket, asio::buffer(mResponse), fn);
		} else {
			mSocket.next_layer().async_read_some(asio::buffer(mResponse), fn);
		}
	} else {
		SLOGE << "PushNotificationClient " << mName << " PNR " << req.get() << " write failed";
		onError(req);
	}
}

void PushNotificationClient::handle_read(shared_ptr<PushNotificationRequest> req, const err_code & error, size_t bytes_transferred){
	if (!error) {
		string responsestr(mResponse.data(), mResponse.size());
		SLOGD << "PushNotificationClient " << mName << " PNR " << req.get() << " read done: " << responsestr;
		if (!req->isValidResponse(responsestr))
			onError(req, "Invalid response");
		else
			onSuccess(req);
	} else {
		SLOGE << "PushNotificationClient " << mName << " PNR " << req.get() << " read failed : " << error.message();
		onError(req);
	}
}

void PushNotificationClient::onError(shared_ptr< PushNotificationRequest > req, const string &msg) {
	SLOGD << "PushNotificationClient " << mName << " PNR " << req.get() << " disconnected";
	if (req->getCallBack()) req->getCallBack()->onError("Error " + msg);

	if (mRequestQueue.front() != req)
		SLOGE << "PushNotificationClient " << mName << " PNR " << req.get() << " != " << mRequestQueue.front().get();
	mRequestQueue.pop();
	mSocket.lowest_layer().close();
	if (mService->mCountFailed) mService->mCountFailed->incr();
	onEnd(); // that is the end for this socket, continue...
}

void PushNotificationClient::onSuccess(shared_ptr<PushNotificationRequest> req) {
	if (mRequestQueue.front() != req)
		SLOGE << "PushNotificationClient " << mName << " PNR " << req.get() << " != " << mRequestQueue.front().get();
	mRequestQueue.pop();
	if (mService->mCountSent) mService->mCountSent->incr();
	onEnd();
}

void PushNotificationClient::onEnd() {
	if (!next()) {
		SLOGD << "PushNotificationClient " << mName << " idle";
		mService->clientEnded();
	}
}
