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

#include <poll.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <flexisip/common.hh>
#include <flexisip/logmanager.hh>

#include "pushnotificationservice.hh"

#include "pushnotificationclient.hh"

using namespace std;

namespace flexisip {

PushNotificationTransportTls::PushNotificationTransportTls(SSLCtxUniquePtr &&ctx, const std::string &host, const std::string &port, bool isSecure)
	: mCtx{move(ctx)}, mHost{host}, mPort{port}, mIsSecure{isSecure} {}

int PushNotificationTransportTls::sendPush(PushNotificationRequest &req, bool hurryUp, const OnSuccessCb &onSuccess, const OnErrorCb &onError) {
	if (mLastUse == 0 || mBio == nullptr) {
		recreateConnection();
	/*the client was inactive possibly for a long time. In such case, close and re-create the socket.*/
	} else if (getCurrentTime() - mLastUse > 60) {
		SLOGD << "PushNotificationTransportTls PNR " << &req << " previous was "
		<< getCurrentTime() - mLastUse << " secs ago, re-creating connection with server.";
		recreateConnection();
	}

	if (mBio == nullptr) {
		onError(req, "Cannot create connection to server");
		return -1;
	}

	/* send push to the server */
	mLastUse = getCurrentTime();
	auto buffer = req.getData();
	int wcount = BIO_write(mBio.get(), buffer.data(), buffer.size());

	SLOGD << "PushNotificationTransportTls PNR " << &req << " sent " << wcount << "/" << buffer.size() << " data";
	if (wcount <= 0) {
		SLOGE << "PushNotificationTransportTls PNR " << &req << " failed to send to server.";
		onError(req, "Cannot send to server");
		recreateConnection();
		return -2;
	}

	/* wait for server response */
	SLOGD << "PushNotificationTransportTls PNR " << &req << " waiting for server response";
	/* if the server response is NOT immediate, wait for something to read on the socket first */
	if (!req.isServerAlwaysResponding()) {
		int fdSocket;
		if (BIO_get_fd(mBio.get(), &fdSocket) < 0) {
			SLOGE << "PushNotificationTransportTls PNR " << &req << " could not retrieve the socket";
			onError(req, "Broken socket");
			return -2;
		}
		pollfd polls = {0};
		polls.fd = fdSocket;
		polls.events = POLLIN;

		int timeout = hurryUp ? 0 : 1000; /*if there are many pending push notification request in our queue, we will not wait
					the answer from the server (we are in the case where there is an answer ONLY if the push request had an error*/
		int nRet = poll(&polls, 1, timeout);
		// this is specific to iOS which does not send a response in case of success
		if (nRet == 0) {//poll timeout, we shall not expect a response.
			SLOGD << "PushNotificationTransportTls PNR " << &req << " nothing read, assuming success";
			onSuccess(req);
			return 0;
		} else if (nRet == -1) {
			SLOGD << "PushNotificationTransportTls PNR " << &req << " poll error ("<<strerror(errno)<<"), assuming success";
			onSuccess(req);
			recreateConnection();//our socket is not going so well if we go here.
			return 0;
		} else if ((polls.revents & POLLIN) == 0) {
			SLOGD << "PushNotificationTransportTls PNR " << &req << "error reading response, closing connection";
			recreateConnection();
			return -2;
		}
	}

	char r[1024];
	int p = BIO_read(mBio.get(), r, sizeof(r)-1);
	if (p <= 0) {
		SLOGE << "PushNotificationTransportTls PNR " << &req << "error reading mandatory response: " << p;
		recreateConnection();
		return -2;
	}

	r[p] = '\0';
	SLOGD << "PushNotificationTransportTls PNR " << &req << " read " << p << " data:\n" << r;
	string responsestr(r, p);
	string error = req.isValidResponse(responsestr);
	if (!error.empty()) {
		onError(req, "Invalid server response: " + error);
		// on iOS at least, when an error happens, the socket is semibroken (server ignore all future requests),
		// so we force to recreate the connection
		recreateConnection();
		return -1;
	}
	onSuccess(req);
	return 0;
}

void PushNotificationTransportTls::recreateConnection() {
	/* Setup the connection */
	mBio.reset();

	/* Create and setup the connection */
	auto hostname = mHost + ":" + mPort;
	SSL *ssl = nullptr;

	BIOUniquePtr newBio{};
	if (mIsSecure) {
		mBio = BIOUniquePtr{BIO_new_ssl_connect(mCtx.get())};
		BIO_set_conn_hostname(mBio.get(), hostname.c_str());
		/* Set the SSL_MODE_AUTO_RETRY flag */
		BIO_get_ssl(mBio.get(), &ssl);
		SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
		SSL_set_options(ssl, SSL_OP_ALL);
	}else{
		mBio =  BIOUniquePtr{BIO_new_connect(hostname.c_str())};
	}

	int sat = BIO_do_connect(mBio.get());

	if (sat <= 0) {
		SLOGE << "Error attempting to connect to " << hostname << ": " << sat << " - " << strerror( errno);
		ERR_print_errors_fp(stderr);
		return;
	}

	if (mIsSecure) {
		sat = BIO_do_handshake(mBio.get());
		if (sat <= 0) {
			SLOGE << "Error attempting to handshake to " << hostname << ": " << sat << " - " << strerror( errno);
			ERR_print_errors_fp(stderr);
			return;
		}
	}

	/* Check the certificate */
	if(ssl && (SSL_get_verify_mode(ssl) == SSL_VERIFY_PEER && SSL_get_verify_result(ssl) != X509_V_OK)) {
		SLOGE << "Certificate verification error: " << X509_verify_cert_error_string(SSL_get_verify_result(ssl));
		return;
	}

	mBio = move(newBio);
}

PushNotificationClient::PushNotificationClient(std::unique_ptr<PushNotificationTransport> &&transport,
											   const string &name, const PushNotificationService &service, unsigned maxQueueSize) :
	mName{name}, mService{service}, mTransport{move(transport)}, mMaxQueueSize{maxQueueSize} {}

PushNotificationClient::~PushNotificationClient() {
	if (mThreadRunning) {
		mThreadRunning = false;
		mMutex.lock();
		if (mThreadWaiting) mCondVar.notify_one();
		mMutex.unlock();
		mThread.join();
	}
}

bool PushNotificationClient::sendPush(const std::shared_ptr<PushNotificationRequest> &req) {
	if (!mThreadRunning) {
		// start thread only when we have at least one push to send
		mThreadRunning = true;
		mThreadWaiting = false;
		mThread = std::thread(&PushNotificationClient::run, this);
	}
	mMutex.lock();

	auto size = mRequestQueue.size();
	if (size >= mMaxQueueSize) {
		mMutex.unlock();
		SLOGW << "PushNotificationClient " << mName << " PNR " << req.get() << " queue full, push lost";
		onError(*req, "Error queue full");
		req->setState(PushNotificationRequest::State::Failed);
		return false;
	} else {
		req->setState(PushNotificationRequest::State::InProgress);
		mRequestQueue.push(req);
		/*client is running, it will pop the queue as soon he is finished with current request*/
		SLOGD << "PushNotificationClient " << mName << " PNR " << req.get() << " running, queue_size=" << size;

		if (mThreadWaiting) mCondVar.notify_one();
		mMutex.unlock();
		return true;
	}
}

void PushNotificationClient::run() {
	std::unique_lock<std::mutex> lock(mMutex);
	while (mThreadRunning) {
		if (!mRequestQueue.empty()) {
			size_t size =  mRequestQueue.size();
			SLOGD << "PushNotificationClient " << mName << " next, queue_size=" <<  size;
			auto req = mRequestQueue.front();
			mRequestQueue.pop();
			lock.unlock();

			// send push to the server and wait for its answer
			auto _onSuccess = [this](PushNotificationRequest &req) {this->onSuccess(req);};
			auto _onError = [this](PushNotificationRequest &req, const std::string &msg) {this->onError(req, msg);};
			bool hurryUp = size > 2;
			if (mTransport->sendPush(*req, hurryUp, _onSuccess, _onError) == -2) {
				SLOGD << "PushNotificationClient " << mName << " PNR " << req.get() << ": try to send again";
				mTransport->sendPush(*req, hurryUp, _onSuccess, _onError);
			}

			lock.lock();
		} else {
			mThreadWaiting = true;
			mCondVar.wait(lock);
			mThreadWaiting = false;
		}
	}
}

void PushNotificationClient::onError(PushNotificationRequest &req, const string &msg) {
	SLOGW << "PushNotificationClient " << mName << " PNR " << &req << " failed: " << msg;
	req.setState(PushNotificationRequest::State::Failed);
	auto countFailed = mService.getFailedCounter();
	if (countFailed) countFailed->incr();
}

void PushNotificationClient::onSuccess(PushNotificationRequest &req) {
	req.setState(PushNotificationRequest::State::Successful);
	auto countSent = mService.getSentCounter();
	if (countSent) countSent->incr();
}

} // end of flexisip namespace
