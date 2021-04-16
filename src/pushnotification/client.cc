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

#include <algorithm>
#include <chrono>
#include <limits>
#include <sstream>
#include <thread>

#include <poll.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <flexisip/common.hh>
#include <flexisip/logmanager.hh>

#include "service.hh"

#include "request.hh"

using namespace std;

namespace flexisip {
namespace pushnotification {

TlsConnection::TlsConnection(const std::string &host, const std::string &port, const SSL_METHOD *method) noexcept
	: mHost{host}, mPort{port}
{
	if (method) {
		auto ctx = SSL_CTX_new(method);
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
		mCtx.reset(ctx);
	}
}

TlsConnection::TlsConnection(const std::string &host, const std::string &port, SSLCtxUniquePtr &&ctx) noexcept
	: mCtx{move(ctx)}, mHost{host}, mPort{port} {}

void TlsConnection::connect() noexcept {
	if (isConnected()) return;

	/* Set connection paramters */
	auto hostname = mHost + ":" + mPort;
	SSL *ssl = nullptr;
	BIOUniquePtr newBio{};
	if (isSecured()) {
		newBio = BIOUniquePtr{BIO_new_ssl_connect(mCtx.get())};
		BIO_set_conn_hostname(newBio.get(), hostname.c_str());
		BIO_set_nbio(newBio.get(), 1);
		BIO_get_ssl(newBio.get(), &ssl);
		SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
		SSL_set_options(ssl, SSL_OP_ALL);
	}else{
		// keep the const_cast() here because BIO_new_connect() takes a 'char *' in old revision of OpenSSL.
		newBio =  BIOUniquePtr{BIO_new_connect(const_cast<char *>(hostname.c_str()))};
	}

	/* Ensure that the error queue is empty */
	ERR_clear_error();

	/* Do the connection by actively waiting for connection completion */
	auto status = 0;
	chrono::milliseconds time{0};
	while (status <= 0) {
		const auto proto = isSecured() ? "tls://" : "tcp://";
		const auto errmsg = string{"Error while connecting to "} + proto + hostname;

		status = isSecured() ? BIO_do_handshake(newBio.get()) : BIO_do_connect(newBio.get());
		if (status <= 0 && !BIO_should_retry(newBio.get())) {
			handleBioError(errmsg, status);
			return;
		}
		if (time >= mTimeout) {
			SLOGE << errmsg << ": timeout";
			return;
		}

		constexpr chrono::milliseconds sleepDuration{100};
		this_thread::sleep_for(sleepDuration);
		time += sleepDuration;
	};

	/* Check the certificate */
	if(ssl && (SSL_get_verify_mode(ssl) == SSL_VERIFY_PEER && SSL_get_verify_result(ssl) != X509_V_OK)) {
		SLOGE << "Certificate verification error: " << X509_verify_cert_error_string(SSL_get_verify_result(ssl));
		return;
	}

	mBio = move(newBio);
}

void TlsConnection::resetConnection() noexcept {
	disconnect();
	connect();
}

int TlsConnection::getFd() const noexcept {
	int fd;
	if (mBio == nullptr) return -1;
	ERR_clear_error();
	auto status = BIO_get_fd(mBio.get(), &fd);
	if (status < 0) {
		handleBioError("TlsConnection: getting fd from BIO failed. ", status);
		return -1;
	}
	return fd;
}

int TlsConnection::read(void *data, int dlen) noexcept {
	ERR_clear_error();
	auto nread = BIO_read(mBio.get(), data, dlen);
	if (nread < 0) {
		if (BIO_should_retry(mBio.get())) return 0;
		ostringstream err{};
		err << "TlsConnection[" << this << "]: error while reading data. ";
		handleBioError(err.str(), nread);
	}
	return nread;
}

int TlsConnection::write(const void *data, int dlen) noexcept {
	ERR_clear_error();
	auto nwritten = BIO_write(mBio.get(), data, dlen);
	if (nwritten < 0) {
		if (BIO_should_retry(mBio.get())) return 0;
		ostringstream err{};
		err << "TlsConnection[" << this << "]: error while writting data. ";
		handleBioError(err.str(), nwritten);
	}
	return nwritten;
}

bool TlsConnection::waitForData(int timeout) const {
	int fdSocket;
	ERR_clear_error();
	if (BIO_get_fd(getBIO(), &fdSocket) < 0) {
		ERR_clear_error();
		throw runtime_error("no associated socket");
	}

	pollfd polls = {0};
	polls.fd = fdSocket;
	polls.events = POLLIN;

	int ret;
	if ((ret = poll(&polls, 1, timeout)) < 0) {
		throw runtime_error(string{"poll() failed: "} + strerror(errno));
	}
	return ret != 0;
}

void TlsConnection::handleBioError(const std::string &msg, int status) {
	ostringstream os{};
	os << msg << ": " << status << " - " << strerror(errno) << " - SSL error stack:";
	ERR_print_errors_cb(
		[] (const char *str, size_t len, void *u) {
			auto &os = *static_cast<ostream *>(u);
			os << endl << '\t' << str;
			return 0;
		},
		&os
	);
	SLOGE << os.str();
}

int TlsTransport::sendPush(Request &req, bool hurryUp, const OnSuccessCb &onSuccess, const OnErrorCb &onError) {
	if (mLastUse == 0 || !mConn->isConnected()) {
		mConn->resetConnection();
	/*the client was inactive possibly for a long time. In such case, close and re-create the socket.*/
	} else if (getCurrentTime() - mLastUse > 60) {
		SLOGD << "PushNotificationTransportTls PNR " << &req << " previous was "
		<< getCurrentTime() - mLastUse << " secs ago, re-creating connection with server.";
		mConn->resetConnection();
	}

	if (!mConn->isConnected()) {
		onError(req, "Cannot create connection to server");
		return -1;
	}

	/* send push to the server */
	mLastUse = getCurrentTime();
	auto buffer = req.getData();
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
			mConn->resetConnection();//our socket is not going so well if we go here.
			return 0;
		} else if ((polls.revents & POLLIN) == 0) {
			SLOGD << "PushNotificationTransportTls PNR " << &req << "error reading response, closing connection";
			mConn->resetConnection();
			return -2;
		}
	}

	char r[1024];
	int p = mConn->read(r, sizeof(r)-1);
	if (p <= 0) {
		SLOGE << "PushNotificationTransportTls PNR " << &req << "error reading mandatory response: " << p;
		mConn->resetConnection();
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
		mConn->resetConnection();
		return -1;
	}
	onSuccess(req);
	return 0;
}

LegacyClient::LegacyClient(std::unique_ptr<Transport> &&transport, const string &name, const Service &service, unsigned maxQueueSize)
: mName{name}, mService{service}, mTransport{move(transport)}, mMaxQueueSize{maxQueueSize} {}

LegacyClient::~LegacyClient() {
	if (mThreadRunning) {
		mThreadRunning = false;
		mMutex.lock();
		if (mThreadWaiting) mCondVar.notify_one();
		mMutex.unlock();
		mThread.join();
	}
}

bool LegacyClient::sendPush(const std::shared_ptr<Request> &req) {
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
		SLOGW << "PushNotificationClient " << mName << " PNR " << req.get() << " queue full, push lost";
		onError(*req, "Error queue full");
		req->setState(Request::State::Failed);
		return false;
	} else {
		req->setState(Request::State::InProgress);
		mRequestQueue.push(req);
		/*client is running, it will pop the queue as soon he is finished with current request*/
		SLOGD << "PushNotificationClient " << mName << " PNR " << req.get() << " running, queue_size=" << size;

		if (mThreadWaiting) mCondVar.notify_one();
		mMutex.unlock();
		return true;
	}
}

void LegacyClient::run() {
	std::unique_lock<std::mutex> lock(mMutex);
	while (mThreadRunning) {
		if (!mRequestQueue.empty()) {
			size_t size =  mRequestQueue.size();
			SLOGD << "PushNotificationClient " << mName << " next, queue_size=" <<  size;
			auto req = mRequestQueue.front();
			mRequestQueue.pop();
			lock.unlock();

			// send push to the server and wait for its answer
			auto _onSuccess = [this](Request &req) {this->onSuccess(req);};
			auto _onError = [this](Request &req, const std::string &msg) {this->onError(req, msg);};
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

void LegacyClient::onError(Request &req, const string &msg) {
	SLOGW << "PushNotificationClient " << mName << " PNR " << &req << " failed: " << msg;
	req.setState(Request::State::Failed);
	auto countFailed = mService.getFailedCounter();
	if (countFailed) countFailed->incr();
}

void LegacyClient::onSuccess(Request &req) {
	req.setState(Request::State::Successful);
	auto countSent = mService.getSentCounter();
	if (countSent) countSent->incr();
}

} // end of pushnotification namespace
} // end of flexisip namespace
