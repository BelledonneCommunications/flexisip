/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "http-mock.hh"

#include <functional>
#include <regex>
#include <string>
#include <thread>

#include "bc-utils.hh"
#include "flexisip/logmanager.hh"

using namespace std;
using namespace boost::asio::ssl;

namespace flexisip::tester::http_mock {

HttpMock::HttpMock(const std::map<std::string, HttpMockHandler>& handlers) : mCtx(ssl::context::tls) {
	mCtx.use_private_key_file(bcTesterRes("cert/self.signed.key.test.pem"), context::pem);
	mCtx.use_certificate_chain_file(bcTesterRes("cert/self.signed.cert.test.pem"));

	for (const auto& kv : handlers) {
		mServer.handle(kv.first, [this, &kv](const server::Request& req, const server::Response& res) {
			kv.second(*this, req, res);
		});
	}
}

HttpMock::HttpMock(const std::initializer_list<std::string> endpoints, std::atomic_int* requestReceivedCount)
    : mCtx(ssl::context::tls), mRequestReceivedCount(requestReceivedCount) {
	mCtx.use_private_key_file(bcTesterRes("cert/self.signed.key.test.pem"), context::pem);
	mCtx.use_certificate_chain_file(bcTesterRes("cert/self.signed.cert.test.pem"));

	for (const auto& handle : endpoints) {
		mServer.handle(handle, [this, handle](const server::Request& req, const server::Response& res) {
			handleRequest(req, res, handle);
		});
		mGETResponse[handle] = kDefaultResponse;
	}
}

std::lock_guard<std::recursive_mutex> HttpMock::pauseProcessing() {
	return lock_guard<recursive_mutex>(mMutex);
}

void HttpMock::handleRequest(const server::Request& req, const server::Response& res, const string& endpoint) {
	LOGD_CTX(mLogPrefix) << "handleRequest()";
	lock_guard<recursive_mutex> lock(mMutex);
	auto requestReceived = make_shared<Request>();
	req.onData([this, requestReceived](const uint8_t* data, std::size_t len) {
		lock_guard<recursive_mutex> lock(mMutex);
		if (len > 0) {
			string body{reinterpret_cast<const char*>(data), len};
			requestReceived->body += body;
			if (mRequestReceivedCount) {
				(*mRequestReceivedCount)++;
			}
		}
	});
	requestReceived->method = req.getMethod();
	requestReceived->headers = req.getHeaders();
	if (requestReceived->headers.count("content-length") == 1 &&
	    requestReceived->headers.find("content-length")->second.getValue() == "0") {
		if (mRequestReceivedCount) {
			(*mRequestReceivedCount)++;
		}
	}
	requestReceived->path = req.getUri().getPath();
	requestReceived->authority = req.getAuthority();
	mRequestsReceived.push(requestReceived);

	res.writeHead(200);
	if (req.getMethod() == "GET" && mGETResponse.find(endpoint) != mGETResponse.cend()) {
		res.send(mGETResponse[endpoint]);
		return;
	}
	res.send(kDefaultResponse);
}

int HttpMock::serveAsync(const std::string& port) {
	boost::system::error_code ec{};

	if (mServer.listenAndServe(ec, mCtx, "127.0.0.1", port)) {
		LOGE_CTX(mLogPrefix) << "error: " << ec.message();
		return -1;
	}
	return !mServer.getPorts().empty() ? mServer.getPorts().front() : -1;
}

void HttpMock::forceCloseServer() {
	mServer.stop();
}

std::shared_ptr<Request> HttpMock::popRequestReceived() {
	lock_guard<recursive_mutex> lock(mMutex);
	shared_ptr<Request> ret{nullptr};
	if (!mRequestsReceived.empty()) {
		ret = mRequestsReceived.front();
		mRequestsReceived.pop();
	}

	return ret;
}

bool HttpMock::addResponseToGET(const std::string& endpoint, const std::string& response) {
	if (mGETResponse.find(endpoint) == mGETResponse.cend()) return false;
	mGETResponse[endpoint] = response;
	return true;
}

int HttpMock::getFirstPort() const {
	const auto ports = mServer.getPorts();
	return ports.empty() ? -1 : ports.front();
}

} // namespace flexisip::tester::http_mock
