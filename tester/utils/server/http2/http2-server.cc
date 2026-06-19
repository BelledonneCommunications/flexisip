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

#include "server/http2/http2-server.hh"

#include <mutex>
#include <optional>
#include <set>
#include <thread>
#include <utility>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/socket_base.hpp>
#include <openssl/ssl.h>

#include "flexisip/logmanager.hh"
#include "server/http2/http2-server-internal.hh"
#include "server/http2/http2-session.hh"

using namespace std;
namespace asio = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

namespace flexisip::tester::http_mock::server {
namespace detail {

namespace {

int selectAlpnCallback(
    SSL*, const unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned int inlen, void*) {
	static constexpr unsigned char h2[] = {2, 'h', '2'};
	if (SSL_select_next_proto(const_cast<unsigned char**>(out), outlen, h2, sizeof(h2), in, inlen) ==
	    OPENSSL_NPN_NEGOTIATED) {
		return SSL_TLSEXT_ERR_OK;
	}
	return SSL_TLSEXT_ERR_NOACK;
}

} // namespace

void RequestState::registerNewCallback(Request::DataCb cb) {
	optional<string> completedBody{};
	unique_lock<mutex> lock(mCallbacksMutex);
	if (mBodyComplete) completedBody = mBody;
	mDataCallbacks.emplace_back(std::move(cb));
	const auto callback = mDataCallbacks.back();
	lock.unlock();
	if (completedBody.has_value()) {
		callback(reinterpret_cast<const uint8_t*>(completedBody->data()), completedBody->size());
	}
}

void RequestState::appendData(const uint8_t* data, size_t length) {
	if (length == 0) return;
	lock_guard<mutex> lock(mCallbacksMutex);
	mBody.append(reinterpret_cast<const char*>(data), length);
}

void RequestState::onRequestBodyReceiptFinished() {
	vector<Request::DataCb> callbacksCopy;
	string bodyCopy{};
	{
		lock_guard<mutex> lock(mCallbacksMutex);
		if (mBodyComplete) return;
		mBodyComplete = true;
		callbacksCopy = mDataCallbacks;
		bodyCopy = mBody;
	}
	for (const auto& callback : callbacksCopy) {
		callback(reinterpret_cast<const uint8_t*>(bodyCopy.data()), bodyCopy.size());
	}
}

const string& RequestState::getMethod() const {
	return mMethod;
}

const HeaderMap& RequestState::getHeaders() const {
	return mHeaders;
}

const UriRef& RequestState::getUri() const {
	return mUri;
}

void RequestState::setMethod(string method) {
	mMethod = std::move(method);
}

void RequestState::setUri(UriRef uri) {
	mUri = std::move(uri);
}

void RequestState::addHeader(string name, HeaderValue value) {
	mHeaders.emplace(std::move(name), std::move(value));
}

void ResponseState::setSession(weak_ptr<Http2Session> session) {
	lock_guard<mutex> lock(mStateMutex);
	mSession = std::move(session);
}

void ResponseState::setStreamId(int32_t streamId) {
	lock_guard<mutex> lock(mStateMutex);
	mStreamId = streamId;
}

StreamState::StreamState()
    : mRequestState(make_shared<RequestState>()), mResponseState(make_shared<ResponseState>()),
      mRequestHandle(mRequestState), mResponseHandle(mResponseState) {}

void ResponseState::writeHead(unsigned int code) {
	lock_guard<mutex> lock(mStateMutex);
	mStatusCode = code;
}

void ResponseState::sendResponse(optional<string> responseBody) {
	shared_ptr<Http2Session> lockedSession{};
	{
		lock_guard<mutex> lock(mStateMutex);
		if (mEnded) return;
		if (responseBody.has_value()) mBody = std::move(*responseBody);
		mBodyOffset = 0;
		mEnded = true;
		lockedSession = mSession.lock();
	}
	if (lockedSession) {
		lockedSession->submitResponse(shared_from_this());
	}
}

Http2ServerImpl::Http2ServerImpl()
    : mIoContext(make_shared<asio::io_context>()), mWorkGuard(asio::make_work_guard(*mIoContext)),
      mAcceptor(*mIoContext) {}

Http2ServerImpl::~Http2ServerImpl() {
	stop();
	join();
}

void Http2ServerImpl::handle(const string& pattern, RequestCb cb) {
	lock_guard<mutex> lock(mMutex);
	mHandlers[pattern] = std::move(cb);
}

int Http2ServerImpl::listenAndServe(boost::system::error_code& ec,
                                    ssl::context& ctx,
                                    const string& address,
                                    const string& port) {
	lock_guard<mutex> lock(mMutex);
	if (mStarted) {
		ec = make_error_code(boost::system::errc::operation_not_permitted);
		return -1;
	}

	SSL_CTX_set_alpn_select_cb(ctx.native_handle(), selectAlpnCallback, nullptr);
	const auto bindAddress = boost::asio::ip::make_address(address, ec);
	if (ec) return -1;

	auto endpoint = tcp::endpoint(bindAddress, static_cast<unsigned short>(stoi(port)));
	mAcceptor.open(endpoint.protocol(), ec);
	if (ec) return -1;
	mAcceptor.set_option(tcp::acceptor::reuse_address(true), ec);
	if (ec) return -1;
	mAcceptor.bind(endpoint, ec);
	if (ec) return -1;
	mAcceptor.listen(asio::socket_base::max_listen_connections, ec);
	if (ec) return -1;

	mPorts = {mAcceptor.local_endpoint(ec).port()};
	if (ec) return -1;

	mStarted = true;
	doAccept(ctx);
	mThread = thread([ioContext = mIoContext]() { ioContext->run(); });
	return 0;
}

vector<uint16_t> Http2ServerImpl::getPorts() const {
	lock_guard<mutex> lock(mMutex);
	return mPorts;
}

optional<RequestCb> Http2ServerImpl::findHandler(const string& path) const {
	lock_guard<mutex> lock(mMutex);
	size_t bestMatchLength = 0;
	optional<RequestCb> selected;
	for (const auto& [pattern, cb] : mHandlers) {
		if (path.rfind(pattern, 0) != 0) continue;
		if (pattern.size() < bestMatchLength) continue;
		bestMatchLength = pattern.size();
		selected = cb;
	}
	return selected;
}

void Http2ServerImpl::stop() {
	{
		lock_guard<mutex> lock(mMutex);
		if (mStopping.exchange(true)) return;
	}

	asio::post(*mIoContext, [this]() {
		boost::system::error_code ec;
		mAcceptor.cancel(ec);
		mAcceptor.close(ec);
	});

	vector<shared_ptr<Http2Session>> sessions;
	{
		lock_guard<mutex> lock(mMutex);
		sessions.assign(mSessions.begin(), mSessions.end());
	}
	for (const auto& session : sessions) {
		session->stop();
	}
	mWorkGuard.reset();
	mIoContext->stop();
}

void Http2ServerImpl::join() {
	std::unique_lock joinLock(mJoinMutex);

	if (mThread.joinable()) {
		mThread.join();
	}

	vector<shared_ptr<Http2Session>> sessions;
	{
		lock_guard<mutex> lock(mMutex);
		sessions.assign(mSessions.begin(), mSessions.end());
	}
	for (const auto& session : sessions) {
		session->join();
	}
	lock_guard<mutex> lock(mMutex);
	mSessions.clear();
}

void Http2ServerImpl::registerSession(const shared_ptr<Http2Session>& session) {
	lock_guard<mutex> lock(mMutex);
	mSessions.emplace(session);
}

void Http2ServerImpl::doAccept(ssl::context& ctx) {
	mAcceptor.async_accept([this, &ctx](boost::system::error_code ec, tcp::socket socket) mutable {
		if (!ec) {
			auto session = make_shared<Http2Session>(std::move(socket), ctx, shared_from_this());
			registerSession(session);
			session->start();
		} else if (ec != asio::error::operation_aborted) {
			LOGE_CTX(mLogPrefix, "doAccept") << "HTTP/2 mock accept failed: " << ec.message();
		}

		if (!mStopping) {
			doAccept(ctx);
		}
	});
}

} // namespace detail

UriRef::UriRef(string path) : mPath(std::move(path)) {}

const string& UriRef::getPath() const {
	return mPath;
}

Request::Request(shared_ptr<detail::RequestState> state) : mState(std::move(state)) {}

const string& Request::getMethod() const {
	static const string empty{};
	return mState ? mState->getMethod() : empty;
}

const HeaderMap& Request::getHeaders() const {
	static const HeaderMap empty{};
	return mState ? mState->getHeaders() : empty;
}

const UriRef& Request::getUri() const {
	static const UriRef empty{};
	return mState ? mState->getUri() : empty;
}

void Request::onData(DataCb cb) const {
	if (!mState) return;
	mState->registerNewCallback(std::move(cb));
}

Response::Response(shared_ptr<detail::ResponseState> state) : mState(std::move(state)) {}

void Response::writeHead(unsigned int statusCode, [[maybe_unused]] HeaderMap headers) const {
	if (!mState) return;
	mState->writeHead(statusCode);
}

void Response::send(string body) const {
	if (!mState) return;
	mState->sendResponse(std::move(body));
}

Http2::Http2() : mImpl(make_shared<detail::Http2ServerImpl>()) {}

Http2::~Http2() = default;

void Http2::handle(const string& pattern, RequestCb cb) {
	mImpl->handle(pattern, std::move(cb));
}

int Http2::listenAndServe(boost::system::error_code& ec, ssl::context& ctx, const string& address, const string& port) {
	return mImpl->listenAndServe(ec, ctx, address, port);
}

void Http2::stop() {
	mImpl->stop();
}

void Http2::join() {
	mImpl->join();
}

vector<uint16_t> Http2::getPorts() const {
	return mImpl->getPorts();
}

} // namespace flexisip::tester::http_mock::server

namespace flexisip::tester::http_mock {

HeaderValue::HeaderValue(string value, bool sensitive) : mValue(std::move(value)), mSensitive(sensitive) {}

const string& HeaderValue::getValue() const {
	return mValue;
}

bool HeaderValue::getSensitive() const {
	return mSensitive;
}

} // namespace flexisip::tester::http_mock
