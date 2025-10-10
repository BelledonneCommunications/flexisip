/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <thread>

#include "bctoolbox/tester.h"

#include "flexisip/logmanager.hh"
#include "tester.hh"
#include "tls-tcp-server.hh"

using namespace std;
using namespace boost::asio;
using namespace flexisip::tester;
using ip::tcp;
using ssl::context;

namespace {
class TcpConnection : public IConnection<tcp::socket> {
public:
	TcpConnection(io_service& ioService) : mSocket{make_unique<tcp::socket>(ioService)} {
	}

	void accept(tcp::acceptor& acceptor) override {
		acceptor.accept(*mSocket);
	}

	void resetSocket(io_service& ioService) override {
		mSocket = make_unique<tcp::socket>(ioService);
	}

	tcp::socket& getSocket() override {
		return *mSocket;
	}

private:
	std::unique_ptr<tcp::socket> mSocket;
};

class TlsConnection : public IConnection<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> {
public:
	TlsConnection(io_service& ioService, std::string_view sniValueExpected)
	    : mSniValueExpected{sniValueExpected},
#if BOOST_VERSION > 105300
	      mContext{ssl::context::tls_server}
#else
	      mContext{ssl::context::tlsv1_server}
#endif
	{
		mContext.set_options(ssl::context::default_workarounds | ssl::context::verify_none | ssl::context::no_sslv2 |
		                     ssl::context::no_sslv3);
		mContext.use_certificate_chain_file(bcTesterRes("cert/self.signed.cert.test.pem"));
		mContext.use_private_key_file(bcTesterRes("cert/self.signed.key.test.pem"), context::pem);
		mSocket = make_unique<ssl::stream<ip::tcp::socket>>(ioService, mContext);
	}

	void accept(tcp::acceptor& acceptor) override {
		acceptor.accept(mSocket->lowest_layer());
		LOGD("TlsConnection[%p] new connection accepted, starting handshake", this);
		mSocket->handshake(ssl::stream_base::server);
		LOGD("TlsConnection[%p] handshake ok", this);

		const auto SSL = mSocket->native_handle();
		const auto sniType = SSL_get_servername_type(SSL);

		if (mSniValueExpected.empty()) {
			if (sniType != -1) BC_FAIL("SNI found after SSL hanshake.");
			return;
		}

		if (sniType == -1) {
			BC_FAIL("No SNI found after SSL hanshake.");
			return;
		}

		const auto sniValue = SSL_get_servername(SSL, sniType);
		BC_ASSERT_STRING_EQUAL(sniValue, mSniValueExpected.c_str());
	}

	void resetSocket(io_service& ioService) override {
		mSocket = make_unique<ssl::stream<tcp::socket>>(ioService, mContext);
	}

	ssl::stream<boost::asio::ip::tcp::socket>& getSocket() override {
		return *mSocket;
	}

private:
	const std::string mSniValueExpected;
	ssl::context mContext;
	std::unique_ptr<ssl::stream<tcp::socket>> mSocket;
};

template <typename SocketType>
string serverName() {
	return {};
}
template <>
string serverName<tcp::socket>() {
	return "TcpServer";
}
template <>
string serverName<ssl::stream<tcp::socket>>() {
	return "TlsServer";
}

template <typename SocketType>
auto setConnection(io_service&, std::string_view) {
	return nullptr;
}
template <>
auto setConnection<tcp::socket>(io_service& ioService, std::string_view) {
	return make_unique<TcpConnection>(ioService);
}
template <>
auto setConnection<ssl::stream<tcp::socket>>(io_service& ioService, std::string_view sniValueExpected) {
	return make_unique<TlsConnection>(ioService, sniValueExpected);
}
} // namespace

template <typename SocketType>
TServer<SocketType>::TServer(int port, std::string_view sniValueExpected)
    : mLogPrefix{serverName<SocketType>()}, mIoService{}, mAcceptor{mIoService, tcp::endpoint(tcp::v4(), port)},
      mConnection{setConnection<SocketType>(mIoService, sniValueExpected)} {
}

template <typename SocketType>
void TServer<SocketType>::accept() {
	LOGD("%s[%p] entering accept", mLogPrefix.c_str(), this);
	mConnection->accept(mAcceptor);
	LOGD("%s[%p] accept ok", mLogPrefix.c_str(), this);
}

template <typename SocketType>
std::string TServer<SocketType>::read() {
	LOGD("%s[%p] entering read", mLogPrefix.c_str(), this);
	boost::asio::streambuf b;
	read_until(mConnection->getSocket(), b, "\n");
	std::istream is(&b);
	ostringstream line;
	line << is.rdbuf();
	LOGD("%s[%p] read: %s", mLogPrefix.c_str(), this, line.str().c_str());
	return line.str();
}

template <typename SocketType>
void TServer<SocketType>::send(const std::string& message) {
	LOGD("%s[%p] entering send", mLogPrefix.c_str(), this);
	const string msg = message + "\n";
	boost::asio::write(mConnection->getSocket(), buffer(message));
	LOGD("%s[%p] send: %s", mLogPrefix.c_str(), this, message.c_str());
}

template <typename SocketType>
int TServer<SocketType>::getPort() const {
	return mAcceptor.local_endpoint().port();
}

template <typename SocketType>
bool TServer<SocketType>::runServerForTest(const std::string& expectedRequest,
                                           const std::string& response,
                                           const std::chrono::milliseconds responseDelay) {
	try {
		accept();
		auto request = read();
		this_thread::sleep_for(responseDelay);
		send(response);
		return request == expectedRequest;
	} catch (const std::exception& e) {
		LOGW("TServer[%p] exception %s\n", this, e.what());
		return false;
	}
}

template <typename SocketType>
void TServer<SocketType>::resetSocket() {
	LOGD("%s[%p] entering %s", mLogPrefix.c_str(), this, __func__);
	mConnection->resetSocket(mIoService);
}

template class TServer<boost::asio::ip::tcp::socket>;
template class TServer<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>;