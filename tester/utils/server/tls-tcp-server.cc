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
	TcpConnection(io_context& ioContext) : mSocket{make_unique<tcp::socket>(ioContext)} {
	}

	void accept(tcp::acceptor& acceptor) override {
		acceptor.accept(*mSocket);
	}

	void resetSocket(io_context& ioContext) override {
		mSocket = make_unique<tcp::socket>(ioContext);
	}

	tcp::socket& getSocket() override {
		return *mSocket;
	}

private:
	std::unique_ptr<tcp::socket> mSocket;
};

class TlsConnection : public IConnection<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> {
public:
	TlsConnection(io_context& ioContext, std::string_view sniValueExpected)
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
		mSocket = make_unique<ssl::stream<ip::tcp::socket>>(ioContext, mContext);
	}

	void accept(tcp::acceptor& acceptor) override {
		acceptor.accept(mSocket->lowest_layer());
		SLOGD << "TlsConnection[" << this << "] new connection accepted, starting handshake";
		mSocket->handshake(ssl::stream_base::server);
		SLOGD << "TlsConnection[" << this << "] handshake ok";

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

	void resetSocket(io_context& ioContext) override {
		mSocket = make_unique<ssl::stream<tcp::socket>>(ioContext, mContext);
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
auto setConnection(io_context&, std::string_view) {
	return nullptr;
}
template <>
auto setConnection<tcp::socket>(io_context& ioContext, std::string_view) {
	return make_unique<TcpConnection>(ioContext);
}
template <>
auto setConnection<ssl::stream<tcp::socket>>(io_context& ioContext, std::string_view sniValueExpected) {
	return make_unique<TlsConnection>(ioContext, sniValueExpected);
}
} // namespace

template <typename SocketType>
TServer<SocketType>::TServer(int port, std::string_view sniValueExpected)
    : mLogPrefix{serverName<SocketType>()}, mIoContext{}, mAcceptor{mIoContext, tcp::endpoint(tcp::v4(), port)},
      mConnection{setConnection<SocketType>(mIoContext, sniValueExpected)} {
}

template <typename SocketType>
void TServer<SocketType>::accept() {
	LOGD << "entering";
	mConnection->accept(mAcceptor);
	LOGD << "ok";
}

template <typename SocketType>
std::string TServer<SocketType>::read() {
	LOGD << "entering";
	boost::asio::streambuf b;
	read_until(mConnection->getSocket(), b, "\n");
	std::istream is(&b);
	ostringstream line;
	line << is.rdbuf();
	LOGD << "read: " << line.str();
	return line.str();
}

template <typename SocketType>
void TServer<SocketType>::send(const std::string& message) {
	LOGD << "entering";
	const string msg = message + "\n";
	boost::asio::write(mConnection->getSocket(), buffer(message));
	LOGD << "sent: " << message;
}

template <typename SocketType>
int TServer<SocketType>::getPort() const {
	return mAcceptor.local_endpoint().port();
}

template <typename SocketType>
bool TServer<SocketType>::runServerForTest(const std::string& expectedRequest,
                                           const std::string& response,
                                           const std::chrono::milliseconds responseDelay) {
	accept();
	auto request = read();
	this_thread::sleep_for(responseDelay);
	send(response);
	return request == expectedRequest;
}

template <typename SocketType>
void TServer<SocketType>::resetSocket() {
	LOGD << "entering";
	mConnection->resetSocket(mIoContext);
}

template class TServer<boost::asio::ip::tcp::socket>;
template class TServer<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>;