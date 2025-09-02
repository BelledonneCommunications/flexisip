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
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <thread>

#include "bctoolbox/tester.h"

#include "flexisip/logmanager.hh"
#include "tester.hh"
#include "tls-server.hh"

using namespace std;
using namespace boost::asio;
using namespace flexisip::tester;
using ip::tcp;
using ssl::context;

TlsServer::TlsServer(int port)
    : mIoContext{}, mAcceptor{mIoContext, tcp::endpoint(tcp::v4(), port)},
#if BOOST_VERSION > 105300
      mContext{ssl::context::tls_server}
#else
      mContext{ssl::context::tlsv1_server}
#endif
{
	mContext.set_options(ssl::context::default_workarounds | ssl::context::verify_none | ssl::context::no_sslv2 |
	                     ssl::context::no_sslv3);
	mContext.use_certificate_chain_file(bcTesterRes("cert/self.signed.cert.test.pem"));
	mContext.use_private_key_file(bcTesterRes("cert/self.signed.key.test.pem"), boost::asio::ssl::context::pem);
	mSocket = make_unique<ssl::stream<ip::tcp::socket>>(mIoContext, mContext);
}

void TlsServer::accept() {
	SLOGD << "TlsServer[" << this << "] entering accept";
	mAcceptor.accept(mSocket->lowest_layer());
	SLOGD << "TlsServer[" << this << "] new connection accepted, starting handshake";
	mSocket->handshake(boost::asio::ssl::stream_base::server);
	SLOGD << "TlsServer[" << this << "] handshake ok";
}

void TlsServer::accept(const std::string& sniValueExpected) {
	accept();

	const auto SSL = mSocket->native_handle();
	const auto sniType = SSL_get_servername_type(SSL);

	if (sniType == -1 && !sniValueExpected.empty()) {
		BC_FAIL("No SNI found after SSL hanshake.");
		return;
	}
	if (sniType != -1 && sniValueExpected.empty()) {
		BC_FAIL("SNI found after SSL hanshake.");
		return;
	}
	if (sniType == -1 && sniValueExpected.empty()) {
		return;
	}

	const auto sniValue = SSL_get_servername(SSL, sniType);
	BC_ASSERT_STRING_EQUAL(sniValue, sniValueExpected.c_str());
}

std::string TlsServer::read() {
	SLOGD << "TlsServer[" << this << "] entering read";
	boost::asio::streambuf b;
	read_until(*mSocket, b, "\n");
	std::istream is(&b);
	ostringstream line;
	line << is.rdbuf();
	SLOGD << "TlsServer[" << this << "] read: " << line.str();
	return line.str();
}

void TlsServer::send(const std::string& message) {
	SLOGD << "TlsServer[" << this << "] entering send";
	const string msg = message + "\n";
	boost::asio::write(*mSocket, buffer(message));
	SLOGD << "TlsServer[" << this << "] send: " << message;
}

int TlsServer::getPort() const {
	return mAcceptor.local_endpoint().port();
}

bool TlsServer::runServerForTest(const std::string& expectedRequest,
                                 const std::string& response,
                                 const std::chrono::milliseconds responseDelay) {
	accept();
	auto request = read();
	this_thread::sleep_for(responseDelay);
	send(response);
	return request == expectedRequest;
}

void TlsServer::resetSocket() {
	mSocket = std::make_unique<ssl::stream<ip::tcp::socket>>(mIoContext, mContext);
}