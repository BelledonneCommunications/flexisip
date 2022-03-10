/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022  Belledonne Communications SARL, All rights reserved.

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

#include <thread>

#include "flexisip/logmanager.hh"

#include "flexisip-tester-config.hh"

#include "tls-server.hh"

using namespace std;
using namespace boost::asio;
using ip::tcp;
using ssl::context;

TlsServer::TlsServer(int port)
    : mIoService{}, mAcceptor{mIoService, tcp::endpoint(tcp::v4(), port)}, mContext{ssl::context::tls_server} {
	mContext.set_options(ssl::context::default_workarounds | ssl::context::verify_none | ssl::context::no_sslv2 |
	                     ssl::context::no_sslv3);
	mContext.use_certificate_chain_file(TESTER_DATA_DIR + string("/cert/self.signed.cert.test.pem"));
	mContext.use_private_key_file(TESTER_DATA_DIR + string("/cert/self.signed.key.test.pem"),
	                              boost::asio::ssl::context::pem);
	mSocket = make_unique<ssl::stream<ip::tcp::socket>>(mIoService, mContext);
}

void TlsServer::accept() {
	LOGD("TlsServer[%p] entering accept", this);
	mAcceptor.accept(mSocket->lowest_layer());
	LOGD("TlsServer[%p] new connection accepted, starting handshake", this);
	mSocket->handshake(boost::asio::ssl::stream_base::server);
	LOGD("TlsServer[%p] handshake ok", this);
}

std::string TlsServer::read() {
	LOGD("TlsServer[%p] entering read", this);
	string data;
	size_t n = read_until(*mSocket, dynamic_buffer(data), "\n");
	string line = data.substr(0, n);
	data.erase(0, n);
	LOGD("TlsServer[%p] read : %s", this, line.c_str());
	return line;
}

void TlsServer::send(const std::string& message) {
	LOGD("TlsServer[%p] entering send", this);
	const string msg = message + "\n";
	boost::asio::write(*mSocket, buffer(message));
	LOGD("TlsServer[%p] send : %s", this, message.c_str());
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
