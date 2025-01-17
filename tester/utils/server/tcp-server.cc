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

#include <flexisip/logmanager.hh>

#include "tcp-server.hh"

using namespace std;
using namespace boost::asio;
using ip::tcp;
using ssl::context;

TcpServer::TcpServer(int port)
    : mIoService{}, mAcceptor{mIoService, tcp::endpoint(tcp::v4(), port)}, mSocket{mIoService} {
}

void TcpServer::accept() {
	SLOGD << "TcpServer[" << this << "] entering accept";
	mAcceptor.accept(mSocket);
	SLOGD << "TcpServer[" << this << "] accept ok";
}

std::string TcpServer::read() {
	SLOGD << "TcpServer[" << this << "] entering read";
	boost::asio::streambuf b;
	read_until(mSocket, b, "\n");
	std::istream is(&b);
	ostringstream line;
	line << is.rdbuf();
	SLOGD << "TcpServer[" << this << "] read : " << line.str();
	return line.str();
}

void TcpServer::send(const std::string& message) {
	SLOGD << "TcpServer[" << this << "] entering send";
	const string msg = message + "\n";
	boost::asio::write(mSocket, boost::asio::buffer(message));
	SLOGD << "TcpServer[" << this << "] send : " << message;
}

bool TcpServer::runServerForTest(const std::string& expectedRequest,
                                 const std::string& response,
                                 const std::chrono::milliseconds responseDelay) {
	accept();
	auto request = read();
	this_thread::sleep_for(responseDelay);
	send(response);
	return request == expectedRequest;
}