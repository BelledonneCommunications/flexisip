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

#pragma once

#include <chrono>
#include <string>
#include <string_view>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

template <typename SocketType>
class IConnection {
public:
	virtual ~IConnection() = default;
	virtual void accept(boost::asio::ip::tcp::acceptor& acceptor) = 0;
	virtual void resetSocket(boost::asio::io_context& ioContext) = 0;
	virtual SocketType& getSocket() = 0;
};

template <typename SocketType>
class TServer {
public:
	/**
	 * If port = 0 a random one is chosen. You can then use TServer::getPort().
	 */
	TServer(int port, std::string_view sniValueExpected);
	TServer(int port = 0) : TServer(port, ""){};

	bool runServerForTest(const std::string& expectedRequest,
	                      const std::string& response,
	                      const std::chrono::milliseconds responseDelay = std::chrono::milliseconds{0});

	void accept();
	std::string read();
	void send(const std::string& message);

	int getPort() const;
	void resetSocket();

private:
	std::string mLogPrefix;
	boost::asio::io_context mIoContext;
	boost::asio::ip::tcp::acceptor mAcceptor;
	std::unique_ptr<IConnection<SocketType>> mConnection;
};

using TcpServer = TServer<boost::asio::ip::tcp::socket>;
using TlsServer = TServer<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>;