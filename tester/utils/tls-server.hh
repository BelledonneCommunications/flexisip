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

#pragma once

#include <iostream>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

class TlsServer {
public:
	/**
	 * If port = 0 a random one is chosen. You can then use TlsServer::getPort().
	 */
	TlsServer(int port = 0);

	bool runServerForTest(const std::string& expectedRequest,
	                      const std::string& response,
	                      const std::chrono::milliseconds responseDelay = std::chrono::milliseconds{0});

	void accept();
	void accept(std::string sniValueExpected);
	std::string read();
	void send(const std::string& message);

	int getPort() {
		return mAcceptor.local_endpoint().port();
	}

private:
	boost::asio::io_service mIoService;
	boost::asio::ip::tcp::acceptor mAcceptor;
	boost::asio::ssl::context mContext;
	std::unique_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> mSocket{nullptr};
};
