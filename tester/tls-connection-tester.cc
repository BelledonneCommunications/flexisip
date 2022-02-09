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
#include <chrono>
#include <future>
#include <thread>

#include "utils/tcp-server.hh"
#include "utils/tls-server.hh"
#include "utils/transport/tls-connection.hh"

#include "tester.hh"

using namespace std;
using namespace std::chrono;
using namespace flexisip;

static void tcpRead() {
	string expectedRead{"To read !"};

	TcpServer tcpServer{1234};
	auto serverStatus = async(launch::async, [&tcpServer, &expectedRead]() {
		tcpServer.accept();
		tcpServer.send(expectedRead);
		return true;
	});

	TlsConnection tlsConnection{"127.0.0.1", "1234", "", "", false};
	tlsConnection.connect();

	char readBuffer[1024];
	this_thread::sleep_for(1s);
	auto nbRead = tlsConnection.read(readBuffer, sizeof(readBuffer));

	string readStr{};
	readStr.insert(readStr.end(), readBuffer, readBuffer + nbRead);

	BC_ASSERT_STRING_EQUAL(readStr.c_str(), expectedRead.c_str());
	BC_ASSERT_TRUE(serverStatus.get());
}

static void tcpReadAllWithTimeout() {
	string request{"Hello World!\n"};
	string expectedResponse{"aaa"};

	TcpServer tcpServer{1234};
	auto requestMatch = async(launch::async, [&tcpServer, &request, &expectedResponse]() {
		return tcpServer.runServerForTest(request, expectedResponse);
	});

	TlsConnection tlsConnection{"127.0.0.1", "1234", "", "", false};
	tlsConnection.connect();

	std::vector<char> vectorReq(request.begin(), request.end());
	tlsConnection.write(vectorReq);

	string responseStr{};
	auto start = steady_clock::now();
	tlsConnection.readAll(responseStr, 1000ms);
	auto end = steady_clock::now();
	auto elapsedTimeMs = (int) duration_cast<milliseconds>(end - start).count();

	BC_ASSERT_STRING_EQUAL(responseStr.c_str(), expectedResponse.c_str());
	BC_ASSERT_LOWER_STRICT(elapsedTimeMs, 1000, int, "%i");
	BC_ASSERT_TRUE(requestMatch.get());
}

static void tcpReadAllWithTimeoutDelayedResponse() {
	string request{"Hello World!\n"};
	string expectedResponse{"aaa"};

	TcpServer tcpServer{1234};
	auto requestMatch = async(launch::async, [&tcpServer, &request, &expectedResponse]() {
		return tcpServer.runServerForTest(request, expectedResponse, 2s);
	});

	TlsConnection tlsConnection{"127.0.0.1", "1234", "", "", false};
	tlsConnection.connect();

	std::vector<char> vectorReq(request.begin(), request.end());
	tlsConnection.write(vectorReq);

	string responseStr{};
	auto start = steady_clock::now();
	tlsConnection.readAll(responseStr, 5000ms);
	auto end = steady_clock::now();
	auto elapsedTimeMs = (int) duration_cast<milliseconds>(end - start).count();

	BC_ASSERT_STRING_EQUAL(responseStr.c_str(), expectedResponse.c_str());
	BC_ASSERT_GREATER(elapsedTimeMs, 2000, int, "%i");
	BC_ASSERT_LOWER_STRICT(elapsedTimeMs, 2500, int, "%i");
	BC_ASSERT_TRUE(requestMatch.get());
}

static void tcpReadAllWithTimeoutLateResponse() {
	string request{"Hello World!\n"};
	string expectedResponse{"aaa"};

	TcpServer tcpServer{1234};
	auto requestMatch = async(launch::async, [&tcpServer, &request, &expectedResponse]() {
		return tcpServer.runServerForTest(request, expectedResponse, 4s);
	});

	TlsConnection tlsConnection{"127.0.0.1", "1234", "", "", false};
	tlsConnection.connect();

	std::vector<char> vectorReq(request.begin(), request.end());
	tlsConnection.write(vectorReq);

	string responseStr{};
	auto start = steady_clock::now();
	tlsConnection.readAll(responseStr, 2000ms);
	auto end = steady_clock::now();
	auto elapsedTimeMs = (int) duration_cast<milliseconds>(end - start).count();

	// We did not wait for response
	BC_ASSERT_STRING_NOT_EQUAL(responseStr.c_str(), expectedResponse.c_str());
	BC_ASSERT_GREATER(elapsedTimeMs, 1999, int, "%i");
	BC_ASSERT_LOWER_STRICT(elapsedTimeMs, 2020, int, "%i");

	BC_ASSERT_TRUE(requestMatch.get());
}

static void tlsRead() {
	string expectedRead{"To read !"};

	TlsServer tlsServer{1234};
	auto serverStatus = async(launch::async, [&tlsServer, &expectedRead]() {
		tlsServer.accept();
		tlsServer.send(expectedRead);
		return 0;
	});

	TlsConnection tlsConnection{"127.0.0.1", "1234", false};
	tlsConnection.connect();

	char readBuffer[1024];
	this_thread::sleep_for(1s);
	auto nbRead = tlsConnection.read(readBuffer, sizeof(readBuffer));

	string readStr{};
	readStr.insert(readStr.end(), readBuffer, readBuffer + nbRead);

	BC_ASSERT_STRING_EQUAL(readStr.c_str(), expectedRead.c_str());
	BC_ASSERT_TRUE(serverStatus.get() == 0);
}

static void tlsReadAllWithTimeout() {
	string request{"Hello World!\n"};
	string expectedResponse{"aaa"};

	TlsServer tlsServer{1234};
	auto requestMatch = async(launch::async, [&tlsServer, &request, &expectedResponse]() {
		return tlsServer.runServerForTest(request, expectedResponse);
	});

	TlsConnection tlsConnection{"127.0.0.1", "1234", false};
	tlsConnection.connect();

	std::vector<char> vectorReq(request.begin(), request.end());
	tlsConnection.write(vectorReq);

	string responseStr{};
	auto start = steady_clock::now();
	tlsConnection.readAll(responseStr, 1000ms);
	auto end = steady_clock::now();
	auto elapsedTimeMs = (int) duration_cast<milliseconds>(end - start).count();

	BC_ASSERT_STRING_EQUAL(responseStr.c_str(), expectedResponse.c_str());
	BC_ASSERT_LOWER_STRICT(elapsedTimeMs, 1000, int, "%i");
	BC_ASSERT_TRUE(requestMatch.get());
}

static void tlsReadAllWithTimeoutDelayedResponse() {
	string request{"Hello World!\n"};
	string expectedResponse{"aaa"};

	TlsServer tlsServer{1234};
	auto requestMatch = async(launch::async, [&tlsServer, &request, &expectedResponse]() {
		return tlsServer.runServerForTest(request, expectedResponse, 2s);
	});

	TlsConnection tlsConnection{"127.0.0.1", "1234", false};
	tlsConnection.connect();

	std::vector<char> vectorReq(request.begin(), request.end());
	tlsConnection.write(vectorReq);

	string responseStr{};
	auto start = steady_clock::now();
	tlsConnection.readAll(responseStr, 5000ms);
	auto end = steady_clock::now();
	auto elapsedTimeMs = (int) duration_cast<milliseconds>(end - start).count();

	BC_ASSERT_STRING_EQUAL(responseStr.c_str(), expectedResponse.c_str());
	BC_ASSERT_GREATER(elapsedTimeMs, 2000, int, "%i");
	BC_ASSERT_LOWER_STRICT(elapsedTimeMs, 2500, int, "%i");
	BC_ASSERT_TRUE(requestMatch.get());
}

static void tlsReadAllWithTimeoutLateResponse() {
	string request{"Hello World!\n"};
	string expectedResponse{"aaa"};

	TlsServer tlsServer{1234};
	auto requestMatch = async(launch::async, [&tlsServer, &request, &expectedResponse]() {
		return tlsServer.runServerForTest(request, expectedResponse, 4s);
	});

	TlsConnection tlsConnection{"127.0.0.1", "1234", false};
	tlsConnection.connect();

	std::vector<char> vectorReq(request.begin(), request.end());
	tlsConnection.write(vectorReq);

	string responseStr{};
	auto start = steady_clock::now();
	tlsConnection.readAll(responseStr, 2000ms);
	auto end = steady_clock::now();
	auto elapsedTimeMs = (int) duration_cast<milliseconds>(end - start).count();

	// We did not wait for response
	BC_ASSERT_STRING_NOT_EQUAL(responseStr.c_str(), expectedResponse.c_str());
	BC_ASSERT_GREATER(elapsedTimeMs, 1999, int, "%i");
	BC_ASSERT_LOWER_STRICT(elapsedTimeMs, 2020, int, "%i");
	BC_ASSERT_TRUE(requestMatch.get());
}

static test_t tests[] = {
    TEST_NO_TAG("TCP read", tcpRead),
    TEST_NO_TAG("TCP readAll with timeout", tcpReadAllWithTimeout),
    TEST_NO_TAG("TCP readAll with timeout, response from server is delayed.", tcpReadAllWithTimeoutDelayedResponse),
    TEST_NO_TAG("TCP readAll with timeout, response from server is late.", tcpReadAllWithTimeoutLateResponse),
    TEST_NO_TAG("TLS read", tlsRead),
    TEST_NO_TAG("TLS readAll with timeout", tlsReadAllWithTimeout),
    TEST_NO_TAG("TLS readAll with timeout, response from server is delayed.", tlsReadAllWithTimeoutDelayedResponse),
    TEST_NO_TAG("TLS readAll with timeout, response from server is late.", tlsReadAllWithTimeoutLateResponse),
};

test_suite_t tls_connection_suite = {"TlsConnection unit tests", nullptr, nullptr, nullptr, nullptr,
                                     sizeof(tests) / sizeof(tests[0]), tests};
