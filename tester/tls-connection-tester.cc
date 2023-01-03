/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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
#include <type_traits>

#include "utils/tcp-server.hh"
#include "utils/tls-server.hh"
#include "utils/transport/tls-connection.hh"

#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono;

namespace flexisip {
namespace tester {

template <typename ServerT, typename HostStr, typename PortStr>
static std::unique_ptr<TlsConnection> makeClientFor(HostStr&& host, PortStr&& port) {
	constexpr auto needTls = is_same<typename decay<ServerT>::type, TlsServer>::value;
	if (needTls) {
		return make_unique<TlsConnection>(std::forward<HostStr>(host), std::forward<PortStr>(port), false);
	} else {
		// Using an empty certPath cause TlsConnection to behave as a raw TCP connection.
		return make_unique<TlsConnection>(std::forward<HostStr>(host), std::forward<PortStr>(port), "", "", false);
	}
}

template <typename ServerT> static void readTest() {
	string expectedRead{"To read !"};
	constexpr auto host = "127.0.0.1";
	constexpr auto port = 1234;

	ServerT server{port};
	auto serverStatus = async(launch::async, [&server, &expectedRead]() {
		server.accept();
		server.send(expectedRead);
		return true;
	});

	auto tlsConnection = makeClientFor<ServerT>(host, to_string(port));
	tlsConnection->connect();

	char readBuffer[1024];
	this_thread::sleep_for(100ms);
	auto nbRead = tlsConnection->read(readBuffer, sizeof(readBuffer));

	string readStr{};
	readStr.insert(readStr.end(), readBuffer, readBuffer + nbRead);

	BC_ASSERT_STRING_EQUAL(readStr.c_str(), expectedRead.c_str());
	BC_ASSERT_TRUE(serverStatus.get());
}

struct ReadAllWithTimeoutParams {
	std::chrono::milliseconds responseDelay{0};
	std::chrono::milliseconds readAllTimeoutDelay{500ms};
	std::chrono::milliseconds minElapsedTime{0};
	std::chrono::milliseconds maxElapsedTime{500ms};
	bool noResponseExpected{false};
};

template <typename ServerT> static void readAllWithTimeoutBase(const ReadAllWithTimeoutParams& params) {
	string request{"Hello World!\n"};
	string expectedResponse{"aaa"};
	constexpr auto host = "127.0.0.1";
	ServerT server{};
	const auto port = server.getPort();

	auto requestMatch = async(launch::async, [&server, &request, &expectedResponse, &params]() {
		return server.runServerForTest(request, expectedResponse, params.responseDelay);
	});

	auto tlsConnection = makeClientFor<ServerT>(host, to_string(port));
	tlsConnection->connect();

	std::vector<char> vectorReq(request.begin(), request.end());
	tlsConnection->write(vectorReq);

	string responseStr{};
	auto start = steady_clock::now();
	tlsConnection->readAll(responseStr, params.readAllTimeoutDelay);
	auto end = steady_clock::now();
	auto elapsedTimeMs = (int)duration_cast<milliseconds>(end - start).count();

	auto minElapsedTimeMs = duration_cast<milliseconds>(params.minElapsedTime).count();
	auto maxElapsedTimeMs = duration_cast<milliseconds>(params.maxElapsedTime).count();
	if (!params.noResponseExpected) {
		BC_ASSERT_STRING_EQUAL(responseStr.c_str(), expectedResponse.c_str());
	} else {
		BC_ASSERT_STRING_EQUAL(responseStr.c_str(), "");
	}
	BC_ASSERT_GREATER(elapsedTimeMs, minElapsedTimeMs, int, "%i");
	BC_ASSERT_LOWER_STRICT(elapsedTimeMs, maxElapsedTimeMs, int, "%i");
	BC_ASSERT_TRUE(requestMatch.get());
};

template <typename ServerT> static void readAllWithTimeout() {
	ReadAllWithTimeoutParams params{};
	readAllWithTimeoutBase<ServerT>(params);
}

template <typename ServerT> static void readAllWithTimeoutDelayedResponse() {
	ReadAllWithTimeoutParams params{};
	params.responseDelay = 500ms;
	params.readAllTimeoutDelay = 5s;
	params.minElapsedTime = 500ms;
	params.maxElapsedTime = 750ms;
	readAllWithTimeoutBase<ServerT>(params);
}

template <typename ServerT> static void readAllWithTimeoutLateResponse() {
	ReadAllWithTimeoutParams params{};
	params.responseDelay = 1s;
	params.readAllTimeoutDelay = 500ms;

	// We did not wait for response
	params.minElapsedTime = 499ms;
	params.maxElapsedTime = 520ms;
	params.noResponseExpected = true;

	readAllWithTimeoutBase<ServerT>(params);
}

namespace {
TestSuite _("TlsConnection unit tests",
            {
                TEST_NO_TAG("TCP read", readTest<TcpServer>),
                TEST_NO_TAG("TCP readAll with timeout", readAllWithTimeout<TcpServer>),
                TEST_NO_TAG("TCP readAll with timeout, response from server is delayed.",
                            readAllWithTimeoutDelayedResponse<TcpServer>),
                TEST_NO_TAG("TCP readAll with timeout, response from server is late.",
                            readAllWithTimeoutLateResponse<TcpServer>),
                TEST_NO_TAG("TLS read", readTest<TlsServer>),
                TEST_NO_TAG("TLS readAll with timeout", readAllWithTimeout<TlsServer>),
                TEST_NO_TAG("TLS readAll with timeout, response from server is delayed.",
                            readAllWithTimeoutDelayedResponse<TlsServer>),
                TEST_NO_TAG("TLS readAll with timeout, response from server is late.",
                            readAllWithTimeoutLateResponse<TlsServer>),
            });
}
} // namespace tester
} // namespace flexisip
