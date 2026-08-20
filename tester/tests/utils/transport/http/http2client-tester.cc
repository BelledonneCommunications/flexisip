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

#include <sys/types.h>

#include <atomic>
#include <chrono>
#include <future>
#include <initializer_list>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "flexisip/sofia-wrapper/su-root.hh"
#include "utils/core-assert.hh"
#include "utils/http-mock/http-mock.hh"
#include "utils/server/tls-tcp-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/transport/http/http-headers.hh"
#include "utils/transport/http/http2client.hh"

using namespace std;
using namespace std::string_literals;
using namespace std::chrono_literals;

namespace flexisip::tester {
using namespace http_mock;

namespace {

struct Arrange {
	sofiasip::SuRoot root{};
	std::atomic_int requestsReceivedCount{0};
	HttpMock httpMock{{"/"}, &requestsReceivedCount};

	std::shared_ptr<Http2Client> client;
	HttpHeaders headers;
	int32_t oversized;

	Arrange() {
		const auto portInt = httpMock.serveAsync();
		BC_HARD_ASSERT_TRUE(portInt > -1);
		const auto port = std::to_string(portInt);
		client = Http2Client::make(root, "127.0.0.1", port);
		client->setRequestTimeout(1s);
		headers = {
		    {":method"s, "POST"s},
		    {":scheme", "https"},
		    {":authority", "127.0.0.1:" + port},
		    {":path", "/"},
		};
		client->send(
		    std::make_shared<Http2Client::HttpRequest>(headers, "Init session"),
		    [&root = root](const std::shared_ptr<Http2Client::HttpRequest>&, const std::shared_ptr<HttpResponse>&) {
			    root.quit();
		    },
		    [&root = root](const std::shared_ptr<Http2Client::HttpRequest>&) {
			    BC_FAIL("Unexpected error sending initial request to init session");
			    root.quit();
		    });
		root.run();
		const auto maybeWindowSize = client->getRemoteWindowSize();
		BC_HARD_ASSERT_TRUE(maybeWindowSize != std::nullopt);
		// Too big to be sent in one batch, but no bigger than necessary
		oversized = *maybeWindowSize + 1;
	}
};

} // namespace

// Send a request too big for the window size. Some frames will be kept in nghttp2's queue.
// Let it timeout, then trigger sending of the remaining frames.
// If not handled correctly, the payload will be freed on timeout and trigger a SEGV when trying to resume the remaining
// frames
void partiallySentRequestCanceledByTimeout() {
	Arrange setup{};
	auto& root = setup.root;

	setup.client->send(
	    std::make_shared<Http2Client::HttpRequest>(setup.headers, std::string(setup.oversized, 'A')),
	    [&root, before = std::chrono::system_clock::now(), size = setup.oversized](
	        const std::shared_ptr<Http2Client::HttpRequest>&, const std::shared_ptr<HttpResponse>&) {
		    std::stringstream msg{};
		    msg << "Request unexpectedly answered in "
		        << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - before)
		               .count()
		        << "ms with a size of " << std::to_string(size) << "bytes";
		    bc_assert(__FILE__, __LINE__, false, msg.str().c_str());
		    root.quit();
	    },
	    [&root](const std::shared_ptr<Http2Client::HttpRequest>&) { root.quit(); });
	{ // Let the request timeout
		const auto lock = setup.httpMock.pauseProcessing();
		root.run();
	}
	setup.client->send(
	    std::make_shared<Http2Client::HttpRequest>(setup.headers, "Trigger sending of remaining frames"),
	    [&root](const std::shared_ptr<Http2Client::HttpRequest>&, const std::shared_ptr<HttpResponse>&) {
		    root.quit();
	    },
	    [&root](const std::shared_ptr<Http2Client::HttpRequest>&) {
		    BC_FAIL("Unexpected error in resend trigger request");
		    root.quit();
	    });
	setup.root.run();
}

// Send a request too big for the window size and assert it succeeds given a few iterations of the main loop
void partiallySentRequestResumedAtWindowUpdate() {
	Arrange setup{};

	setup.client->send(
	    std::make_shared<Http2Client::HttpRequest>(setup.headers, std::string(setup.oversized, 'A')),
	    [&root = setup.root](const std::shared_ptr<Http2Client::HttpRequest>&, const std::shared_ptr<HttpResponse>&) {
		    root.quit();
	    },
	    [&root = setup.root](const std::shared_ptr<Http2Client::HttpRequest>&) {
		    BC_FAIL("Unexpected error sending oversized request");
		    root.quit();
	    });
	setup.root.run();
}

/**
 * Test that the Http2Client switches to the "disconnected" state if the "connection reset by peer" error occurs.
 * Then, it should try to reconnect before sending pending requests.
 */
void reconnectAfterConnectionResetByPeer() {
	TlsServer server{};
	const auto serverPort = to_string(server.getPort());

	sofiasip::SuRoot root{};
	CoreAssert asserter{root};

	auto client = Http2Client::make(root, "127.0.0.1", serverPort);
	client->setRequestTimeout(5s);
	client->enableInsecureTestMode();

	const auto func = [&server] {
		return server.runServerForTest("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "stub-response", 0ms);
	};

	const auto onError = [](const auto&) {};
	const auto onResponse = [](const auto&, const auto&) {};

	// The first request works as expected.
	{
		auto result = async(launch::async, func);
		client->send(make_shared<Http2Client::HttpRequest>(HttpHeaders{}, "stub-request"), onResponse, onError);
		asserter.iterateUpTo(0x20, [&client] { return LOOP_ASSERTION(client->isConnected()); }, 2s).assert_passed();
		if (result.wait_for(2s) != std::future_status::ready) {
			client.reset(); // force disconnection to stop server thread
		}
		BC_HARD_ASSERT(result.get());
	}

	// Simulate the "connection reset by peer" error.
	server.resetSocket();

	// The second request fails, and the connection is then closed by the client.
	// Test that the third request works as expected.
	{
		auto result = async(launch::async, func);
		client->send(make_shared<Http2Client::HttpRequest>(HttpHeaders{}, "stub-request"), onResponse, onError);

		asserter.iterateUpTo(0x20, [&client] { return LOOP_ASSERTION(!client->isConnected()); }, 2s).assert_passed();

		BC_HARD_ASSERT(result.wait_for(500ms) == std::future_status::timeout);

		client->send(make_shared<Http2Client::HttpRequest>(HttpHeaders{}, "stub-request"), onResponse, onError);
		asserter.iterateUpTo(0x20, [&client] { return LOOP_ASSERTION(client->isConnected()); }, 2s).assert_passed();
		if (result.wait_for(2s) != std::future_status::ready) {
			client.reset(); // force disconnection to stop server thread
		}
		BC_ASSERT(result.get());
	}
}

/**
 * Requests queued before a connection is established are sent once the connection is ready.
 */
void requestsQueuedBeforeConnectionSetupAreSentInOrder() {
	sofiasip::SuRoot root{};

	atomic_int responsesReceivedCount{0};
	const auto onResponse = [&responsesReceivedCount](const auto&, const auto&) { ++responsesReceivedCount; };
	atomic_int errorsCount{0};
	const auto onError = [&errorsCount](const auto&) { ++errorsCount; };

	HttpMock httpMock{{"/"}};
	const auto portInt = httpMock.serveAsync();
	BC_HARD_ASSERT_TRUE(portInt > -1);
	const auto port = to_string(portInt);

	auto client = Http2Client::make(root, "127.0.0.1", port);
	const HttpHeaders headers = {
	    {":method"s, "POST"s},
	    {":scheme", "https"},
	    {":authority", "127.0.0.1:" + port},
	    {":path", "/"},
	};
	const vector<string> requestBodies{"request_1", "request_2", "request_3"};

	for (const auto& body : requestBodies) {
		// Note: the client initiates the connection on the first send, so the first request is queued while the
		// connection is being established. Following requests are queued while the connection is being established, and
		// sent in order once the connection is ready.
		client->send(make_shared<Http2Client::HttpRequest>(headers, body), onResponse, onError);
	}

	CoreAssert asserter{root};
	asserter.wait([&responsesReceivedCount] { return LOOP_ASSERTION(responsesReceivedCount == 3); })
	    .hard_assert_passed();

	for (const auto& expectedBody : requestBodies) {
		const auto request = httpMock.popRequestReceived();
		BC_HARD_ASSERT_TRUE(request != nullptr);
		BC_ASSERT_STRING_EQUAL(request->body.c_str(), expectedBody.c_str());
	}

	BC_ASSERT(httpMock.popRequestReceived() == nullptr);
}

/**
 * A send failure during pending-request draining must preserve the remaining requests and their order.
 */
void pendingRequestsRemainOrderedAfterDrainFailure() {
	sofiasip::SuRoot root{};

	atomic_int responsesReceivedCount{0};
	const auto onResponse = [&responsesReceivedCount](const auto&, const auto&) { ++responsesReceivedCount; };
	vector<string> errorBodies{};
	const auto onError = [&errorBodies](const shared_ptr<Http2Client::HttpRequest>& request) {
		errorBodies.emplace_back(request->getBody().begin(), request->getBody().end());
	};

	auto firstServer = make_unique<TlsServer>();
	const auto serverPort = firstServer->getPort();

	auto client = Http2Client::make(root, "127.0.0.1", to_string(serverPort));
	client->setRequestTimeout(1s);
	client->enableInsecureTestMode();

	const HttpHeaders headers = {
	    {":method"s, "POST"s},
	    {":scheme", "https"},
	    {":authority", "127.0.0.1:" + to_string(serverPort)},
	    {":path", "/"},
	};
	vector<string> requestBodies{"request_1", "request_2", "request_3"};

	auto firstConnection = async(launch::async, [&firstServer] {
		firstServer->accept();
		// Simulate a connection drop after the first request is received.
		firstServer.reset();
	});

	// Try to send requests that will be queued while the connection is being established. The first request will fail,
	// and the connection will be closed, leaving the other requests pending.
	for (const auto& body : requestBodies) {
		client->send(make_shared<Http2Client::HttpRequest>(headers, body), onResponse, onError);
	}

	CoreAssert asserter{root};
	// Wait until the first request fails and the connection is closed, leaving the other requests pending.
	asserter.wait([&] { return LOOP_ASSERTION(errorBodies.size() == 1); }).hard_assert_passed();
	asserter.wait([&] { return LOOP_ASSERTION(!client->isConnected()); }).hard_assert_passed();
	BC_HARD_ASSERT(errorBodies.front() == requestBodies.front());
	requestBodies.erase(requestBodies.begin());

	// Reopen the server with the same port.
	auto secondServer = make_unique<HttpMock>(initializer_list<string>{"/"});
	BC_ASSERT(secondServer->serveAsync(to_string(serverPort)) == serverPort);

	// Send a new request to trigger reconnection and draining of the pending requests.
	requestBodies.emplace_back("request_4");
	client->send(make_shared<Http2Client::HttpRequest>(headers, requestBodies.back()), onResponse, onError);

	asserter
	    .wait([&] {
		    FAIL_IF(!client->isConnected());
		    FAIL_IF(errorBodies.size() != 1);
		    FAIL_IF(responsesReceivedCount != 3);
		    FAIL_IF(!client->isIdle());
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	// Assert that all the pending requests were sent in order after the first request failed.
	for (const auto& expectedBody : requestBodies) {
		const auto request = secondServer->popRequestReceived();
		BC_HARD_ASSERT_TRUE(request != nullptr);
		BC_ASSERT_STRING_EQUAL(request->body.c_str(), expectedBody.c_str());
	}

	BC_ASSERT(secondServer->popRequestReceived() == nullptr);
}

namespace {

TestSuite _{
    "Http2Client",
    {
        CLASSY_TEST(partiallySentRequestCanceledByTimeout),
        CLASSY_TEST(partiallySentRequestResumedAtWindowUpdate),
        CLASSY_TEST(reconnectAfterConnectionResetByPeer),
        CLASSY_TEST(requestsQueuedBeforeConnectionSetupAreSentInOrder),
        CLASSY_TEST(pendingRequestsRemainOrderedAfterDrainFailure),
    },
};

}
} // namespace flexisip::tester