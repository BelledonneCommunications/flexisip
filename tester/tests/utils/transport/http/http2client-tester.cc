/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "bctoolbox/tester.h"
#include "utils/http-mock/http-mock.hh"

#include <atomic>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

#include <sys/types.h>

#include <nghttp2/nghttp2.h>

#include "flexisip/sofia-wrapper/su-root.hh"

#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/transport/http/http-headers.hh"
#include "utils/transport/http/http2client.hh"

using namespace std::string_literals;
using namespace std::chrono_literals;

namespace flexisip::tester {

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
		client = Http2Client::make(root, "localhost", port);
		client->setRequestTimeout(1s);
		headers = {
		    {":method"s, "POST"s},
		    {":scheme", "https"},
		    {":authority", "localhost:" + port},
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
		oversized = *maybeWindowSize;
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
	    [&root](const std::shared_ptr<Http2Client::HttpRequest>&, const std::shared_ptr<HttpResponse>&) {
		    BC_FAIL("This request will never be answered");
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

namespace {
TestSuite _("Http2Client",
            {
                CLASSY_TEST(partiallySentRequestCanceledByTimeout),
                CLASSY_TEST(partiallySentRequestResumedAtWindowUpdate),
            });
}
} // namespace flexisip::tester
