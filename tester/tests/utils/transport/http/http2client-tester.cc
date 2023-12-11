/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "bctoolbox/tester.h"
#include "utils/http-mock/http-mock.hh"

#include <atomic>
#include <chrono>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
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

namespace {
TestSuite _("Http2Client",
            {
                CLASSY_TEST(partiallySentRequestCanceledByTimeout),
                CLASSY_TEST(partiallySentRequestResumedAtWindowUpdate),
            });
}
} // namespace flexisip::tester
