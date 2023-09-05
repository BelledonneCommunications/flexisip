/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "bctoolbox/tester.h"
#include "utils/http-mock/http-mock.hh"

#include <atomic>
#include <limits>
#include <memory>
#include <mutex>
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

// Send a request too big for the window size. Some frames will be kept in nghttp2's queue.
// Let it timeout, then trigger sending of the remaining frames.
// If not handled correctly, the payload will be freed on timeout and trigger a SEGV when trying to resume the remaining
// frames
void partiallySentRequestCanceledByTimeout() {
	sofiasip::SuRoot root{};
	std::atomic_int requestsReceivedCount{0};
	HttpMock httpMock{{"/"}, &requestsReceivedCount};
	const auto port = [&httpMock]() {
		const auto port = httpMock.serveAsync();
		BC_HARD_ASSERT_TRUE(port > -1);
		return std::to_string(port);
	}();
	const auto client = Http2Client::make(root, "localhost", port);
	client->setRequestTimeout(1s);
	const HttpHeaders headers{
	    {":method"s, "POST"s},
	    {":scheme", "https"},
	    {":authority", "localhost:" + port},
	    {":path", "/"},
	};

	client->send(
	    std::make_shared<Http2Client::HttpRequest>(headers,
	                                               std::string(/* overflow window size */ 0x4009 * 4 - 0x25, 'A')),
	    [&root](const std::shared_ptr<Http2Client::HttpRequest>&, const std::shared_ptr<HttpResponse>&) {
		    BC_FAIL("This request will never be answered");
		    root.quit();
	    },
	    [&root](const std::shared_ptr<Http2Client::HttpRequest>&) { root.quit(); });
	root.run();
	client->send(
	    std::make_shared<Http2Client::HttpRequest>(headers, "Trigger sending of remaining frames"),
	    [&root](const std::shared_ptr<Http2Client::HttpRequest>&, const std::shared_ptr<HttpResponse>&) {
		    root.quit();
	    },
	    [&root](const std::shared_ptr<Http2Client::HttpRequest>&) {
		    BC_FAIL("Unexpected error in resend trigger request");
		    root.quit();
	    });
	root.run();
	// Clean up
	root.step(1s);
}

namespace {
TestSuite _("Http2Client",
            {
                CLASSY_TEST(partiallySentRequestCanceledByTimeout),
            });
}
} // namespace flexisip::tester
