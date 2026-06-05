/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "auth/domains-store.hh"

#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include "core-assert.hh"
#include "shared-tests.hh"
#include "utils/http-mock/http-mock.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/transport/http/rest-client.hh"

using namespace std;

namespace flexisip::tester {
namespace {

const auto apiPath = "/api/spaces";
const nlohmann::json spaces = {
    {
        {"domain", kTestDomains[0]},
        {"super", true},
    },
    {
        {"domain", kTestDomains[1]},
        {"super", false},
    },
};

/*
 * Test domains loading at initialization and periodic refresh.
 */
void getDomains() {
	const auto suRoot = make_shared<sofiasip::SuRoot>();
	CoreAssert asserter{suRoot};

	http_mock::HttpMock server{apiPath};
	BC_HARD_ASSERT_TRUE(server.addResponseToGET(apiPath, spaces.dump()));
	const auto port = to_string(server.serveAsync());
	const auto http2Client = Http2Client::make(*suRoot, "localhost", port);

	const auto store = make_shared<DynamicDomainsStore>(suRoot, RestClient{http2Client}, 500ms);
	asserter.waitUntil(250ms, [&store] { return !store->getDomains().empty(); }).hard_assert_passed();

	flexisip::tester::getDomains(store, unordered_set<string>{kTestDomains.begin(), kTestDomains.end()});

	const string newDomain{"new.example.org"};
	auto newSpaces = spaces;
	newSpaces.emplace_back(nlohmann::json{{"domain", newDomain}, {"super", false}});
	BC_HARD_ASSERT_TRUE(server.addResponseToGET(apiPath, newSpaces.dump()));

	asserter
	    .wait([&store, &newDomain] {
		    const auto& domains = store->getDomains();
		    FAIL_IF(domains.find(newDomain) == domains.end());
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	flexisip::tester::getDomains(store, unordered_set<string>{kTestDomains[0], kTestDomains[1], newDomain});
}

const TestSuite kSuite{
    "DynamicDomainsStore",
    {
        CLASSY_TEST(getDomains),
    },
};

} // namespace
} // namespace flexisip::tester