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

#include "spaces-store/spaces/fam-spaces-data.hh"

#include <memory>
#include <string>
#include <vector>

#include "core-assert.hh"
#include "flexiapi/schemas/space/space.hh"
#include "shared-tests.hh"
#include "utils/http-mock/http-mock.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/transport/http/rest-client.hh"

using namespace std;

namespace flexisip::tester {
namespace {

const auto apiPath = "/api/spaces";

/*
 * Test domains loading at initialization and periodic refresh.
 */
void spacesLoading() {
	const auto suRoot = make_shared<sofiasip::SuRoot>();
	CoreAssert asserter{suRoot};

	vector<flexiapi::Space> actualSpaces{};
	const auto notifySpacesChangedCb = [&](const vector<flexiapi::Space>& spaces) { actualSpaces = spaces; };

	http_mock::HttpMock server{apiPath};
	BC_HARD_ASSERT_TRUE(server.addResponseToGET(apiPath, kTestSpacesJson.dump()));
	const auto port = to_string(server.serveAsync());
	const auto http2Client = Http2Client::make(*suRoot, "localhost", port);

	const auto data = make_shared<FAMSpacesData>(suRoot, RestClient{http2Client}, 500ms, notifySpacesChangedCb);
	asserter.waitUntil(250ms, [&] { return !actualSpaces.empty(); }).hard_assert_passed();

	flexisip::tester::hasSpaces(actualSpaces, kTestSpaces);

	const string newDomain{"new.example.org"};
	auto newSpaces = kTestSpacesJson;
	newSpaces.emplace_back(nlohmann::json{{"domain", newDomain}, {"super", false}});
	BC_HARD_ASSERT_TRUE(server.addResponseToGET(apiPath, newSpaces.dump()));

	// Expect actual spaces to have one more space after the next refresh.
	asserter.wait([&] { return LOOP_ASSERTION(actualSpaces.size() == kTestSpaces.size() + 1); }).hard_assert_passed();

	const vector<flexiapi::Space> newExpectedSpaces = {
	    {.domain = kTestDomains[0]},
	    {.domain = kTestDomains[1]},
	    {.domain = newDomain},
	};
	flexisip::tester::hasSpaces(actualSpaces, newExpectedSpaces);
}

const TestSuite kSuite{
    "FAMSpacesData",
    {
        CLASSY_TEST(spacesLoading),
    },
};

} // namespace
} // namespace flexisip::tester