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

#include "shared-tests.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip::tester {
namespace {

/*
 * Test domains loading at initialization.
 */
void getDomains() {
	const auto store = make_shared<StaticDomainsStore>(list<string>{kTestDomains.begin(), kTestDomains.end()});
	flexisip::tester::getDomains(store, unordered_set<string>{kTestDomains.begin(), kTestDomains.end()});
}

const TestSuite kSuite{
    "StaticDomainsStore",
    {
        CLASSY_TEST(getDomains),
    },
};

} // namespace
} // namespace flexisip::tester