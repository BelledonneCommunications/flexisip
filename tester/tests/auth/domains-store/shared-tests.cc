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

#include "shared-tests.hh"

#include "test-patterns/test.hh"

using namespace std;

namespace flexisip::tester {

void getDomains(const shared_ptr<IDomainsStore>& store, const unordered_set<string>& expected) {
	BC_HARD_ASSERT_NOT_NULL(store);

	const auto& domains = store->getDomains();
	BC_HARD_ASSERT_CPP_EQUAL(domains.size(), expected.size());
	for (const auto& domain : domains) {
		BC_HARD_ASSERT(expected.find(domain) != expected.end());
	}
}

} // namespace flexisip::tester