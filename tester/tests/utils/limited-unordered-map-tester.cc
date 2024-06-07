/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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
#include <unordered_set>

#include "utils/limited-unordered-map.hh"

#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace flexisip::tester {

using namespace std;

void sizeTests() {
	LimitedUnorderedMap<int, int> limitedTo5{5};
	LimitedUnorderedMap<int, int> limitedTo10{10};

	for (int i = 0; i < 20; i++) {
		limitedTo5.try_emplace(i, i);
		limitedTo10.try_emplace(i, i);
	}

	BC_ASSERT_CPP_EQUAL(limitedTo5.size(), 5);
	BC_ASSERT_CPP_EQUAL(limitedTo10.size(), 10);

	int loopSize = 0;
	for (auto [key, value] : limitedTo5) {
		loopSize++;
		BC_ASSERT_CPP_EQUAL(key, value);
		BC_ASSERT_TRUE(value >= 15);
		BC_ASSERT_TRUE(value < 20);
	}
	BC_ASSERT_CPP_EQUAL(loopSize, 5);

	loopSize = 0;
	for (auto [key, value] : limitedTo10) {
		loopSize++;
		BC_ASSERT_CPP_EQUAL(key, value);
		BC_ASSERT_TRUE(value >= 10);
		BC_ASSERT_TRUE(value < 20);
	}
	BC_ASSERT_CPP_EQUAL(loopSize, 10);
}

void mergeTestToEmpty() {
	LimitedUnorderedMap<int, int> limitedTo5{5};
	LimitedUnorderedMap<int, int> limitedTo10{10};

	for (int i = 0; i < 20; i++) {
		limitedTo10.try_emplace(i, i);
	}

	limitedTo5.merge(limitedTo10);

	int loopSize = 0;
	for (auto [key, value] : limitedTo5) {
		loopSize++;
		BC_ASSERT_CPP_EQUAL(key, value);
		BC_ASSERT_TRUE(value >= 10);
		BC_ASSERT_TRUE(value < 15);
	}
	BC_ASSERT_CPP_EQUAL(loopSize, 5);
	BC_ASSERT_CPP_EQUAL(limitedTo5.size(), 5);
}

void mergeTestFromEmpty() {
	LimitedUnorderedMap<int, int> limitedTo5{5};
	LimitedUnorderedMap<int, int> limitedTo10{10};

	for (int i = 0; i < 20; i++) {
		limitedTo5.try_emplace(i, i);
	}

	limitedTo5.merge(limitedTo10);

	int loopSize = 0;
	for (auto [key, value] : limitedTo5) {
		loopSize++;
		BC_ASSERT_CPP_EQUAL(key, value);
		BC_ASSERT_TRUE(value >= 15);
		BC_ASSERT_TRUE(value < 20);
	}
	BC_ASSERT_CPP_EQUAL(loopSize, 5);
	BC_ASSERT_CPP_EQUAL(limitedTo5.size(), 5);
}

void mergeTestBothFull() {
	LimitedUnorderedMap<int, int> limitedTo5{5};
	LimitedUnorderedMap<int, int> limitedTo15{15};

	for (int i = 0; i < 20; i++) {
		limitedTo5.try_emplace(i, i);
	}
	for (int i = 100; i < 120; i++) {
		limitedTo15.try_emplace(i, i);
	}

	limitedTo15.merge(limitedTo5);

	int loopSize = 0;
	unordered_set listOfValues{105, 15, 106, 16, 107, 17, 108, 18, 109, 19, 110, 111, 112, 113, 114};
	for (auto [key, value] : limitedTo15) {
		loopSize++;
		BC_ASSERT_CPP_EQUAL(key, value);
		BC_ASSERT_CPP_EQUAL(listOfValues.count(key), 1);
	}
	BC_ASSERT_CPP_EQUAL(loopSize, 15);
	BC_ASSERT_CPP_EQUAL(limitedTo15.size(), 15);

	limitedTo5 = LimitedUnorderedMap<int, int>{5};
	for (int i = 200; i < 205; i++) {
		limitedTo5.try_emplace(i, i);
	}

	limitedTo15.merge(limitedTo5);

	loopSize = 0;
	unordered_set listOfValues2{105, 200, 15, 201, 106, 202, 16, 203, 107, 204, 17, 108, 18, 109, 19};
	for (auto [key, value] : limitedTo15) {
		loopSize++;
		BC_ASSERT_CPP_EQUAL(key, value);
		BC_ASSERT_CPP_EQUAL(listOfValues2.count(key), 1);
	}

	BC_ASSERT_CPP_EQUAL(loopSize, 15);
	BC_ASSERT_CPP_EQUAL(limitedTo15.size(), 15);
}
namespace {
TestSuite _("LimitedUnorderedMap",
            {
                CLASSY_TEST(sizeTests),
                CLASSY_TEST(mergeTestToEmpty),
                CLASSY_TEST(mergeTestFromEmpty),
                CLASSY_TEST(mergeTestBothFull),
            });
} // namespace
} // namespace flexisip::tester
