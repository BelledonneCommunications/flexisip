/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "libhiredis-wrapper/redis-reply.hh"

#include <stdexcept>

#include "compat/hiredis/hiredis.h"

#include "bctoolbox/tester.h"

#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/variant-utils.hh"

namespace flexisip::tester {
namespace {

using namespace redis::reply;

void array_indexOutOfBounds() {
	const Array array{nullptr, 1};

	try {
		array[1];
		BC_FAIL("The array does not have enough elements, this is an invalid read");
	} catch (const std::out_of_range&) {
	}
}

void arrayOfPairs_indexOutOfBounds() {
	const ArrayOfPairs arrayOfPairs{nullptr, 2};

	try {
		arrayOfPairs[1];
		BC_FAIL("The array does not have enough elements, this is an invalid read");
	} catch (const std::out_of_range&) {
	}
}

void arrayOfPairs_unEvenArray() {
	try {
		const ArrayOfPairs arrayOfPairs{nullptr, 1};
		BC_FAIL("The array has an uneven number of elements, and cannot be viewed as an array of pairs");
	} catch (const std::logic_error&) {
	}
}

void arrayOfPairs_indexing() {
	constexpr redisReply elements[]{
	    {.type = REDIS_REPLY_INTEGER, .integer = 0},
	    {.type = REDIS_REPLY_INTEGER, .integer = 1},
	    {.type = REDIS_REPLY_INTEGER, .integer = 2},
	    {.type = REDIS_REPLY_INTEGER, .integer = 3},
	};
	constexpr auto count = sizeof(elements) / sizeof(elements[0]);
	const redisReply* const arrayOfPointers[count]{elements, elements + 1, elements + 2, elements + 3};
	const ArrayOfPairs pairs{arrayOfPointers, count};
	BC_ASSERT_CPP_EQUAL(pairs.size(), 2);

	const auto [first, second] = pairs[0];
	BC_ASSERT_CPP_EQUAL(EXPECT_VARIANT(Integer).in(first), 0);
	BC_ASSERT_CPP_EQUAL(EXPECT_VARIANT(Integer).in(second), 1);
	const auto [third, fourth] = pairs[1];
	BC_ASSERT_CPP_EQUAL(EXPECT_VARIANT(Integer).in(third), 2);
	BC_ASSERT_CPP_EQUAL(EXPECT_VARIANT(Integer).in(fourth), 3);
}

TestSuite _("redis::Reply",
            {
                CLASSY_TEST(array_indexOutOfBounds),
                CLASSY_TEST(arrayOfPairs_indexOutOfBounds),
                CLASSY_TEST(arrayOfPairs_unEvenArray),
                CLASSY_TEST(arrayOfPairs_indexing),
            });
} // namespace
} // namespace flexisip::tester
