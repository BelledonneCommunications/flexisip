/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "bctoolbox/tester.h"
#include "flexiapi/schemas/iso-8601-date.hh"

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "utils/asserts.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace {
using namespace flexisip;
using namespace flexisip::tester;
using namespace flexisip::flexiapi;
using namespace std;

void fromJsonValid() {
	// ❯ date --date='1953-12-05T11:21:12Z' +%s
	constexpr time_t timestamp = -507213528;
	BC_ASSERT_CPP_EQUAL(R"("1953-12-05T11:21:12Z")"_json.get<ISO8601Date>(), ISO8601Date(timestamp));
}

void fromJsonInvalid() {
	try {
		R"("October 27, 1930")"_json.get<ISO8601Date>();
		BC_FAIL("This date shouldn't parse");
	} catch (const nlohmann::json::exception&) {
		// passed
	}
}

TestSuite _("ISO8601Date",
            {
                CLASSY_TEST(fromJsonValid),
                CLASSY_TEST(fromJsonInvalid),
            });
} // namespace
