/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/logmanager.hh"
#include "tester.hh"
#include "utils/test-suite.hh"
#include "utils/xsd-utils.hh"

using namespace std;
using namespace std::chrono;

namespace flexisip {
namespace tester {

using namespace Xsd::DataModel;
using namespace xsd::cxx::tree;

static void toTimeTTests() {
	Timestamp_t inferior{"2019-09-07T14:50:35Z", nullptr, flags::dont_initialize, nullptr};
	Timestamp_t mid1{"2019-09-07T15:50:35Z", nullptr, flags::dont_initialize, nullptr};
	Timestamp_t mid2{"2019-09-07T14:50:35+01:00", nullptr, flags::dont_initialize, nullptr};
	Timestamp_t superior{"2019-09-07T16:50:35Z", nullptr, flags::dont_initialize, nullptr};

	const auto& timeInf = XsdUtils::toTimeT(inferior);
	const auto& timeMid1 = XsdUtils::toTimeT(mid1);
	const auto& timeMid2 = XsdUtils::toTimeT(mid2);
	const auto& timeSup = XsdUtils::toTimeT(superior);

	BC_ASSERT_TRUE(1567867835 == timeInf);
	BC_ASSERT_TRUE(1567871435 == timeMid1);
	BC_ASSERT_TRUE(1567871435 == timeMid2);
	BC_ASSERT_TRUE(1567875035 == timeSup);
};

static void operatorTests() {
	Timestamp_t inferior{"2019-09-07T14:50:35Z", nullptr, flags::dont_initialize, nullptr};
	Timestamp_t mid1{"2019-09-07T15:50:35Z", nullptr, flags::dont_initialize, nullptr};
	Timestamp_t mid2{"2019-09-07T14:50:35+01:00", nullptr, flags::dont_initialize, nullptr};
	Timestamp_t superior{"2019-09-07T16:50:35Z", nullptr, flags::dont_initialize, nullptr};

	BC_ASSERT_TRUE(inferior < mid1);
	BC_ASSERT_TRUE(mid1 > inferior);
	BC_ASSERT_TRUE(mid1 <= mid2);
	BC_ASSERT_TRUE(mid1 >= mid2);
	BC_ASSERT_TRUE(inferior < superior);
	BC_ASSERT_TRUE(mid2 < superior);
};

TestSuite _("XSD utils test",
            {
                TEST_NO_TAG_AUTO_NAMED(toTimeTTests),
                TEST_NO_TAG_AUTO_NAMED(operatorTests),
            });

} // namespace tester

} // namespace flexisip
