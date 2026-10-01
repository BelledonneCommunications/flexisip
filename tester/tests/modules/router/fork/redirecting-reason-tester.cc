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

#include "fork-context/redirecting-reason.hh"

#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace flexisip;

namespace flexisip::tester {
namespace {

void reasonValuesFollowRfc4458() {
	// Redirecting Reason values defined by RFC 4458 (§ 2.2).
	BC_ASSERT_CPP_EQUAL(toValue(RedirectingReason::Unknown), 404);
	BC_ASSERT_CPP_EQUAL(toValue(RedirectingReason::UserBusy), 486);
	BC_ASSERT_CPP_EQUAL(toValue(RedirectingReason::NoReply), 408);
	BC_ASSERT_CPP_EQUAL(toValue(RedirectingReason::Unconditional), 302);
	BC_ASSERT_CPP_EQUAL(toValue(RedirectingReason::DeflectionDuringAlerting), 487);
	BC_ASSERT_CPP_EQUAL(toValue(RedirectingReason::DeflectionImmediateResponse), 480);
	BC_ASSERT_CPP_EQUAL(toValue(RedirectingReason::MobileNotReachable), 503);
}

TestSuite _{
    "RedirectingReason",
    {
        CLASSY_TEST(reasonValuesFollowRfc4458),
    },
};
} // namespace
} // namespace flexisip::tester
