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

void receivedCodesTranslateToReasons() {
	// Codes with an explicit mapping.
	BC_ASSERT_ENUM_EQUAL(codeToRedirectingReason(408), RedirectingReason::NoReply);
	BC_ASSERT_ENUM_EQUAL(codeToRedirectingReason(480), RedirectingReason::NoReply);
	BC_ASSERT_ENUM_EQUAL(codeToRedirectingReason(486), RedirectingReason::UserBusy);
	BC_ASSERT_ENUM_EQUAL(codeToRedirectingReason(603), RedirectingReason::UserBusy);
}

void unmappedCodesFallbackToUnconditional() {
	// RFC 4458 (§ 2.2): codes with no appropriate mapping are mapped to 302 'Unconditional'.
	// This includes codes used as cause values by RFC 4458 (e.g. 404, 487, 503): the RFC binds them to
	// reasons for encoding, but a received code does not imply that reason, so they are deliberately
	// left to the fallback.
	for (int code : {100, 300, 301, 302, 400, 404, 410, 484, 487, 488, 500, 503, 600, 604}) {
		BC_ASSERT_ENUM_EQUAL(codeToRedirectingReason(code), RedirectingReason::Unconditional);
	}
}

TestSuite _{
    "RedirectingReason",
    {
        CLASSY_TEST(reasonValuesFollowRfc4458),
        CLASSY_TEST(receivedCodesTranslateToReasons),
        CLASSY_TEST(unmappedCodesFallbackToUnconditional),
    },
};
} // namespace
} // namespace flexisip::tester
