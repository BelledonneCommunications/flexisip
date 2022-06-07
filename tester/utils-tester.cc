/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022  Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <bctoolbox/tester.h>

#include "tester.hh"
#include "utils/test-patterns/test.hh"
#include "utils/uri-utils.hh"

using namespace std;

namespace flexisip {
namespace tester {

class UriUtilsIsIpvXTest : public Test {
public:
	void operator()() override {
		// IPV4
		BC_ASSERT_TRUE(UriUtils::isIpv4Address("127.0.0.1"));
		BC_ASSERT_TRUE(UriUtils::isIpv4Address("192.168.3.5"));
		BC_ASSERT_TRUE(UriUtils::isIpv4Address("10.42.0.55"));

		BC_ASSERT_FALSE(UriUtils::isIpv6Address("127.0.0.1"));
		BC_ASSERT_FALSE(UriUtils::isIpv6Address("192.168.3.5"));
		BC_ASSERT_FALSE(UriUtils::isIpv6Address("10.42.0.55"));

		// IPV6
		BC_ASSERT_TRUE(UriUtils::isIpv6Address("::1"));
		BC_ASSERT_TRUE(UriUtils::isIpv6Address("2001:0db8:0000:85a3:0000:0000:ac1f:8001"));
		BC_ASSERT_TRUE(UriUtils::isIpv6Address("2001:db8:0:85a3:0:0:ac1f:8001"));
		BC_ASSERT_TRUE(UriUtils::isIpv6Address("2001:db8:0:85a3::ac1f:8001"));

		BC_ASSERT_FALSE(UriUtils::isIpv4Address("::1"));
		BC_ASSERT_FALSE(UriUtils::isIpv4Address("2001:0db8:0000:85a3:0000:0000:ac1f:8001"));
		BC_ASSERT_FALSE(UriUtils::isIpv4Address("2001:db8:0:85a3:0:0:ac1f:8001"));
		BC_ASSERT_FALSE(UriUtils::isIpv4Address("2001:db8:0:85a3::ac1f:8001"));

		// Hostname
		BC_ASSERT_FALSE(UriUtils::isIpv4Address("localhost"));
		BC_ASSERT_FALSE(UriUtils::isIpv4Address("sip.example.org"));

		BC_ASSERT_FALSE(UriUtils::isIpv6Address("localhost"));
		BC_ASSERT_FALSE(UriUtils::isIpv6Address("sip.example.org"));
	}
};

static test_t tests[] = {
    TEST_NO_TAG("UriUtils isIpv4Address and isIpv6Address method test", run<UriUtilsIsIpvXTest>),
};

test_suite_t utilsSuite = {
    "Utils unit tests", nullptr, nullptr, nullptr, nullptr, sizeof(tests) / sizeof(tests[0]), tests};

} // namespace tester
} // namespace flexisip
