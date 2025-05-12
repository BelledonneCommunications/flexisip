/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include <list>

#include <bctoolbox/tester.h>

#include "utils/rand.hh"
#include "utils/string-utils.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/uri-utils.hh"

using namespace std;

namespace flexisip::tester {

namespace uri_utils {
using namespace flexisip::uri_utils;

void isIPv4() {
	BC_ASSERT_TRUE(isIpv4Address("127.0.0.1"));
	BC_ASSERT_TRUE(isIpv4Address("192.168.3.5"));
	BC_ASSERT_TRUE(isIpv4Address("10.42.0.55"));

	BC_ASSERT_FALSE(isIpv4Address("::1"));
	BC_ASSERT_FALSE(isIpv4Address("2001:0db8:0000:85a3:0000:0000:ac1f:8001"));
	BC_ASSERT_FALSE(isIpv4Address("2001:db8:0:85a3:0:0:ac1f:8001"));
	BC_ASSERT_FALSE(isIpv4Address("2001:db8:0:85a3::ac1f:8001"));
	BC_ASSERT_FALSE(isIpv4Address("[2001:db8:0:85a3::ac1f:8001]"));

	BC_ASSERT_FALSE(isIpv4Address("localhost"));
	BC_ASSERT_FALSE(isIpv4Address("sip.example.org"));
}

void isIPv6() {
	BC_ASSERT_FALSE(isIpv6Address("127.0.0.1"));
	BC_ASSERT_FALSE(isIpv6Address("192.168.3.5"));
	BC_ASSERT_FALSE(isIpv6Address("10.42.0.55"));

	BC_ASSERT_TRUE(isIpv6Address("::1"));
	BC_ASSERT_TRUE(isIpv6Address("2001:0db8:0000:85a3:0000:0000:ac1f:8001"));
	BC_ASSERT_TRUE(isIpv6Address("2001:db8:0:85a3:0:0:ac1f:8001"));
	BC_ASSERT_TRUE(isIpv6Address("2001:db8:0:85a3::ac1f:8001"));
	BC_ASSERT_FALSE(isIpv6Address("[2001:db8:0:85a3::ac1f:8001]"));

	BC_ASSERT_FALSE(isIpv6Address("localhost"));
	BC_ASSERT_FALSE(isIpv6Address("sip.example.org"));
}

void isIP() {
	BC_ASSERT_TRUE(isIpAddress("192.168.3.5"));

	BC_ASSERT_TRUE(isIpAddress("2001:0db8:0000:85a3:0000:0000:ac1f:8001"));
	BC_ASSERT_TRUE(isIpAddress("[2001:db8:0:85a3::ac1f:8001]"));

	BC_ASSERT_FALSE(isIpAddress("localhost"));
	BC_ASSERT_FALSE(isIpAddress("sip.example.org"));
}

} // namespace uri_utils

namespace string_utils {

void join() {
	// Basic + template tests
	vector<string> stringVector{"0", "1", "2", "3", "4", "5"};
	const auto& vectorJoined = StringUtils::join(stringVector);
	BC_ASSERT_TRUE(vectorJoined == "0 1 2 3 4 5");

	list<string> stringList{"0", "1", "2", "3", "4", "5"};
	const auto& listJoined = StringUtils::join(stringList);
	BC_ASSERT_TRUE(listJoined == "0 1 2 3 4 5");

	set<string> stringSet{"0", "1", "2", "3", "4", "5"};
	const auto& setJoined = StringUtils::join(stringSet);
	BC_ASSERT_TRUE(setJoined == "0 1 2 3 4 5");

	// Tests with fromIndex
	const auto& vectorJoinedFrom1 = StringUtils::join(stringVector, 1);
	BC_ASSERT_TRUE(vectorJoinedFrom1 == "1 2 3 4 5");

	const auto& vectorJoinedFrom3 = StringUtils::join(stringVector, 3);
	BC_ASSERT_TRUE(vectorJoinedFrom3 == "3 4 5");

	const auto& vectorJoinedFrom8 = StringUtils::join(stringVector, 8);
	BC_ASSERT_TRUE(vectorJoinedFrom8 == "");

	// Borderline cases
	vector<string> emptyVector{};
	const auto& emptyJoined = StringUtils::join(emptyVector);
	BC_ASSERT_TRUE(emptyJoined == "");
	const auto& emptyJoinedFrom5 = StringUtils::join(emptyVector, 5);
	BC_ASSERT_TRUE(emptyJoinedFrom5 == "");

	const auto& vectorJoinedFromNegative = StringUtils::join(stringVector, -1);
	// fromIndex must be unsigned
	BC_ASSERT_TRUE(vectorJoinedFromNegative == "");
}

void searchAndReplace() {
	// Test the string remains unchanged.
	string test1 = "this is a test string.";
	StringUtils::searchAndReplace(test1, "y", "a");
	BC_ASSERT_TRUE(test1 == test1);

	// Simple test.
	string test2 = "this is a test string.";
	StringUtils::searchAndReplace(test2, "s ", "_");
	BC_ASSERT_TRUE(test2 == "thi_i_a test string.");

	// Test that all " characters are replaced with \".
	// This test makes sure the function still works even when the value contains the key.
	string test3 = R"({"data": {"key" : "value", "key": {"key": "value"}}})";
	StringUtils::searchAndReplace(test3, R"(")", R"(\")");
	BC_ASSERT_TRUE(test3 == R"({\"data\": {\"key\" : \"value\", \"key\": {\"key\": \"value\"}}})");
}

} // namespace string_utils

namespace random_utils {

void integer() {
	Random random{0x5EED};

	auto vChar = random.integer<char>().generate();
	BC_ASSERT_CPP_EQUAL(vChar, static_cast<char>(-80));
	auto vSignedChar = random.integer<signed char>().generate();
	BC_ASSERT_CPP_EQUAL(vSignedChar, static_cast<signed char>(-1));
	auto vUnsignedChar = random.integer<unsigned char>().generate();
	BC_ASSERT_CPP_EQUAL(vUnsignedChar, static_cast<unsigned char>(247));
	auto vWchart = random.integer<wchar_t>().generate();
	BC_ASSERT_CPP_EQUAL(vWchart, 1667813865);
	auto vShort = random.integer<short>().generate();
	BC_ASSERT_CPP_EQUAL(vShort, 27997);
	auto vUnsignedShort = random.integer<unsigned short>().generate();
	BC_ASSERT_CPP_EQUAL(vUnsignedShort, 15153);
	auto vInt = random.integer<int>().generate();
	BC_ASSERT_CPP_EQUAL(vInt, -897737855);
	auto vUnsignedInt = random.integer<unsigned int>().generate();
	BC_ASSERT_CPP_EQUAL(vUnsignedInt, 2767839866);
	auto vLong = random.integer<long>().generate();
	BC_ASSERT_CPP_EQUAL(vLong, -8433882674259222672L);
	auto vUnsignedLong = random.integer<unsigned long>().generate();
	BC_ASSERT_CPP_EQUAL(vUnsignedLong, 14174584727448916282Ul);
	auto vLongLong = random.integer<long long>().generate();
	BC_ASSERT_CPP_EQUAL(vLongLong, -3105208237836728405ll);
	auto vUnsignedLongLong = random.integer<unsigned long long>().generate();
	BC_ASSERT_CPP_EQUAL(vUnsignedLongLong, 16312724988467902449ull);
}

void real() {
	Random random{0x5EED};

	auto vFloat = random.real<float>().generate();
	BC_ASSERT_CPP_EQUAL(vFloat, 6.47178224e+37f);
	auto vDouble = random.real<double>().generate();
	BC_ASSERT_CPP_EQUAL(vDouble, 1.7346564169626818e+308);
	// Note: the type 'long double' is not tested as its precision may vary (implementation-defined).
}

void timestamp() {
	Random random{0x5EED};

	auto vTimestamp = random.timestamp().generate();
	BC_ASSERT_CPP_EQUAL(vTimestamp, 408426906);
}

void boolean() {
	Random random{0x5EED};

	auto vBoolean = random.boolean().generate();
	BC_ASSERT_CPP_EQUAL(vBoolean, false);
}

void string() {
	Random random{0x5EED};

	const auto result = random.string().generate(10);
	BC_ASSERT_STRING_EQUAL(result.c_str(), "Mf9qx7OFl-");

	// State is stored in the Random instance, saving the intermediate StringGenerator is optional.
	const auto other = random.string().generate(10);
	BC_ASSERT_CPP_NOT_EQUAL(other, result);
}

} // namespace random_utils

namespace {
TestSuite _("Utils",
            {
                CLASSY_TEST(uri_utils::isIPv4),
                CLASSY_TEST(uri_utils::isIPv6),
                CLASSY_TEST(uri_utils::isIP),
                CLASSY_TEST(string_utils::searchAndReplace),
                CLASSY_TEST(string_utils::join),
                CLASSY_TEST(random_utils::integer),
                CLASSY_TEST(random_utils::timestamp),
                CLASSY_TEST(random_utils::boolean),
                CLASSY_TEST(random_utils::real),
                CLASSY_TEST(random_utils::string),
            });
}
} // namespace flexisip::tester