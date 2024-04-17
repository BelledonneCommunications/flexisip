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

#include "registrar/contact-key.hh"
#include "utils/rand.hh"
#include "utils/string-utils.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/uri-utils.hh"

using namespace std;

namespace flexisip::tester {

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

class RandomStringGeneratorTest : public Test {
public:
	void operator()() override {
		RandomStringGenerator rsg(flexisip::ContactKey::kPlaceholderAlphabet, 0x5EED);

		const auto result = rsg(10);

		BC_ASSERT_STRING_EQUAL(result.c_str(), "Mf9qx7OFl-");
	}
};

class StringUtilsJoinTest : public Test {
public:
	void operator()() override {
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
};

class StringUtilsSearchAndReplaceTest : public Test {
public:
	void operator()() override {
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
};

namespace {
TestSuite _("Utils unit tests",
            {
                TEST_NO_TAG("UriUtils isIpv4Address and isIpv6Address method test", run<UriUtilsIsIpvXTest>),
                CLASSY_TEST(RandomStringGeneratorTest),
                TEST_NO_TAG("StringUtils::join method test", run<StringUtilsJoinTest>),
                TEST_NO_TAG("StringUtils::searchAndReplace method test", run<StringUtilsSearchAndReplaceTest>),
            });
}
} // namespace flexisip::tester
