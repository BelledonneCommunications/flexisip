/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <cstdint>
#include <iomanip>
#include <ios>
#include <iostream>
#include <ostream>
#include <utility>

#include "bctoolbox/tester.h"

#include "utils/test-suite.hh"

#include "flexisip/utils/utf8-string.hh"

using namespace flexisip::utils;

namespace flexisip {
namespace tester {
namespace utils {

void decode_valid_utf8() {
	Utf8String validated(u8"🏔️📞");
	BC_ASSERT_STRING_EQUAL(validated.asString().c_str(), u8"🏔️📞");
}

void decode_invalid_utf8() {
	{
		std::string invalidAtStart{u8"🏔️📞"};
		auto invalid = invalidAtStart[1] = 0x8f;
		Utf8String validated(invalidAtStart);
		BC_ASSERT_NOT_EQUAL(validated.asString()[1], invalid, char, "%x");
		BC_ASSERT_STRING_EQUAL(validated.asString().c_str(), u8"����️📞");
	}
	{
		std::string invalidAtEnd{u8"🏔️📞"};
		auto invalid = invalidAtEnd.back() = 0xff;
		Utf8String validated(invalidAtEnd);
		BC_ASSERT_NOT_EQUAL(validated.asString().back(), invalid, char, "%x");
		BC_ASSERT_STRING_EQUAL(validated.asString().c_str(), u8"🏔️����");
	}
	{
		std::string invalidAtEnd{u8"🏔️phone"};
		auto invalid = invalidAtEnd.back() = 0xff;
		Utf8String validated(invalidAtEnd);
		BC_ASSERT_NOT_EQUAL(validated.asString().back(), invalid, char, "%x");
		BC_ASSERT_STRING_EQUAL(validated.asString().c_str(), u8"🏔️phon�");
	}
	{
		std::string invalidInTheMiddle{u8"🏔️oops📞"};
		auto index = invalidInTheMiddle.find('p');
		auto invalid = invalidInTheMiddle[index] = 0xff;
		Utf8String validated(invalidInTheMiddle);
		BC_ASSERT_NOT_EQUAL(validated.asString()[index], invalid, char, "%x");
		BC_ASSERT_STRING_EQUAL(validated.asString().c_str(), u8"🏔️oo�s📞");
	}
}

namespace {
TestSuite _("Utf8String",
            {
                TEST_NO_TAG_AUTO_NAMED(decode_valid_utf8),
                TEST_NO_TAG_AUTO_NAMED(decode_invalid_utf8),
            });
}
} // namespace utils
} // namespace tester
} // namespace flexisip
