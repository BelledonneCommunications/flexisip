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

#include <ios>

#include "bctoolbox/tester.h"

#include "utils/test-suite.hh"
#include "utils/utf8-string.hh"

using namespace flexisip::utils;

namespace flexisip::tester::utils {

void decode_valid_utf8() {
	Utf8String validated(u8"🏔️📞");
	BC_ASSERT_STRING_EQUAL(validated.asString().c_str(), u8"🏔️📞");
}

// The empty string has .size() == 0 which could lead to Some Nasty Things™️ (pointer to zero-lengthed array) if we
// create a temporary buffer to validate it
void decode_empty_string() {
	Utf8String validated(u8"");
	BC_ASSERT_STRING_EQUAL(validated.asString().c_str(), u8"");
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
                TEST_NO_TAG_AUTO_NAMED(decode_empty_string),
                TEST_NO_TAG_AUTO_NAMED(decode_invalid_utf8),
            });
}
} // namespace flexisip::tester::utils
