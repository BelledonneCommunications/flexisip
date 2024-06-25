/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "b2bua/sip-bridge/string-format-fields.hh"

#include "flexisip/logmanager.hh"

#include "utils/string-interpolation/template-formatter.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace flexisip::tester {
namespace {
using namespace utils::string_interpolation;
using namespace b2bua::bridge;

bool operator==(const StringViewMold& left, const StringViewMold& right) {
	return left.start == right.start && left.size == right.size;
}

std::ostream& operator<<(std::ostream& ostr, const StringViewMold& mold) {
	return ostr << "StringViewMold{ .start = " << mold.start << ", .size = " << mold.size << "}";
}

void tryParse(std::string template_) {
	TemplateFormatter<const linphone::Call&>(template_, kLinphoneCallFields);
}

std::size_t charCount(std::string_view view) {
	return view.size();
}

void knownFields() {
	tryParse("{to.hostport}");
}

void unknownFields() {
	try {
		tryParse("{unknown.hostport}");
		BC_FAIL("expected exception");
	} catch (const ResolutionError& err) {
		const auto& expected = StringViewMold{.start = charCount("{"), .size = charCount("unknown")};
		BC_ASSERT_CPP_EQUAL(err.offendingToken, expected);
	}

	try {
		tryParse("{to.hostport.what}");
		BC_FAIL("expected exception");
	} catch (const ResolutionError& err) {
		const auto& expected = StringViewMold{.start = charCount("{to.hostport."), .size = charCount("what")};
		BC_ASSERT_CPP_EQUAL(err.offendingToken, expected);
		SLOGD << "Preview of caught exception .what(): " << err.what();
	}
}

void missingClosingDelim() {
	try {
		tryParse("sip:{from.hostport");
		BC_FAIL("expected exception");
	} catch (const TemplateString::MissingClosingDelimiter& err) {
		BC_ASSERT_CPP_EQUAL(err.startDelimPos, charCount("sip:"));
		BC_ASSERT_CPP_EQUAL(err.expectedDelim, "}");
		SLOGD << "Preview of caught exception .what():" << err.what();
	}
}

TestSuite _{
    "b2bua::bridge::variable_substitution",
    {
        CLASSY_TEST(knownFields),
        CLASSY_TEST(unknownFields),
        CLASSY_TEST(missingClosingDelim),
    },
};
} // namespace
} // namespace flexisip::tester