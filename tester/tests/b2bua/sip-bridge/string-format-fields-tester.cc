/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include "b2bua/sip-bridge/string-format-fields.hh"

#include "flexisip/logmanager.hh"

#include "utils/string-interpolation/template-formatter.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

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

void linphoneAddressFields() {
	const string expectedDisplayName{"Expected DisplayName"};
	const string expectedUserInfo{"expected-user-info"};
	const string expectedHostPort{"expected-hostport.com"};
	const string expectedUriParams{";transport=tcp;device=phone"};
	const auto factory = linphone::Factory::get();
	const auto addr = factory->createAddress("sip:" + expectedUserInfo + "@" + expectedHostPort + expectedUriParams);

	{
		const TemplateFormatter formatter{"{displayName}", kLinphoneAddressFields};

		const auto result = formatter.format(addr);

		BC_ASSERT(result.empty());
	}

	addr->setDisplayName(expectedDisplayName);
	{
		const TemplateFormatter formatter{"{displayName}", kLinphoneAddressFields};

		const auto result = formatter.format(addr);

		BC_ASSERT_CPP_EQUAL(result, R"(")" + expectedDisplayName + R"(")");
	}
	{
		const TemplateFormatter formatter{"{user}", kLinphoneAddressFields};

		const auto result = formatter.format(addr);

		BC_ASSERT_CPP_EQUAL(result, expectedUserInfo);
	}
	{
		const TemplateFormatter formatter{"{hostport}", kLinphoneAddressFields};

		const auto result = formatter.format(addr);

		BC_ASSERT_CPP_EQUAL(result, expectedHostPort);
	}
	{
		const TemplateFormatter formatter{"{uriParameters}", kLinphoneAddressFields};

		const auto result = formatter.format(addr);

		BC_ASSERT_CPP_EQUAL(result, expectedUriParams);
	}
	{
		const string templateStr{"{displayName} <sip:{user}@{hostport}{uriParameters}>"};
		const TemplateFormatter formatter{templateStr, kLinphoneAddressFields};

		const auto result = formatter.format(addr);

		BC_ASSERT_CPP_EQUAL(result, addr->asString());
	}
}

TestSuite _{
    "b2bua::sip-bridge::variable_substitution",
    {
        CLASSY_TEST(knownFields),
        CLASSY_TEST(unknownFields),
        CLASSY_TEST(missingClosingDelim),
        CLASSY_TEST(linphoneAddressFields),
    },
};

} // namespace
} // namespace flexisip::tester