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

#include "sofia-wrapper/sip-header-private.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace flexisip::tester {

using namespace std;
using namespace sofiasip;

namespace {

/*
 * Test creation of SipMsgParam.
 */
void createSipMsgParam() {
	constexpr string_view expectedKey = "parameter-key";
	constexpr string_view expectedValue = "parameter-value";

	const auto paramString = string{expectedKey} + "=" + string{expectedValue};
	const auto param = SipMsgParam{paramString};

	BC_ASSERT_CPP_EQUAL(param.getKey(), expectedKey);
	BC_ASSERT_CPP_EQUAL(param.getValue(), expectedValue);
}

/*
 * Test creation of a SipMsgParam with an ill-formatted parameter.
 */
void createSipMsgParamWithIllFormattedParameter() {
	BC_ASSERT_THROWN(SipMsgParam{"wrong-parameter-value"}, FlexisipException);
}

// Tests for the SIP "Contact:" header.
namespace contact {

/*
 * Test creation from a string describing a formatted header.
 */
void createFromFormattedHeaderWithDisplayName() {
	constexpr string_view expectedDisplayName = R"("Display Name")";
	constexpr string_view expectedUri = "sip:user@domain:1324;uri-parameter=value";
	const auto expectedHeaderParameter = SipMsgParam{"header-parameter=value"};
	const auto expectedExpires = SipMsgParam{"expires=600"};
	const auto expectedQ = SipMsgParam{"q=0.5"};

	const auto contact =
	    SipHeaderContact{expectedDisplayName.data() + " <"s + expectedUri.data() + ">;" +
	                     expectedHeaderParameter.str() + ";" + expectedExpires.str() + ";" + expectedQ.str()};

	BC_HARD_ASSERT(contact.getNativePtr() != nullptr);
	BC_ASSERT_CPP_EQUAL(contact.getDisplayName(), expectedDisplayName);
	BC_ASSERT_CPP_EQUAL(contact.getUri().str(), expectedUri);
	BC_ASSERT_CPP_EQUAL(contact.getParams().size(), 3);
	BC_ASSERT_CPP_EQUAL(contact.getParams()[0].getParam(), expectedHeaderParameter.getParam());
	BC_ASSERT_CPP_EQUAL(contact.getParams()[1].getParam(), expectedExpires.getParam());
	BC_ASSERT_CPP_EQUAL(contact.getParams()[2].getParam(), expectedQ.getParam());
	BC_ASSERT_CPP_EQUAL(contact.getComment(), "");
	BC_ASSERT_CPP_EQUAL(contact.getQ(), expectedQ.getValue());
	BC_ASSERT_CPP_EQUAL(contact.getExpires(), expectedExpires.getValue());
}

/*
 * Test creation from a string describing a formatted header.
 */
void createFromFormattedHeaderWithoutDisplayName() {
	constexpr string_view expectedUri = "sip:user@domain:1324;uri-parameter=value";
	const auto expectedHeaderParameter = SipMsgParam{"header-parameter=value"};
	const auto expectedExpires = SipMsgParam{"expires=600"};
	const auto expectedQ = SipMsgParam{"q=0.5"};

	const auto contact = SipHeaderContact{"<"s + expectedUri.data() + ">;" + expectedHeaderParameter.str() + ";" +
	                                      expectedExpires.str() + ";" + expectedQ.str()};

	BC_HARD_ASSERT(contact.getNativePtr() != nullptr);
	BC_ASSERT_CPP_EQUAL(contact.getDisplayName(), "");
	BC_ASSERT_CPP_EQUAL(contact.getUri().str(), expectedUri);
	BC_ASSERT_CPP_EQUAL(contact.getParams().size(), 3);
	BC_ASSERT_CPP_EQUAL(contact.getParams()[0].getParam(), expectedHeaderParameter.getParam());
	BC_ASSERT_CPP_EQUAL(contact.getParams()[1].getParam(), expectedExpires.getParam());
	BC_ASSERT_CPP_EQUAL(contact.getParams()[2].getParam(), expectedQ.getParam());
	BC_ASSERT_CPP_EQUAL(contact.getComment(), "");
	BC_ASSERT_CPP_EQUAL(contact.getQ(), expectedQ.getValue());
	BC_ASSERT_CPP_EQUAL(contact.getExpires(), expectedExpires.getValue());
}

/*
 * Test creation from a SIP uri in string format.
 */
void createFromSipUriInStringFormat() {
	constexpr string_view expectedUri = "sip:user@domain:1324;uri-parameter=value";

	const auto contact = SipHeaderContact{expectedUri};

	BC_HARD_ASSERT(contact.getNativePtr() != nullptr);
	BC_ASSERT_CPP_EQUAL(contact.getDisplayName(), "");
	BC_ASSERT_CPP_EQUAL(contact.getUri().str(), expectedUri);
	BC_ASSERT(contact.getParams().empty());
	BC_ASSERT_CPP_EQUAL(contact.getComment(), "");
	BC_ASSERT_CPP_EQUAL(contact.getQ(), "");
	BC_ASSERT_CPP_EQUAL(contact.getExpires(), "");
}

/*
 * Test creation from a flexisip::SipUri.
 */
void createFromFlexisipSipUri() {
	constexpr string_view expectedUri = "sip:user@domain:1324;uri-parameter=value";

	const auto contact = SipHeaderContact{SipUri{expectedUri}};

	BC_HARD_ASSERT(contact.getNativePtr() != nullptr);
	BC_ASSERT_CPP_EQUAL(contact.getDisplayName(), "");
	BC_ASSERT_CPP_EQUAL(contact.getUri().str(), expectedUri);
	BC_ASSERT(contact.getParams().empty());
	BC_ASSERT_CPP_EQUAL(contact.getComment(), "");
	BC_ASSERT_CPP_EQUAL(contact.getQ(), "");
	BC_ASSERT_CPP_EQUAL(contact.getExpires(), "");
}

/*
 * Test creation from a flexisip::SipUri and a list of header parameters.
 */
void createFromFlexisipSipUriAndListOfHeaderParameters() {
	constexpr string_view expectedUri = "sip:user@domain:1324;uri-parameter=value";
	const auto expectedHeaderParameter1 = SipMsgParam{"header-parameter=1"};
	const auto expectedHeaderParameter2 = SipMsgParam{"header-parameter=2"};

	const auto contact = SipHeaderContact{
	    SipUri{expectedUri},
	    expectedHeaderParameter1.str(),
	    expectedHeaderParameter2.str(),
	};

	BC_HARD_ASSERT(contact.getNativePtr() != nullptr);
	BC_ASSERT_CPP_EQUAL(contact.getDisplayName(), "");
	BC_ASSERT_CPP_EQUAL(contact.getUri().str(), expectedUri);
	BC_ASSERT_CPP_EQUAL(contact.getParams().size(), 2);
	BC_ASSERT_CPP_EQUAL(contact.getParams()[0].getParam(), expectedHeaderParameter1.getParam());
	BC_ASSERT_CPP_EQUAL(contact.getParams()[1].getParam(), expectedHeaderParameter2.getParam());
	BC_ASSERT_CPP_EQUAL(contact.getComment(), "");
	BC_ASSERT_CPP_EQUAL(contact.getQ(), "");
	BC_ASSERT_CPP_EQUAL(contact.getExpires(), "");
}

} // namespace contact

// Tests for the SIP "Expires:" header.
namespace expires {

/*
 * Test creation from a positive value.
 */
void createFromPositiveValue() {
	const int expectedExpiresValue = 600;

	const auto expires = SipHeaderExpires{expectedExpiresValue};

	BC_HARD_ASSERT(expires.getNativePtr() != nullptr);
	BC_ASSERT_CPP_EQUAL(expires.getDate(), 0);
	BC_ASSERT_CPP_EQUAL(expires.getDelta(), expectedExpiresValue);
}

/*
 * Test creation from a negative value.
 */
void createFromNegativeValue() {
	BC_ASSERT_THROWN(SipHeaderExpires{-1}, FlexisipException);
}

} // namespace expires

TestSuite _("sofiasip::SipHeader",
            {
                CLASSY_TEST(createSipMsgParam),
                CLASSY_TEST(createSipMsgParamWithIllFormattedParameter),

                CLASSY_TEST(contact::createFromFormattedHeaderWithDisplayName),
                CLASSY_TEST(contact::createFromFormattedHeaderWithoutDisplayName),
                CLASSY_TEST(contact::createFromSipUriInStringFormat),
                CLASSY_TEST(contact::createFromFlexisipSipUri),
                CLASSY_TEST(contact::createFromFlexisipSipUriAndListOfHeaderParameters),

                CLASSY_TEST(expires::createFromPositiveValue),
                CLASSY_TEST(expires::createFromNegativeValue),
            });

} // namespace

} // namespace flexisip::tester