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

#include "nat/contact-correction-strategy.hh"

#include <memory>

#include <sofia-sip/msg.h>

#include "flexisip/logmanager.hh"

#include "utils/nat-test-helper.hh"
#include "utils/string-formatter.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace sofiasip;

namespace flexisip::tester {

using RqSipEv = RequestSipEvent;
using RsSipEv = ResponseSipEvent;

namespace {

struct Helper : public NatTestHelper {
	static shared_ptr<MsgSip>
	getRegister(bool hasContact, const std::string& contactUrlParams = "", const std::string& contactParams = "") {
		StringFormatter contactFormatter{
		    "REGISTER sip:user@sip.example.org SIP/2.0\r\n"
		    "Via: SIP/2.0/TCP 10.0.2.10:5678;branch=z9hG4bK-3908207663;rport=8765;received=82.65.220.100\r\n"
		    "To: <sip:user@sip.example.org>\r\n"
		    "From: <sip:user@sip.example.org>;tag=465687829\r\n"
		    "Call-ID: stub-id.\r\n"
		    "{contact}"
		    "CSeq: 1 REGISTER\r\n"
		    "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO\r\n"
		    "Content-Type: application/sdp\r\n"};

		StringFormatter contactParameterFormatter{contactFormatter.format({
		    {"contact",
		     (hasContact ? "Contact: <sip:user@sip.example.org;transport=tcp{contactUrlParams}>{contactParams}\r\n"
		                 : "")},
		})};
		const auto request = contactParameterFormatter.format({
		    {"contactUrlParams", contactUrlParams},
		    {"contactParams", contactParams},
		});

		return make_shared<MsgSip>(0, request);
	}

	ContactCorrectionStrategy::Helper mHelper{"verified"};
};

/*
 * Test "Contact" header does not need to be fixed if it does not exist.
 */
void contactNeedsToBeFixedNoContact() {
	const Helper helper{};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getRegister(false), helper.mTport);

	BC_ASSERT(helper.mHelper.contactNeedsToBeFixed(nullptr, event) == false);
}

/*
 * Test "Contact" header should not be fixed if it contains the "verified" url parameter.
 */
void contactNeedsToBeFixedContactUrlContainsContactParameter() {
	const Helper helper{};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getRegister(true, ";verified"), helper.mTport);

	BC_ASSERT(helper.mHelper.contactNeedsToBeFixed(nullptr, event) == false);
}

/*
 * Test "Contact" header should not be fixed if it contains the "gr" url parameter.
 */
void contactNeedsToBeFixedContactUrlContainsGrParameter() {
	const Helper helper{};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getRegister(true, ";gr"), helper.mTport);

	BC_ASSERT(helper.mHelper.contactNeedsToBeFixed(nullptr, event) == false);
}

/*
 * Test "Contact" header should not be fixed if it contains "isFocus" header value parameter.
 */
void contactNeedsToBeFixedContactContainsIsFocusParameter() {
	const Helper helper{};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getRegister(true, "", "isFocus"), helper.mTport);

	BC_ASSERT(helper.mHelper.contactNeedsToBeFixed(nullptr, event) == false);
}

/*
 * Test "Contact" header should not be fixed if the Agent's internal transport is the same as the primary transport used
 * by the SIP request.
 */
void contactNeedsToBeFixedTransportIsSameAsInternalTransport() {
	const Helper helper{};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getRegister(true), nullptr);

	BC_ASSERT(helper.mHelper.contactNeedsToBeFixed(nullptr, event) == false);
}

void contactNeedsToBeFixed() {
	const Helper helper{};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getRegister(true), helper.mTport);

	BC_ASSERT(helper.mHelper.contactNeedsToBeFixed(nullptr, event) == true);
}

TestSuite _("NatTraversalStrategy::ContactCorrection::Helper",
            {
                TEST_NO_TAG_AUTO_NAMED(contactNeedsToBeFixedNoContact),
                TEST_NO_TAG_AUTO_NAMED(contactNeedsToBeFixedContactUrlContainsContactParameter),
                TEST_NO_TAG_AUTO_NAMED(contactNeedsToBeFixedContactUrlContainsGrParameter),
                TEST_NO_TAG_AUTO_NAMED(contactNeedsToBeFixedContactContainsIsFocusParameter),
                TEST_NO_TAG_AUTO_NAMED(contactNeedsToBeFixedTransportIsSameAsInternalTransport),
                TEST_NO_TAG_AUTO_NAMED(contactNeedsToBeFixed),
            });

} // namespace

} // namespace flexisip::tester