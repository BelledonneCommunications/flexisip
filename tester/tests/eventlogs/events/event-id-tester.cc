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

#include "eventlogs/events/event-id.hh"

#include "flexisip/sofia-wrapper/msg-sip.hh"

#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace sofiasip;

namespace flexisip::tester {

namespace {

/*
 * Test: event ID calculation is not sensitive to inversion of "From" and "To" header values for the same "Call-ID".
 */
void eventIdCreatedFromByeComingFromCallerOrCallee() {
	string callId{"stub-call-id"};
	string caller{"sip:caller@sip.example.org"};
	string callee{"sip:callee@sip.example.org"};

	ostringstream byeFromCaller;
	byeFromCaller << "BYE " << callee << ";gr=stub-uid SIP/2.0\r\n"
	              << "Via: SIP/2.0/UDP 1.2.3.4:1234;branch=stub-branch;rport\r\n"
	              << "From: <" << caller << ">;tag=stub-from-tag\r\n"
	              << "To: <" << callee << ">;tag=stub-to-tag\r\n"
	              << "CSeq: 22 BYE\r\n"
	              << "Call-ID: " << callId << "\r\n"
	              << "User-Agent: stub-user-agent\r\n";

	ostringstream byeFromCallee;
	byeFromCallee << "BYE " << caller << ";gr=stub-uid SIP/2.0\r\n"
	              << "Via: SIP/2.0/UDP 1.2.3.4:1234;branch=stub-branch;rport\r\n"
	              << "From: <" << callee << ">;tag=stub-from-tag\r\n"
	              << "To: <" << caller << ">;tag=stub-to-tag\r\n"
	              << "CSeq: 22 BYE\r\n"
	              << "Call-ID: " << callId << "\r\n"
	              << "User-Agent: stub-user-agent\r\n";

	const MsgSip msgFromCaller{0, byeFromCaller.str()};
	const MsgSip msgFromCallee{0, byeFromCallee.str()};

	BC_ASSERT_CPP_EQUAL(string{EventId{*msgFromCaller.getSip()}}, string{EventId{*msgFromCallee.getSip()}});
}

/*
 * Test: event ID can be computed using sip uris with empty user parts.
 */
void eventIdCreatedUsingUrisWithEmptyUserParts() {
	string callId{"stub-call-id"};
	string caller{"sip:@sip.example.org"};
	string callee{"sip:@sip.example.org"};

	ostringstream request;
	request << "BYE " << callee << ";gr=stub-uid SIP/2.0\r\n"
	        << "Via: SIP/2.0/UDP 1.2.3.4:1234;branch=stub-branch;rport\r\n"
	        << "From: <" << caller << ">;tag=stub-from-tag\r\n"
	        << "To: <" << callee << ">;tag=stub-to-tag\r\n"
	        << "CSeq: 22 BYE\r\n"
	        << "Call-ID: " << callId << "\r\n"
	        << "User-Agent: stub-user-agent\r\n";

	const MsgSip msg{0, request.str()};

	BC_ASSERT(!string{EventId{*msg.getSip()}}.empty());
}

// Test: Event id throws when constructed from an invalid id.
void invalidIdForCreation(){BC_ASSERT_THROWN(EventId("invalidId"), EventId::EventIdError)}

TestSuite _("EventId",
            {
                CLASSY_TEST(eventIdCreatedFromByeComingFromCallerOrCallee),
                CLASSY_TEST(eventIdCreatedUsingUrisWithEmptyUserParts),
                CLASSY_TEST(invalidIdForCreation),
            });

} // namespace

} // namespace flexisip::tester
