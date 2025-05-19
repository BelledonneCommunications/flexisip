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

#include "utils/digest.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace sofiasip;

namespace flexisip::tester {

namespace {

/*
 * Test: event ID calculation is not sensitive to inversion of "From" and "To" header values for the same "Call-ID".
 *
 * This happens in BYE messages, which must still be linked to the same event
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

struct MockEvent {
	struct Url {
		const char* user;
		const char* host;
	};

	Url from;
	Url to;
	const char* callId;

	string id() const {
		auto fromStruct = sip_from_t{
		    .a_url = {url_t{
		        .url_user = from.user,
		        .url_host = from.host,
		    }},
		};
		auto toStruct = sip_to_t{
		    .a_url = {url_t{
		        .url_user = to.user,
		        .url_host = to.host,
		    }},
		};
		auto callIdStruct = sip_call_id_t{.i_id = callId};

		return EventId(sip_t{
		    .sip_from = &fromStruct,
		    .sip_to = &toStruct,
		    .sip_call_id = &callIdStruct,
		});
	}
};

/** Example of how the hash is constructed. Update it when needed
 */
void hashInputConstruction() {
	const auto expected = Sha256().compute<string>("A-from-userB-from-hostC-to-userD-to-hostE-call-id"s);

	BC_ASSERT_CPP_EQUAL((MockEvent{.from =
	                                   {
	                                       .user = "A-from-user",
	                                       .host = "B-from-host",
	                                   },
	                               .to =
	                                   {
	                                       .user = "C-to-user",
	                                       .host = "D-to-host",
	                                   },
	                               .callId = "E-call-id"}
	                         .id()),
	                    expected);
	BC_ASSERT_CPP_EQUAL((MockEvent{.from =
	                                   {
	                                       .user = "C-to-user",
	                                       .host = "D-to-host",
	                                   },
	                               .to =
	                                   {
	                                       .user = "A-from-user",
	                                       .host = "B-from-host",
	                                   },
	                               .callId = "E-call-id"}
	                         .id()),
	                    expected);
}

/** Quirks in previous implementations
 */
void collisions() {
	BC_ASSERT_CPP_NOT_EQUAL((MockEvent{.from =
	                                       {
	                                           .user = "A-from-user",
	                                           .host = "B-from-host",
	                                       },
	                                   .to =
	                                       {
	                                           .user = "C-to-user",
	                                           .host = "D-to-host",
	                                       },
	                                   .callId = "E-call-id"}
	                             .id()),
	                        (MockEvent{.from =
	                                       {
	                                           .user = "C-to-user",
	                                           .host = "F-different-host",
	                                       },
	                                   .to =
	                                       {
	                                           .user = "A-from-user",
	                                           .host = "G-different-host",
	                                       },
	                                   .callId = "E-call-id"}
	                             .id()));
}

TestSuite _("EventId",
            {
                CLASSY_TEST(eventIdCreatedFromByeComingFromCallerOrCallee),
                CLASSY_TEST(eventIdCreatedUsingUrisWithEmptyUserParts),
                CLASSY_TEST(hashInputConstruction),
                CLASSY_TEST(collisions),
            });

} // namespace

} // namespace flexisip::tester
