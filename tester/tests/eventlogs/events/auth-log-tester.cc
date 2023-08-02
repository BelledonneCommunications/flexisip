/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "eventlogs/events/eventlogs.hh"
#include "utils/asserts.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace flexisip::tester {
using namespace std;

/**
 * Test the AuthLog::setOrigin method (called during AuthLog constructor)
 */
void authLogSetOriginUnitTest() {
	string requestWithViaReceived{R"sip(SUBSCRIBE sip:127.0.0.1:6066;transport=tcp SIP/2.0
Via: SIP/2.0/TLS [fc00:bbbb:bbbb:bb01:d:0:4:e894]:47578;alias;branch=z9hG4bK.eWzyjulqE;rport=47572;received=2608:fcd0:bb80:403::b32e
From: <sip:test@sip.example.org;gr=urn:uuid:a5b87206-f31a-00c4-8977-1d8c88e03a76>;tag=O-NM9W5kc
To: <sip:conference-factory@sip.linphone.org>;tag=rPpljg7
CSeq: 28 SUBSCRIBE
Call-ID: XpzR6dzOLG
Max-Forwards: 70
Content-Length: 0
)sip"};

	MsgSip msgSip{0, requestWithViaReceived};
	AuthLog authLog{msgSip.getSip(), false};
	BC_ASSERT_CPP_EQUAL(authLog.getOrigin()->url_host, "[2608:fcd0:bb80:403::b32e]"s);
	BC_ASSERT_CPP_EQUAL(authLog.getOrigin()->url_port, "47572"s);
	BC_ASSERT_CPP_EQUAL(authLog.getOrigin()->url_params, "transport=TLS"s);

	string requestWithViaNoReceived{R"sip(SUBSCRIBE sip:127.0.0.1:6066;transport=tcp SIP/2.0
Via: SIP/2.0/UDP [fc00:bbbb:bbbb:bb01:d:0:4:e894]:47578;alias;branch=z9hG4bK.eWzyjulqE;rport=47572
From: <sip:test@sip.example.org;gr=urn:uuid:a5b87206-f31a-00c4-8977-1d8c88e03a76>;tag=O-NM9W5kc
To: <sip:conference-factory@sip.linphone.org>;tag=rPpljg7
CSeq: 28 SUBSCRIBE
Call-ID: XpzR6dzOLG
Max-Forwards: 70
Content-Length: 0
)sip"};

	MsgSip msgSip2{0, requestWithViaNoReceived};
	AuthLog authLog2{msgSip2.getSip(), false};
	BC_ASSERT_CPP_EQUAL(authLog2.getOrigin()->url_host, "[fc00:bbbb:bbbb:bb01:d:0:4:e894]"s);
	BC_ASSERT_CPP_EQUAL(authLog2.getOrigin()->url_port, "47572"s);
	BC_ASSERT_CPP_EQUAL(authLog2.getOrigin()->url_params, "transport=UDP"s);

	string requestWithViaNoReceivedNoRPort{R"sip(SUBSCRIBE sip:127.0.0.1:6066;transport=tcp SIP/2.0
Via: SIP/2.0/TCP [fc00:bbbb:bbbb:bb02:d:0:4:e894]:47578;alias;branch=z9hG4bK.eWzyjulqE
From: <sip:test@sip.example.org;gr=urn:uuid:a5b87206-f31a-00c4-8977-1d8c88e03a76>;tag=O-NM9W5kc
To: <sip:conference-factory@sip.linphone.org>;tag=rPpljg7
CSeq: 28 SUBSCRIBE
Call-ID: XpzR6dzOLG
Max-Forwards: 70
Content-Length: 0
)sip"};

	MsgSip msgSip3{0, requestWithViaNoReceivedNoRPort};
	AuthLog authLog3{msgSip3.getSip(), false};
	BC_ASSERT_CPP_EQUAL(authLog3.getOrigin()->url_host, "[fc00:bbbb:bbbb:bb02:d:0:4:e894]"s);
	BC_ASSERT_CPP_EQUAL(authLog3.getOrigin()->url_port, "47578"s);
	BC_ASSERT_CPP_EQUAL(authLog3.getOrigin()->url_params, "transport=TCP"s);
};

namespace {
TestSuite _("AuthLog unit test",
            {
                CLASSY_TEST(authLogSetOriginUnitTest),
            });
} // namespace

} // namespace flexisip::tester