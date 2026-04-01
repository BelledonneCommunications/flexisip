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

#include <sstream>

#include "flexisip/flexisip-exception.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "sofia-wrapper/nta-outgoing-transaction.hh"
#include "utils/core-assert.hh"
#include "utils/server/injected-module-info.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace string_literals;
using namespace sofiasip;

namespace flexisip::tester {
namespace {
InjectedHooks forceThrow{
    .onRequest =
        [](unique_ptr<RequestSipEvent>&& ev) {
	        ev.reset();
	        throw InternalError();
	        return std::move(ev);
        },
};

// Ensure an error after a move event can not lead to a crash.
void errorOnMoveEvent() {
	Server proxy{{
	                 {"module::DoSProtection/enabled", "false"},
	                 {"module::Registrar/reg-domains", "*"},
	             },
	             &forceThrow};
	proxy.start();

	stringstream request;
	request << "REGISTER sip:user@sip.example.org SIP/2.0\r\n"
	        << "Via: SIP/2.0/TCP 127.0.0.4\r\n"
	        << "From: <sip:user@sip.example.org>;tag=58c85036e4f35fa8\r\n"
	        << "To: <sip:user@sip.example.org>\r\n"
	        << "Call-ID: c82d26f4@stub-call-id\r\n"
	        << "CSeq: 20 REGISTER\r\n"
	        << "Contact: <sip:user@sip.example.org>;+sip.instance=fcm1Reg\r\n"
	        << "Expires: 3600\r\n"
	        << "Content-Length: 0\r\n";

	sofiasip::NtaAgent client{proxy.getRoot(), "sip:127.0.0.1:0"};
	auto transaction = client.createOutgoingTransaction(request.str(), "sip:127.0.0.1:"s + proxy.getFirstPort());
	CoreAssert(proxy.getRoot())
	    .wait([&transaction] {
		    FAIL_IF(!transaction->isCompleted());
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(transaction->getStatus(), 500);
}

TestSuite _("Module",
            {
                CLASSY_TEST(errorOnMoveEvent),
            });
} // namespace
} // namespace flexisip::tester