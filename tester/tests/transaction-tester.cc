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

#include "transaction.hh"

#include <stdexcept>
#include <string>

#include "sofia-sip/sip.h"

#include "bctoolbox/tester.h"
#include "linphone++/enums.hh"

#include "flexisip/utils/sip-uri.hh"

#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/injected-module.hh"
#include "utils/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace flexisip::tester {
namespace {

// Test that the Reason header of a CANCEL is correcly forwarded
// when sent through an OutgoingTransaction *without* a ForkContext
void cancelReasonIsForwarded() {
	// Fake an intermediate proxy forwarding the requests from the caller
	const SipUri magicAddress{"sip:magic@sip.example.org"};
	SipUri calleeAddress;
	InjectedHooks hooks{{
	    .onRequest = // Replace the magic request URI with the fully qualified address of the callee
	    [&magicAddress, &calleeAddress](const std::shared_ptr<RequestSipEvent>& requestEvent) {
		    const auto* sip = requestEvent->getSip();
		    auto* requestUri = sip->sip_request->rq_url;
		    if (magicAddress.rfc3261Compare(requestUri)) {
			    *requestUri = *calleeAddress.get();
		    }
	    },
	}};
	Server proxy{{
	                 // Requesting bind on port 0 to let the kernel find any available port
	                 {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	                 {"module::MediaRelay/enabled", "true"},        // Creates an IncomingTransaction for all INVITES
	                 {"module::MediaRelay/prevent-loops", "false"}, // Allow loopback to localnetwork
	             },
	             &hooks};
	proxy.start();
	auto builder = proxy.clientBuilder();
	// Prevent creation of ForkContext
	builder.setRegistration(OnOff::Off);
	const auto canceller = builder.build("sip:cancel-caller@sip.example.org");
	const auto cancellee = builder.build("sip:cancel-callee@sip.example.org");
	// Reconstruct callee's local address
	calleeAddress = SipUri("sip:" + cancellee.getMe()->getUsername() +
	                       "@127.0.0.1:" + std::to_string(cancellee.getTcpPort()) + ";transport=tcp");
	const auto reason = linphone::Reason::DoNotDisturb;
	const auto cancelInfo = linphone::Factory::get()->createErrorInfo();
	cancelInfo->setProtocol("SIP");
	// Unfortunately setting the reason is not sufficient (and practically useless),
	// the important part is the protocol code
	cancelInfo->setReason(reason);
	cancelInfo->setProtocolCode(600 /* "Busy Everywhere" */);
	CoreAssert asserter{canceller, cancellee, proxy};

	// The magic address prevents the client from bypassing the proxy and sending the INVITE directly to the callee.
	// This is necessary because the Linphone SDK does not let you send an INVITE to a different URI than the To header.
	const auto outgoingCall = canceller.invite(magicAddress.str());
	asserter
	    .iterateUpTo(5,
	                 [&outgoingCall = *outgoingCall] {
		                 FAIL_IF(outgoingCall.getState() != linphone::Call::State::OutgoingRinging);
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();
	const auto incomingCall = cancellee.getCurrentCall().value();
	outgoingCall->terminateWithErrorInfo(cancelInfo);
	asserter
	    .iterateUpTo(2,
	                 [&incomingCall] {
		                 FAIL_IF(incomingCall.getState() != linphone::Call::State::End);
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();

	BC_ASSERT_ENUM_EQUAL(incomingCall.getState(), linphone::Call::State::End);
	BC_ASSERT_ENUM_EQUAL(incomingCall.getReason(), reason); // Reason forwarded correctly
}

TestSuite _("transaction",
            {
                CLASSY_TEST(cancelReasonIsForwarded),
            });
} // namespace
} // namespace flexisip::tester
