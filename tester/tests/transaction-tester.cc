/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <chrono>
#include <string>

#include "bctoolbox/tester.h"
#include "linphone++/enums.hh"

#include "flexisip/utils/sip-uri.hh"

#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace flexisip::tester {
namespace {

using namespace std;

// Test that the Reason header of a CANCEL is correctly forwarded
// when sent through an OutgoingTransaction *without* a ForkContext
void cancelReasonIsForwarded() {
	SipUri calleeAddress;
	Server proxy{{
	                 // Requesting bind on port 0 to let the kernel find any available port
	                 {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	                 {"module::MediaRelay/enabled", "true"},        // Creates an IncomingTransaction for all INVITES
	                 {"module::MediaRelay/prevent-loops", "false"}, // Allow loopback to localnetwork
	}};
	proxy.start();
	auto builder = proxy.clientBuilder();
	// Prevent creation of ForkContext
	builder.setRegistration(OnOff::Off);

	auto canceller = builder.build("sip:cancel-caller@sip.example.org");
	canceller.setRoute("sip:127.0.0.1", proxy.getFirstPort());
	auto cancellee = builder.build("sip:cancel-callee@sip.example.org");
	cancellee.setRoute("sip:127.0.0.1", proxy.getFirstPort());

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

	const auto outgoingCall = canceller.invite(calleeAddress.str());
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
	    .iterateUpTo(10,
	                 [&incomingCall, &outgoingCall] {
		                 FAIL_IF(incomingCall.getState() != linphone::Call::State::Released);
		                 FAIL_IF(outgoingCall->getState() != linphone::Call::State::Released);
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();

	BC_ASSERT_ENUM_EQUAL(incomingCall.getState(), linphone::Call::State::Released);
	BC_ASSERT_ENUM_EQUAL(incomingCall.getReason(), reason); // Reason forwarded correctly
}

TestSuite _("transaction",
            {
                CLASSY_TEST(cancelReasonIsForwarded),
            });
} // namespace
} // namespace flexisip::tester
