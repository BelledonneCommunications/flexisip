/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <map>
#include <memory>
#include <string>

#include "bctoolbox/tester.h"

#include "linphone++/call.hh"

#include "utils/asserts.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip {
namespace tester {

void video_is_received_by_caller_in_early_media() {
	const auto server = make_shared<Server>(map<string, string>{{
	    {"module::MediaRelay/enabled", "true"},
	    {"module::MediaRelay/prevent-loops", "false"}, // Allow loopback to localnetwork
	    {"global/transports", "sip:127.0.0.1:5861;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	}});
	server->start();
	const auto pauline = ClientBuilder("sip:pauline@sip.example.org").useMireAsCamera().registerTo(server);
	const auto clemence = ClientBuilder("sip:clemence@sip.example.org").useMireAsCamera().registerTo(server);
	CoreAssert asserter({pauline.getCore(), clemence.getCore()}, server->getAgent());
	const auto params = pauline.getCore()->createCallParams(nullptr);
	params->enableEarlyMediaSending(true);
	params->enableVideo(true);

	const auto paulineCall = pauline.invite(clemence, params);
	if (!BC_ASSERT_TRUE(clemence.hasReceivedCallFrom(pauline))) {
		return;
	}
	const auto clemenceCall = clemence.getCore()->getCurrentCall();
	clemenceCall->acceptEarlyMedia();

	asserter
	    .iterateUpTo(10,
	                 [&paulineCall = *paulineCall, &clemenceCall = *clemenceCall] {
		                 FAIL_IF(clemenceCall.getState() != linphone::Call::State::IncomingEarlyMedia);
		                 FAIL_IF(paulineCall.getState() != linphone::Call::State::OutgoingEarlyMedia);
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();
	BC_ASSERT_ENUM_EQUAL(paulineCall->getState(), linphone::Call::State::OutgoingEarlyMedia);
	BC_ASSERT_ENUM_EQUAL(clemenceCall->getState(), linphone::Call::State::IncomingEarlyMedia);

	asserter
	    .iterateUpTo(90,
	                 [&paulineCall] {
		                 FAIL_IF(paulineCall->getVideoStats()->getDownloadBandwidth() == 0.);
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();
	BC_ASSERT_NOT_EQUAL(clemenceCall->getVideoStats()->getUploadBandwidth(), 0., float, "%f");
	BC_ASSERT_NOT_EQUAL(clemenceCall->getVideoStats()->getDownloadBandwidth(), 0., float, "%f");
	BC_ASSERT_NOT_EQUAL(paulineCall->getVideoStats()->getUploadBandwidth(), 0., float, "%f");
	BC_ASSERT_NOT_EQUAL(paulineCall->getVideoStats()->getDownloadBandwidth(), 0., float, "%f");
}

namespace {
TestSuite _("MediaRelay",
            {
                TEST_NO_TAG_AUTO_NAMED(video_is_received_by_caller_in_early_media),
            });
}
} // namespace tester
} // namespace flexisip
