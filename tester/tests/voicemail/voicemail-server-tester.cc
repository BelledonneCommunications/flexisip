/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "tester.hh"
#include "utils/asserts.hh"
#include "utils/client-builder.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "voicemail/voicemail-server.hh"
#include "utils/audio/wave.hh"

using namespace std;
using namespace flexisip;
using namespace flexisip::tester;

namespace {



/**
 * Check that when a call is received:
 * - The call is answered by the server
 * - The server sends audio data
 * - The server ends the call after playing its audio file
 */
void answerCallThenHangUp() {
	const TmpDir tmpDir{"voicemail"};
	const auto audioFile = createShortAudioFile(tmpDir);

	Server server{{
	    {"global/transports", "sip:127.0.0.1:6066;transport=tcp"}, // Useful for clientBuilder setServerAddress()
	    {"voicemail-server/transport", "sip:127.0.0.1:6066;transport=tcp"},
	    {"voicemail-server/announcement-file-path", audioFile},
	}};
	const auto& agent = *server.getAgent();
	auto voicemail = make_shared<VoicemailServer>(agent.getRoot(), server.getConfigManager());
	voicemail->init();
	ClientBuilder clientBuilder{agent};
	clientBuilder.setRegistration(OnOff::Off);
	const auto caller = clientBuilder.build("caller@sip.example.org");
	const auto callParams = caller.getCore()->createCallParams(nullptr);
	CoreAssert asserter{caller, voicemail};
	const auto call = caller.invite("sip:flexisip-voicemail@sip.example.org", callParams);
	BC_HARD_ASSERT(call != nullptr);
	bool wasAnswered{}, audioReceived{};

	wasAnswered = asserter
	                  .waitUntil(3s,
	                             [&call, &wasAnswered, &audioReceived] {
		                             const auto state = call->getState();

		                             wasAnswered |= (state == linphone::Call::State::StreamsRunning);
		                             FAIL_IF(!wasAnswered);
		                             // With empty audio content the download bandwidth is 23.2816
		                             audioReceived |= (call->getAudioStats()->getDownloadBandwidth() > 25);
		                             FAIL_IF(!audioReceived);
		                             return LOOP_ASSERTION(wasAnswered && state >= linphone::Call::State::End);
	                             })
	                  .assert_passed();

	std::ignore = voicemail->stop();
}

TestSuite _{
    "Voicemail",
    {
        CLASSY_TEST(answerCallThenHangUp),
    },
};
} // namespace
