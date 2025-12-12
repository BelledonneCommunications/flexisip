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

#include <nghttp2/asio_http2_server.h>

#include "flexiapi/schemas/account/account.hh"
#include "flexiapi/schemas/voicemail/slot-creation.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "tester.hh"
#include "utils/asserts.hh"
#include "utils/audio/wave.hh"
#include "utils/client-builder.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/http-mock/http-mock.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "voicemail/voicemail-server.hh"

using namespace std;
namespace flexisip::tester {
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
	const TmpDir tmpStorageDir{"voicemail-storage"};

	Server server{{
	    {"global/transports", "sip:127.0.0.1"},
	    {"voicemail-server/transport", "sip:flexisip-voicemail@localhost:0;maddr=127.0.0.1;transport=tcp"},
	    {"voicemail-server/default-announcement-path", audioFile},
	    {"voicemail-server/voicemail-announcement-path", audioFile},
	    {"global::flexiapi/url", "https://127.0.0.1:443"},
	}};
	const auto& agent = server.getAgent();

	auto voicemail = make_shared<VoicemailServer>(agent->getRoot(), server.getConfigManager());
	voicemail->init();

	ClientBuilder clientBuilder{"sip:flexisip-voicemail@localhost:" + to_string(voicemail->getTcpPort()) +
	                            ";maddr=127.0.0.1;transport=tcp"};
	clientBuilder.setRegistration(OnOff::Off);
	const auto caller = clientBuilder.build("caller@sip.example.org");
	const auto callParams = caller.getCore()->createCallParams(nullptr);

	CoreAssert asserter{caller, voicemail, agent->getRoot()};
	const auto call =
	    caller.invite("sip:flexisip-voicemail@localhost;target=sip:test-target%40sip.test.org", callParams);
	BC_HARD_ASSERT(call != nullptr);
	bool wasAnswered{}, audioReceived{};

	wasAnswered = asserter
	                  .iterateUpTo(
	                      10,
	                      [&call, &wasAnswered, &audioReceived] {
		                      const auto state = call->getState();

		                      wasAnswered |= (state == linphone::Call::State::StreamsRunning);
		                      FAIL_IF(!wasAnswered);
		                      // With empty audio content the download bandwidth is 23.2816
		                      audioReceived |= (call->getAudioStats()->getDownloadBandwidth() > 25);
		                      FAIL_IF(!audioReceived);
		                      return LOOP_ASSERTION(state >= linphone::Call::State::End);
	                      },
	                      4s)
	                  .assert_passed();

	std::ignore = voicemail->stop();
}

void getAccountIdHandler(http_mock::HttpMock&,
                         const nghttp2::asio_http2::server::request&,
                         const nghttp2::asio_http2::server::response& res) {
	nlohmann::json account = flexiapi::Account{1234};

	res.write_head(200);
	res.end(account.dump());
}

void getSlotHandler(http_mock::HttpMock& httpMock,
                    const nghttp2::asio_http2::server::request& req,
                    const nghttp2::asio_http2::server::response& res) {
	if (req.method() != "POST") {
		res.write_head(404);
		res.end(http_mock::HttpMock::kDefaultError);
		return;
	}

	req.on_data([&httpMock, &res](const uint8_t* body, std::size_t size) {
		try {
			if (size) {
				const auto jsonBody = nlohmann::json::parse(string((char*)body, size));
				const auto slot = jsonBody.get<flexiapi::SlotCreation>();
			}
		} catch (exception& e) {
			BC_FAIL("getSlotHandler::on_data - exception while parsing json: "s + e.what());

			res.write_head(500);
			res.end();
		}

		nlohmann::json slot = {
		    {"id", "some-slot-id"},
		    {"sip_from", ""},
		    {"upload_url", "https://127.0.0.1:" + to_string(httpMock.getFirstPort()) + "/api/upload"},
		    {"max_upload_size", 13000000},
		    {"content_type", "audio/wav"},
		};

		res.write_head(200);
		res.end(slot.dump());
	});
}

void postFileHandler(http_mock::HttpMock&,
                     const nghttp2::asio_http2::server::request& req,
                     const nghttp2::asio_http2::server::response& res) {
	if (req.method() != "POST") {
		res.write_head(404);
		res.end(http_mock::HttpMock::kDefaultError);
		return;
	}

	res.write_head(200);
	res.end(http_mock::HttpMock::kDefaultResponse);
}

/**
 * Test voicemail recording and upload
 *
 * It expects all HTTP requests to succeed and no error case are checked
 */
void answerCallRecordVoicemail() {
	const TmpDir tmpDir{"voicemail"};
	const TmpDir tmpStorageDir{"voicemail-storage"};
	const auto audioFile = createShortAudioFile(tmpDir);

	bool fileUploaded{};

	std::map<std::string, http_mock::HttpMockHandler> handlers;
	handlers["/api/accounts/target@sip.test.org/search"] = getAccountIdHandler;
	handlers["/api/accounts/1234/voicemails"] = getSlotHandler;
	handlers["/api/upload"] = [&fileUploaded](http_mock::HttpMock& mock,
	                                          const nghttp2::asio_http2::server::request& req,
	                                          const nghttp2::asio_http2::server::response& res) {
		fileUploaded = true;
		postFileHandler(mock, req, res);
	};
	http_mock::HttpMock httpServer{handlers};

	const auto httpPort = httpServer.serveAsync();

	Server proxy{{
	    {"voicemail-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"voicemail-server/default-announcement-path", audioFile},
	    {"voicemail-server/voicemail-announcement-path", audioFile},
	    {"voicemail-server/voicemail-storage-path", tmpStorageDir.path()},
	    {"global::flexiapi/url", "https://127.0.0.1:" + to_string(httpPort)},
	}};
	const auto& agent = proxy.getAgent();
	LOGD_CTX("answerCallRecordVoicemail") << "Root address" << agent->getRoot().get();
	auto voicemail = make_shared<VoicemailServer>(agent->getRoot(), proxy.getConfigManager());
	try {
		voicemail->init();
	} catch (exception& e) {
		BC_FAIL("Unexpected exception during voicemail initialization: " + e.what());
	}
	ClientBuilder clientBuilder{"sip:127.0.0.1:" + to_string(voicemail->getTcpPort()) + ";transport=tcp"};
	clientBuilder.setRegistration(OnOff::Off);
	const auto caller = clientBuilder.build("caller@sip.example.org");
	const auto callParams = caller.getCore()->createCallParams(nullptr);
	// callParams->to
	CoreAssert asserter{caller, voicemail, agent->getRoot()};
	const auto call = caller.invite("sip:flexisip-voicemail@sip.test.org;target=sip:target%40sip.test.org", callParams);
	BC_HARD_ASSERT(call != nullptr);
	bool wasAnswered{}, audioReceived{};

	wasAnswered = asserter
	                  .iterateUpTo(
	                      5,
	                      [&call, &wasAnswered, &audioReceived] {
		                      const auto state = call->getState();

		                      wasAnswered |= (state == linphone::Call::State::StreamsRunning);
		                      FAIL_IF(!wasAnswered);
		                      // With empty audio content the download bandwidth is 23.2816
		                      audioReceived |= (call->getAudioStats()->getDownloadBandwidth() > 25);
		                      FAIL_IF(!audioReceived);
		                      // Wait until announce is finished
		                      return LOOP_ASSERTION(call->getAudioStats()->getDownloadBandwidth() < 23);
	                      },
	                      4s)
	                  .assert_passed();
	BC_ASSERT_CPP_EQUAL(wasAnswered, true);
	call->terminate();

	std::ignore = asserter.iterateUpTo(5, [&fileUploaded] { return LOOP_ASSERTION(fileUploaded); }, 2s).assert_passed();

	std::ignore = voicemail->stop();
	httpServer.forceCloseServer();
	agent->getRoot()->step(10ms); // needed to acknowledge mock server closing
}

TestSuite _{
    "Voicemail",
    {
        CLASSY_TEST(answerCallThenHangUp),
        CLASSY_TEST(answerCallRecordVoicemail),
    },
};
} // namespace
} // namespace flexisip::tester