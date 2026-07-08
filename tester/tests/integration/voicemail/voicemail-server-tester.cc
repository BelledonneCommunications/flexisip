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

#include "voicemail/voicemail-server.hh"

#include "flexiapi/config.hh"
#include "flexiapi/schemas/schemas-json.hh"
#include "flexiapi/schemas/voicemail/slot-creation-json.hh"
#include "flexiapi/schemas/voicemail/slot-creation.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "sofia-wrapper/sip-header-private.hh"
#include "utils/asserts.hh"
#include "utils/audio/wave.hh"
#include "utils/bc-utils.hh"
#include "utils/client-builder.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/http-mock/http-mock.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

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
	const auto beepFile = bcTesterRes("../share/voicemail/beep.wav");
	const TmpDir tmpStorageDir{"voicemail-storage"};

	Server server{{
	    {"global/transports", "sip:127.0.0.1"},
	    {"voicemail-server/transport", "sip:flexisip-voicemail@localhost:0;maddr=127.0.0.1;transport=tcp"},
	    {"voicemail-server/default-announcement-path", audioFile},
	    {"voicemail-server/voicemail-announcement-path", audioFile},
	    {"voicemail-server/beep-sound-path", beepFile},
	    {"voicemail-server/voicemail-storage-path", tmpStorageDir.path()},
	    {"global::flexiapi/url", "https://127.0.0.1:443"},
	}};
	const auto& agent = server.getAgent();

	auto voicemail = make_shared<VoicemailServer>(agent->getRoot(), server.getConfigManager(),
	                                              flexiapi::createClient(server.getConfigManager(), *agent->getRoot()));
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
                         const http_mock::server::Request&,
                         const http_mock::server::Response& res) {
	nlohmann::json account{}; // = flexiapi::Account{1234}; doesn't work for a reason.
	account["id"] = 1234;
	account["call_forwardings"] = nlohmann::json::array();
	account["sip_uri"] = SipUri{};

	res.writeHead(200);
	res.send(account.dump());
}

void getSlotHandler(http_mock::HttpMock& httpMock,
                    const http_mock::server::Request& req,
                    const http_mock::server::Response& res) {
	if (req.getMethod() != "POST") {
		res.writeHead(404);
		res.send(http_mock::HttpMock::kDefaultError);
		return;
	}

	req.onData([&httpMock, &res](const uint8_t* body, std::size_t size) {
		try {
			if (size) {
				const auto jsonBody = nlohmann::json::parse(string((char*)body, size));
				const auto slot = jsonBody.get<flexiapi::SlotCreation>();
			}
		} catch (exception& e) {
			BC_FAIL("getSlotHandler::on_data - exception while parsing json: "s + e.what());

			res.writeHead(500);
			res.send();
		}

		nlohmann::json slot = {
		    {"id", "some-slot-id"},
		    {"sip_from", ""},
		    {"upload_url", "https://127.0.0.1:" + to_string(httpMock.getFirstPort()) + "/api/upload"},
		    {"max_upload_size", 13000000},
		    {"content_type", "audio/wav"},
		};

		res.writeHead(200);
		res.send(slot.dump());
	});
}

void postFileHandler(http_mock::HttpMock&,
                     const http_mock::server::Request& req,
                     const http_mock::server::Response& res) {
	if (req.getMethod() != "POST") {
		res.writeHead(404);
		res.send(http_mock::HttpMock::kDefaultError);
		return;
	}

	res.writeHead(200);
	res.send(http_mock::HttpMock::kDefaultResponse);
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
	const auto beepFile = bcTesterRes("../share/voicemail/beep.wav");

	bool fileUploaded{};

	std::map<std::string, http_mock::HttpMockHandler> handlers;
	handlers["/api/accounts/target@sip.test.org/search"] = getAccountIdHandler;
	handlers["/api/accounts/1234/voicemails"] = getSlotHandler;
	handlers["/api/upload"] = [&fileUploaded](http_mock::HttpMock& mock, const http_mock::server::Request& req,
	                                          const http_mock::server::Response& res) {
		fileUploaded = true;
		postFileHandler(mock, req, res);
	};
	http_mock::HttpMock httpServer{handlers};

	const auto httpPort = httpServer.serveAsync();

	Server proxy{{
	    {"voicemail-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"voicemail-server/default-announcement-path", audioFile},
	    {"voicemail-server/voicemail-announcement-path", audioFile},
	    {"voicemail-server/beep-sound-path", beepFile},
	    {"voicemail-server/voicemail-storage-path", tmpStorageDir.path()},
	    {"global::flexiapi/url", "https://127.0.0.1:" + to_string(httpPort)},
	}};
	const auto& agent = proxy.getAgent();
	LOGD_CTX("answerCallRecordVoicemail") << "Root address" << agent->getRoot().get();
	auto voicemail = make_shared<VoicemailServer>(agent->getRoot(), proxy.getConfigManager(),
	                                              flexiapi::createClient(proxy.getConfigManager(), *agent->getRoot()));
	try {
		voicemail->init();
	} catch (exception& e) {
		BC_HARD_FAIL(("Unexpected exception during voicemail initialization: "s + e.what()).c_str());
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

void transportInitialization() {
	using namespace sofiasip;
	const TmpDir tmpDir{"voicemail"};
	const auto audioFile = createShortAudioFile(tmpDir);
	const auto beepFile = bcTesterRes("../share/voicemail/beep.wav");
	const TmpDir tmpStorageDir{"voicemail-storage"};

	Server server{{
	    {"global/transports", "sip:127.0.0.1"},
	    {"voicemail-server/transport", "sip:flexisip-voicemail@127.0.0.1:0;transport=tcp"},
	    {"voicemail-server/default-announcement-path", audioFile},
	    {"voicemail-server/voicemail-announcement-path", audioFile},
	    {"voicemail-server/beep-sound-path", beepFile},
	    {"voicemail-server/voicemail-storage-path", tmpStorageDir.path()},
	    {"global::flexiapi/url", "https://127.0.0.1:443"},
	}};
	const auto& agent = server.getAgent();
	auto suRoot = agent->getRoot();
	auto voicemail = make_shared<VoicemailServer>(agent->getRoot(), server.getConfigManager(),
	                                              flexiapi::createClient(server.getConfigManager(), *agent->getRoot()));

	try {
		voicemail->init();
	} catch (exception& e) {
		BC_HARD_FAIL(("Unexpected exception during voicemail initialization: "s + e.what()).c_str());
	}
	CoreAssert asserter{voicemail, suRoot};
	const auto tcpPort = to_string(voicemail->getTcpPort());
	const auto serverUri = "sip:127.0.0.1:" + tcpPort + ";transport=tcp";

	const auto serverUriWrongAddress = "sip:127.0.0.2:" + tcpPort + ";transport=tcp";

	// Test connection with the server.
	NtaAgent client{suRoot, "sip:user-1@127.0.0.1:0;transport=tcp"};
	const auto clientUri = "<sip:user-1@127.0.0.1:"s + client.getFirstPort() + ";transport=tcp>";
	MsgSip msg{};
	msg.makeAndInsert<SipHeaderRequest>(sip_method_options, "sip:user-2@flexisip.example.org");
	msg.makeAndInsert<SipHeaderFrom>("sip:user-1@flexisip.example.org", "stub-from-tag");
	msg.makeAndInsert<SipHeaderTo>("sip:user-2@flexisip.example.org");
	msg.makeAndInsert<SipHeaderCallID>("stub-call-id");
	msg.makeAndInsert<SipHeaderCSeq>(20u, sip_method_options);
	msg.makeAndInsert<SipHeaderContact>(clientUri);

	const auto transaction = client.createOutgoingTransaction(msg.msgAsString(), serverUri);
	asserter
	    .iterateUpTo(
	        0x20,
	        [&transaction]() { return LOOP_ASSERTION(transaction->isCompleted() and transaction->getStatus() == 200); },
	        100ms)
	    .assert_passed();

	const auto transactionWrongAddress = client.createOutgoingTransaction(msg.msgAsString(), serverUriWrongAddress);
	asserter
	    .iterateUpTo(
	        0x20,
	        [&transactionWrongAddress]() {
		        return LOOP_ASSERTION(transactionWrongAddress->isCompleted() and
		                              transactionWrongAddress->getStatus() == 503);
	        },
	        100ms)
	    .assert_passed();

	// Currently, "stop()" always  returns nullptr
	std::ignore = voicemail->stop();
}

TestSuite _{
    "Voicemail",
    {
        CLASSY_TEST(answerCallThenHangUp),
        CLASSY_TEST(answerCallRecordVoicemail),
        CLASSY_TEST(transportInitialization),
    },
};
} // namespace
} // namespace flexisip::tester