/*
 * Copyright (C) 2022 Belledonne Communications SARL
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <bctoolbox/logging.h>

#include <linphone++/linphone.hh>

#include "flexisip/agent.hh"
#include "flexisip/configmanager.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

#include "b2bua/b2bua-server.hh"
#include "conference/conference-server.hh"
#include "registration-events/client.hh"
#include "registration-events/server.hh"
#include "tester.hh"
#include "utils/asserts.hh"

using namespace std;
using namespace linphone;
using namespace flexisip;

namespace b2buatester {
// B2bua is configured to set media encryption according to a regex on the callee URI
// define uri to match each of the possible media encryption
static constexpr auto srtpUri = "sip:b2bua_srtp@sip.example.org";
static constexpr auto zrtpUri = "sip:b2bua_zrtp@sip.example.org";
static constexpr auto dtlsUri = "sip:b2bua_dtlsp@sip.example.org";

class B2buaServer : public Server {
private:
	std::shared_ptr<flexisip::B2buaServer> mB2buaServer;

public:
	explicit B2buaServer(const std::string& configFile = "") : Server(configFile) {
		// Configure B2bua Server
		auto* b2buaServerConf = GenericManager::get()->getRoot()->get<GenericStruct>("b2bua-server");
		// b2bua server needs an outbound proxy to route all sip messages to the proxy, set it to the first transport
		// of the proxy.
		auto proxyTransports =
		    GenericManager::get()->getRoot()->get<GenericStruct>("global")->get<ConfigStringList>("transports")->read();
		b2buaServerConf->get<ConfigString>("outbound-proxy")->set(proxyTransports.front());
		// need a writable dir to store DTLS-SRTP self signed certificate
		b2buaServerConf->get<ConfigString>("data-directory")->set(bc_tester_get_writable_dir_prefix());

		mB2buaServer = make_shared<flexisip::B2buaServer>(this->getRoot());
		mB2buaServer->init();

		// Configure module b2bua
		GenericManager::get()
		    ->getRoot()
		    ->get<GenericStruct>("module::B2bua")
		    ->get<ConfigString>("b2bua-server")
		    ->set(b2buaServerConf->get<ConfigString>("transport")->read());

		// Start proxy
		this->start();
	}
	~B2buaServer() {
		mB2buaServer->stop();
	}
};

// Basic call not using the B2bua server
static void basic() {
	// Create a server and start it
	auto server = std::make_shared<Server>("/config/flexisip_b2bua.conf");
	// flexisip_b2bua config file enables the module B2bua in proxy, disable it for this basic test
	GenericManager::get()->getRoot()->get<GenericStruct>("module::B2bua")->get<ConfigBoolean>("enabled")->set("false");
	server->start();
	{
		// create clients and register them on the server
		// do it in a block to make sure they are destroyed before the server

		// creation and registration in one call
		auto marie = std::make_shared<CoreClient>("sip:marie@sip.example.org", server);
		// creation then registration
		auto pauline = std::make_shared<CoreClient>("sip:pauline@sip.example.org");
		BC_ASSERT_PTR_NULL(
		    pauline->getAccount()); // Pauline account in not available yet, only after registration on the server
		pauline->registerTo(server);
		BC_ASSERT_PTR_NOT_NULL(pauline->getAccount()); // Pauline account in now available

		// marie calls pauline with default call params
		marie->call(pauline);
		pauline->endCurrentCall(marie); // endCurrentCall will fail if there is no current call

		// marie calls pauline with call params
		auto callParams = marie->getCore()->createCallParams(nullptr);
		callParams->setMediaEncryption(linphone::MediaEncryption::ZRTP);
		if (!BC_ASSERT_PTR_NOT_NULL(marie->call(pauline, callParams)))
			return; // stop the test if we fail to establish the call
		BC_ASSERT_TRUE(marie->getCore()->getCurrentCall()->getCurrentParams()->getMediaEncryption() ==
		               linphone::MediaEncryption::ZRTP);
		BC_ASSERT_TRUE(pauline->getCore()->getCurrentCall()->getCurrentParams()->getMediaEncryption() ==
		               linphone::MediaEncryption::ZRTP);
		marie->endCurrentCall(pauline);

		// marie calls with video pauline with default call params
		// This could also be achieved by setting enableVideo(true) in the callParams given to the call function
		if (!BC_ASSERT_PTR_NOT_NULL(marie->callVideo(pauline))) return;
		pauline->endCurrentCall(marie);
	}
}

/**
 * Scenario: Marie calls Pauline
 * encryptions on outgoing and incoming calls are checked
 * When video is enabled, perform
 * 		- a call with video enabled form start
 * 		. a call audio only updated to add video and then remove it
 *
 * @param[in] marieName			sip URI of user Marie
 * @param[in] marieEncryption	MediaEncryption used for outgoing call
 * @param[in] paulineName		sip URI of user Pauline
 * @param[in] paulineEncryption	MediaEncryption expected for incoming call (not enforced at callee callParams level)
 * @param[in] video				perform video call when true
 *
 * @return true when everything went well
 */
static bool mixedEncryption(const std::string& marieName,
                            linphone::MediaEncryption marieEncryption,
                            const std::string& paulineName,
                            linphone::MediaEncryption paulineEncryption,
                            bool video) {
	// initialize and start the proxy and B2bua server
	auto server = std::make_shared<B2buaServer>("/config/flexisip_b2bua.conf");
	{
		// Create and register clients
		auto marie = std::make_shared<CoreClient>(marieName, server);
		auto pauline = std::make_shared<CoreClient>(paulineName, server);

		// Marie calls Pauline
		auto marieCallParams = marie->getCore()->createCallParams(nullptr);
		marieCallParams->setMediaEncryption(marieEncryption);
		marieCallParams->enableVideo(video);
		if (!BC_ASSERT_PTR_NOT_NULL(marie->call(pauline, marieCallParams))) return false;
		BC_ASSERT_TRUE(marie->getCore()->getCurrentCall()->getCurrentParams()->getMediaEncryption() == marieEncryption);
		BC_ASSERT_TRUE(pauline->getCore()->getCurrentCall()->getCurrentParams()->getMediaEncryption() ==
		               paulineEncryption);
		// we're going through a back-2-back user agent, so the callIds are not the same
		BC_ASSERT_TRUE(marie->getCore()->getCurrentCall()->getCallLog()->getCallId() !=
		               pauline->getCore()->getCurrentCall()->getCallLog()->getCallId());
		if (!BC_ASSERT_TRUE(marie->endCurrentCall(pauline))) return false;

		// updating call to add and remove video
		if (video) {
			auto marieCallParams = marie->getCore()->createCallParams(nullptr);
			marieCallParams->setMediaEncryption(marieEncryption);
			// Call audio only
			auto marieCall = marie->call(pauline, marieCallParams);
			if (!BC_ASSERT_PTR_NOT_NULL(marieCall)) return false;
			auto paulineCall = pauline->getCore()->getCurrentCall();
			BC_ASSERT_TRUE(marieCall->getCurrentParams()->getMediaEncryption() == marieEncryption);
			BC_ASSERT_TRUE(paulineCall->getCurrentParams()->getMediaEncryption() == paulineEncryption);
			BC_ASSERT_FALSE(marieCall->getCurrentParams()->videoEnabled());
			BC_ASSERT_FALSE(paulineCall->getCurrentParams()->videoEnabled());
			// update call to add video
			marieCallParams->enableVideo(true);
			if (!BC_ASSERT_TRUE(marie->callUpdate(pauline, marieCallParams)))
				return false; // The callUpdate checks that video is enabled
			BC_ASSERT_TRUE(marieCall->getCurrentParams()->getMediaEncryption() == marieEncryption);
			BC_ASSERT_TRUE(paulineCall->getCurrentParams()->getMediaEncryption() == paulineEncryption);
			// update call to remove video
			marieCallParams->enableVideo(false);
			if (!BC_ASSERT_TRUE(marie->callUpdate(pauline, marieCallParams)))
				return false; // The callUpdate checks that video is disabled
			BC_ASSERT_TRUE(marieCall->getCurrentParams()->getMediaEncryption() == marieEncryption);
			BC_ASSERT_TRUE(paulineCall->getCurrentParams()->getMediaEncryption() == paulineEncryption);
			if (!BC_ASSERT_TRUE(marie->endCurrentCall(pauline))) return false;
		}
	}
	return true;
}

static void forward() {
	// Use uri not matching anything in the b2bua server config, so ougoing media encryption shall match incoming one
	// SDES
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::SRTP,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::SRTP, false));
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::SRTP,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::SRTP, true));
	// ZRTP
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::ZRTP,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::ZRTP, false));
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::ZRTP,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::ZRTP, true));
	// DTLS
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::DTLS,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::DTLS, false));
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::DTLS,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::DTLS, true));
	// None
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::None,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::None, false));
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::None,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::None, true));
}

static void sdes2zrtp() {
	// sdes to zrtp
	BC_ASSERT_TRUE(
	    mixedEncryption(srtpUri, linphone::MediaEncryption::SRTP, zrtpUri, linphone::MediaEncryption::ZRTP, false));
	BC_ASSERT_TRUE(
	    mixedEncryption(srtpUri, linphone::MediaEncryption::SRTP, zrtpUri, linphone::MediaEncryption::ZRTP, true));
	// zrtp to sdes
	BC_ASSERT_TRUE(
	    mixedEncryption(zrtpUri, linphone::MediaEncryption::ZRTP, srtpUri, linphone::MediaEncryption::SRTP, false));
	BC_ASSERT_TRUE(
	    mixedEncryption(zrtpUri, linphone::MediaEncryption::ZRTP, srtpUri, linphone::MediaEncryption::SRTP, true));
}

static void sdes2dtls() {
	// sdes to dtls
	BC_ASSERT_TRUE(
	    mixedEncryption(srtpUri, linphone::MediaEncryption::SRTP, dtlsUri, linphone::MediaEncryption::DTLS, false));
	BC_ASSERT_TRUE(
	    mixedEncryption(srtpUri, linphone::MediaEncryption::SRTP, dtlsUri, linphone::MediaEncryption::DTLS, true));
	// dtls to sdes
	BC_ASSERT_TRUE(
	    mixedEncryption(dtlsUri, linphone::MediaEncryption::DTLS, srtpUri, linphone::MediaEncryption::SRTP, false));
	BC_ASSERT_TRUE(
	    mixedEncryption(dtlsUri, linphone::MediaEncryption::DTLS, srtpUri, linphone::MediaEncryption::SRTP, true));
}

static void zrtp2dtls() {
	// zrtp to dtls
	BC_ASSERT_TRUE(
	    mixedEncryption(zrtpUri, linphone::MediaEncryption::ZRTP, dtlsUri, linphone::MediaEncryption::DTLS, false));
	BC_ASSERT_TRUE(
	    mixedEncryption(zrtpUri, linphone::MediaEncryption::SRTP, dtlsUri, linphone::MediaEncryption::DTLS, true));
	// dtls to zrtp
	BC_ASSERT_TRUE(
	    mixedEncryption(dtlsUri, linphone::MediaEncryption::DTLS, zrtpUri, linphone::MediaEncryption::ZRTP, false));
	BC_ASSERT_TRUE(
	    mixedEncryption(dtlsUri, linphone::MediaEncryption::DTLS, zrtpUri, linphone::MediaEncryption::ZRTP, true));
}

static void sdes2sdes256(bool video) {
	// initialize and start the proxy and B2bua server
	auto server = std::make_shared<B2buaServer>("/config/flexisip_b2bua.conf");
	{
		// Create and register clients
		auto sdes = std::make_shared<CoreClient>("sip:b2bua_srtp@sip.example.org", server);
		auto sdes256 = std::make_shared<CoreClient>("sip:b2bua_srtp256@sip.example.org", server);
		auto sdes256gcm = std::make_shared<CoreClient>("sip:b2bua_srtpgcm@sip.example.org", server);

		// Call from SDES to SDES256
		auto sdesCallParams = sdes->getCore()->createCallParams(nullptr);
		sdesCallParams->setMediaEncryption(linphone::MediaEncryption::SRTP);
		sdesCallParams->setSrtpSuites(
		    {linphone::SrtpSuite::AESCM128HMACSHA180, linphone::SrtpSuite::AESCM128HMACSHA132});
		sdesCallParams->enableVideo(video);
		if (!BC_ASSERT_PTR_NOT_NULL(sdes->call(sdes256, sdesCallParams))) return;
		BC_ASSERT_TRUE(sdes->getCore()->getCurrentCall()->getCurrentParams()->getMediaEncryption() ==
		               linphone::MediaEncryption::SRTP);
		BC_ASSERT_TRUE(sdes->getCore()->getCurrentCall()->getCurrentParams()->getSrtpSuites().front() ==
		               linphone::SrtpSuite::AESCM128HMACSHA180);
		BC_ASSERT_TRUE(sdes256->getCore()->getCurrentCall()->getCurrentParams()->getMediaEncryption() ==
		               linphone::MediaEncryption::SRTP);
		BC_ASSERT_TRUE(sdes256->getCore()->getCurrentCall()->getCurrentParams()->getSrtpSuites().front() ==
		               linphone::SrtpSuite::AES256CMHMACSHA180);
		sdes->endCurrentCall(sdes256);

		// Call from SDES256 to SDES
		auto sdes256CallParams = sdes256->getCore()->createCallParams(nullptr);
		sdes256CallParams->setMediaEncryption(linphone::MediaEncryption::SRTP);
		sdes256CallParams->setSrtpSuites(
		    {linphone::SrtpSuite::AES256CMHMACSHA180, linphone::SrtpSuite::AES256CMHMACSHA132});
		sdes256CallParams->enableVideo(video);
		if (!BC_ASSERT_PTR_NOT_NULL(sdes256->call(sdes, sdes256CallParams))) return;
		BC_ASSERT_TRUE(sdes->getCore()->getCurrentCall()->getCurrentParams()->getMediaEncryption() ==
		               linphone::MediaEncryption::SRTP);
		BC_ASSERT_TRUE(sdes->getCore()->getCurrentCall()->getCurrentParams()->getSrtpSuites().front() ==
		               linphone::SrtpSuite::AESCM128HMACSHA180);
		BC_ASSERT_TRUE(sdes256->getCore()->getCurrentCall()->getCurrentParams()->getMediaEncryption() ==
		               linphone::MediaEncryption::SRTP);
		BC_ASSERT_TRUE(sdes256->getCore()->getCurrentCall()->getCurrentParams()->getSrtpSuites().front() ==
		               linphone::SrtpSuite::AES256CMHMACSHA180);
		sdes->endCurrentCall(sdes256);

		// Call from SDES256 to SDES256gcm
		sdes256CallParams = sdes256->getCore()->createCallParams(nullptr);
		sdes256CallParams->setMediaEncryption(linphone::MediaEncryption::SRTP);
		sdes256CallParams->setSrtpSuites(
		    {linphone::SrtpSuite::AES256CMHMACSHA180, linphone::SrtpSuite::AES256CMHMACSHA132});
		sdes256CallParams->enableVideo(video);
		if (!BC_ASSERT_PTR_NOT_NULL(sdes256->call(sdes256gcm, sdes256CallParams))) return;
		BC_ASSERT_TRUE(sdes256gcm->getCore()->getCurrentCall()->getCurrentParams()->getMediaEncryption() ==
		               linphone::MediaEncryption::SRTP);
		BC_ASSERT_TRUE(sdes256gcm->getCore()->getCurrentCall()->getCurrentParams()->getSrtpSuites().front() ==
		               linphone::SrtpSuite::AEADAES256GCM);
		BC_ASSERT_TRUE(sdes256->getCore()->getCurrentCall()->getCurrentParams()->getMediaEncryption() ==
		               linphone::MediaEncryption::SRTP);
		BC_ASSERT_TRUE(sdes256->getCore()->getCurrentCall()->getCurrentParams()->getSrtpSuites().front() ==
		               linphone::SrtpSuite::AES256CMHMACSHA180);
		sdes256gcm->endCurrentCall(sdes256);

	}
}

static void sdes2sdes256() {
	sdes2sdes256(false);
	sdes2sdes256(true);
}

static void videoRejected() {
	// initialize and start the proxy and B2bua server
	auto server = std::make_shared<B2buaServer>("/config/flexisip_b2bua.conf");
	{
		// Create and register clients
		auto marie = std::make_shared<CoreClient>("sip:marie@sip.example.org", server);
		auto pauline = std::make_shared<CoreClient>("sip:pauline@sip.example.org", server);

		auto marieCallParams = marie->getCore()->createCallParams(nullptr);
		marieCallParams->enableVideo(true);

		// marie call pauline, asking for video
		auto marieCall =
		    marie->getCore()->inviteAddressWithParams(pauline->getAccount()->getContactAddress(), marieCallParams);

		if (!BC_ASSERT_PTR_NOT_NULL(marieCall)) return;
		if (!BC_ASSERT_TRUE(CoreAssert({marie->getCore(), pauline->getCore()}, server->getAgent()).wait([pauline] {
			    return ((pauline->getCore()->getCurrentCall() != nullptr) &&
			            (pauline->getCore()->getCurrentCall()->getState() == linphone::Call::State::IncomingReceived));
		    }))) {
			return;
		}

		auto paulineCall = pauline->getCore()->getCurrentCall();
		if (!BC_ASSERT_PTR_NOT_NULL(paulineCall)) return;

		if (!BC_ASSERT_TRUE(CoreAssert({marie->getCore(), pauline->getCore()}, server->getAgent()).wait([marieCall] {
			    return (marieCall->getState() == linphone::Call::State::OutgoingRinging);
		    }))) {
			return;
		}

		// Callee answer the call but reject video
		auto paulineCallParams = pauline->getCore()->createCallParams(paulineCall);
		paulineCallParams->enableVideo(false);
		if (!BC_ASSERT_TRUE(paulineCall->acceptWithParams(paulineCallParams) == 0)) return;

		if (!BC_ASSERT_TRUE(
		        CoreAssert({marie->getCore(), pauline->getCore()}, server->getAgent()).wait([marieCall, paulineCall] {
			        return (marieCall->getState() == linphone::Call::State::StreamsRunning &&
			                paulineCall->getState() == linphone::Call::State::StreamsRunning);
		        }))) {
			return;
		}

		// Check video is disabled on both calls
		BC_ASSERT_FALSE(marieCall->getCurrentParams()->videoEnabled());
		BC_ASSERT_FALSE(paulineCall->getCurrentParams()->videoEnabled());

		pauline->endCurrentCall(marie);
	}
}

static test_t tests[] = {
    TEST_NO_TAG("Basic", basic),
    TEST_NO_TAG("Forward Media Encryption", forward),
    TEST_NO_TAG("SDES to ZRTP call", sdes2zrtp),
    TEST_NO_TAG("SDES to DTLS call", sdes2dtls),
    TEST_NO_TAG("ZRTP to DTLS call", zrtp2dtls),
    TEST_NO_TAG("SDES to SDES256 call", sdes2sdes256),
    TEST_NO_TAG("Video rejected by callee", videoRejected),
};

} // namespace b2buatester
test_suite_t b2bua_suite = {"B2bua",           nullptr, nullptr,
                            nullptr,           nullptr, sizeof(b2buatester::tests) / sizeof(b2buatester::tests[0]),
                            b2buatester::tests};
