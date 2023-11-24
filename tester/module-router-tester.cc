/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include <chrono>
#include <memory>
#include <string>
#include <unistd.h>

#include "belle-sip/types.h"

#include "flexisip/logmanager.hh"
#include "flexisip/module-router.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

#include "registrar/registrar-db.hh"
#include "utils/asserts.hh"
#include "utils/bellesip-utils.hh"
#include "utils/proxy-server.hh"
#include "utils/test-patterns/registrardb-test.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono_literals;
using namespace std::chrono;
using namespace flexisip;
using namespace flexisip::tester;

namespace flexisip {
namespace tester {

class FallbackRouteFilterTest : public AgentTest {
private:
	void onAgentConfiguration(ConfigManager& cfg) override {
		AgentTest::onAgentConfiguration(cfg);
		const auto* globalCfg = cfg.getRoot()->get<GenericStruct>("global");
		globalCfg->get<ConfigStringList>("transports")->set("sip:localhost:5260");

		cfg.getRoot()->get<GenericStruct>("module::DoSProtection")->get<ConfigBoolean>("enabled")->set("false");

		auto registrarConf = cfg.getRoot()->get<GenericStruct>("module::Registrar");
		registrarConf->get<ConfigStringList>("reg-domains")->set("127.0.0.1");

		auto routerConf = cfg.getRoot()->get<GenericStruct>("module::Router");

		// Setting up a fallback-route and BelleSip stack waiting for request.
		routerConf->get<ConfigString>("fallback-route")->set("sip:127.0.0.1:8282;transport=udp");

		// Configuring a filter to use the fallback only if, applied to the request, the filter is true.
		routerConf->get<ConfigBooleanExpression>("fallback-route-filter")
		    ->set(
		        "request.method != 'INVITE' || ( request.uri.user != 'conference-factory' && !(request.uri.user regexp "
		        "'chatroom-.*' ))");
	}

	void testExec() override {
		bool responseReceived = false;
		bool requestReceived = false;
		BellesipUtils bellesipUtilsFallback{
		    "0.0.0.0", 8282, "UDP", nullptr,
		    [&requestReceived](const belle_sip_request_event_t*) { requestReceived = true; }};
		BellesipUtils bellesipUtils{"0.0.0.0", -1, "UDP",
		                            [&responseReceived](int status) {
			                            if (status != 100) {
				                            BC_ASSERT_EQUAL(status, 200, int, "%i");
				                            responseReceived = true;
			                            }
		                            },
		                            nullptr};

		// We are sending a request matching the filter...
		bellesipUtils.sendRawRequest("OPTIONS sip:participant1@127.0.0.1:5260 SIP/2.0\r\n"
		                             "Via: SIP/2.0/UDP 10.10.10.10:5060;rport;branch=z9hG4bK1439638806\r\n"
		                             "From: <sip:anthony@127.0.0.1>;tag=465687829\r\n"
		                             "To: <sip:participant1@127.0.0.1>\r\n"
		                             "Call-ID: 1053183492\r\n"
		                             "CSeq: 1 OPTIONS\r\n"
		                             "Contact: <sip:jehan-mac@192.168.1.8:5062>\r\n"
		                             "Max-Forwards: 42\r\n"
		                             "User-Agent: Linphone/3.3.99.10 (eXosip2/3.3.0)\r\n"
		                             "Content-Length: 0\r\n\r\n");

		auto beforePlus2 = system_clock::now() + 2s;
		while ((!responseReceived || !requestReceived) && beforePlus2 >= system_clock::now()) {
			waitFor(10ms);
			bellesipUtils.stackSleep(10);
			bellesipUtilsFallback.stackSleep(10);
		}
		// ... so the fallback route MUST have received the request...
		BC_ASSERT_TRUE(requestReceived);
		// ... and the sender MUST have received the "200 Ok" from the fallback route.
		BC_ASSERT_TRUE(responseReceived);

		responseReceived = false;
		requestReceived = false;

		BellesipUtils bellesipUtils2{"0.0.0.0", -1, "UDP",
		                             [&responseReceived](int status) {
			                             if (status != 100) {
				                             BC_ASSERT_EQUAL(status, 404, int, "%i");
				                             responseReceived = true;
			                             }
		                             },
		                             nullptr};

		// This time we send a request not matching the filter...
		bellesipUtils2.sendRawRequest(
		    // Sip message
		    "INVITE sip:chatroom-1212@127.0.0.1:5260 SIP/2.0\r\n"
		    "Via: SIP/2.0/UDP "
		    "10.23.17.117:22600;branch=z9hG4bK-d8754z-4d7620d2feccbfac-1---d8754z-;rport=4820;received=202.165.193."
		    "129\r\n"
		    "Max-Forwards: 70\r\n"
		    "Contact: <sip:anthony@127.0.0.1>\r\n"
		    "To: <sip:chatroom-1212@127.0.0.1>\r\n"
		    "From: <sip:anthony@127.0.0.1>;tag=465687829\r\n"
		    "Call-ID: Y2NlNzg0ODc0ZGIxODU1MWI5MzhkNDVkNDZhOTQ4YWU.\r\n"
		    "CSeq: 1 INVITE\r\n"
		    "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, PRACK\r\n"
		    "c: application/sdp\r\n"
		    "Supported: replaces\r\n"
		    "Supported: 100rel\r\n"
		    "Authorization: Digest username=\"003332176\", realm=\"sip.ovh.net\", "
		    "nonce=\"24212965507cde726e8bc37e04686459\", uri=\"sip:sip.ovh.net\", "
		    "response=\"896e786e9c0525ca3085322c7f1bce7b\", algorithm=MD5, opaque=\"241b9fb347752f2\"\r\n"
		    "User-Agent: X-Lite 4 release 4.0 stamp 58832\r\n",
		    // Request body
		    "v=0\r\n"
		    "o=anthony.gauchy 3102 279 IN IP4 127.0.0.1\r\n"
		    "s=Talk\r\n"
		    "c=IN IP4 127.0.0.1\r\n"
		    "t=0 0\r\n"
		    "m=audio 7078 RTP/AVP 111 110 3 0 8 101\r\n"
		    "a=rtpmap:111 speex/16000\r\n"
		    "a=fmtp:111 vbr=on\r\n"
		    "a=rtpmap:110 speex/8000\r\n"
		    "a=fmtp:110 vbr=on\r\n"
		    "a=rtpmap:101 telephone-event/8000\r\n"
		    "a=fmtp:101 0-11\r\n"
		    "m=video 8078 RTP/AVP 99 97 98\r\n"
		    "c=IN IP4 192.168.0.18\r\n"
		    "b=AS:380\r\n"
		    "a=rtpmap:99 MP4V-ES/90000\r\n"
		    "a=fmtp:99 profile-level-id=3\r\n");

		beforePlus2 = system_clock::now() + 2s;
		while ((!responseReceived || !requestReceived) && beforePlus2 >= system_clock::now()) {
			waitFor(10ms);
			bellesipUtils2.stackSleep(10);
			bellesipUtilsFallback.stackSleep(10);
		}

		// ... so the fallback route MUST NOT have received the request...
		BC_ASSERT_FALSE(requestReceived);
		// ... and the sender MUST have received the "404 Not Found" from flexisip (no user in the registrar db).
		BC_ASSERT_TRUE(responseReceived);
	}
};

/*
 * Check that module router remove route to itself.
 *
 * In this test we want to verify that every request that enter module::Router
 * with a "Route:" header pointing to itself are actually resolved by using the
 * registrar DB and goes out the module::Router with the
 * route header removed.
 */
class SelfRouteHeaderRemovingTest : public RegistrarDbTest<DbImplementation::Internal> {
public:
	SelfRouteHeaderRemovingTest() noexcept : RegistrarDbTest(true){};

private:
	void onAgentConfiguration(ConfigManager& cfg) override {
		SLOGD << "Step 1: Setup";
		RegistrarDbTest::onAgentConfiguration(cfg);
		const auto* globalCfg = cfg.getRoot()->get<GenericStruct>("global");
		globalCfg->get<ConfigStringList>("transports")->set("sip:127.0.0.1:6060");
		globalCfg->get<ConfigStringList>("aliases")->set("test.flexisip.org");

		cfg.getRoot()->get<GenericStruct>("module::DoSProtection")->get<ConfigBoolean>("enabled")->set("false");

		auto registrarConf = cfg.getRoot()->get<GenericStruct>("module::Registrar");
		registrarConf->get<ConfigStringList>("reg-domains")->set("test.flexisip.org");
	}

	void testExec() override {
		bool isRequestAccepted = false;
		bool isRequestReceived = false;
		BellesipUtils bellesipUtilsReceiver{
		    "0.0.0.0", 8383, "TCP", nullptr, [&isRequestReceived](const belle_sip_request_event_t* event) {
			    isRequestReceived = true;
			    if (!BC_ASSERT_PTR_NOT_NULL(belle_sip_request_event_get_request(event))) {
				    return;
			    }
			    auto request = belle_sip_request_event_get_request(event);
			    auto message = BELLE_SIP_MESSAGE(request);
			    auto routes = belle_sip_message_get_headers(message, "Route");
			    if (routes != nullptr) {
				    BC_FAIL("Route was not removed");
			    }
		    }};

		BellesipUtils bellesipUtilsSender{"0.0.0.0", -1, "TCP",
		                                  [&isRequestAccepted](int status) {
			                                  if (status != 100) {
				                                  BC_ASSERT_EQUAL(status, 200, int, "%i");
				                                  isRequestAccepted = true;
			                                  }
		                                  },
		                                  nullptr};

		mInserter->setAor("sip:user@test.flexisip.org")
		    .setExpire(30s)
		    .insert({"sip:user@127.0.0.1:8383;transport=tcp;"});
		BC_ASSERT_TRUE(this->waitFor([this] { return mInserter->finished(); }, 1s));

		SLOGD << "Step 2: Send message";
		// clang-format off
		bellesipUtilsSender.sendRawRequest("MESSAGE sip:user@test.flexisip.org SIP/2.0\r\n"
									 "Via: SIP/2.0/TCP 127.0.0.1:6060;branch=z9hG4bK.PAWTmCZv1;rport=49828\r\n"
									 "From: <sip:kijou@sip.linphone.org;gr=8aabdb1c>;tag=l3qXxwsO~\r\n"
									 "To: <sip:user@test.flexisip.org>\r\n"
									 "CSeq: 20 MESSAGE\r\n"
									 "Call-ID: Tvw6USHXYv\r\n"
									 "Max-Forwards: 70\r\n"
									 "Route: <sip:127.0.0.1:6060;transport=tcp;lr>\r\n"
									 "Supported: replaces, outbound, gruu\r\n"
									 "Date: Fri, 01 Apr 2022 11:18:26 GMT\r\n"
									 "Content-Type: text/plain\r\n",
									 "C'est pas faux \r\n\r\n");
		// clang-format on
		auto beforePlus2 = system_clock::now() + 2s;
		while ((!isRequestAccepted || !isRequestReceived) && beforePlus2 >= system_clock::now()) {
			waitFor(10ms);
			bellesipUtilsSender.stackSleep(10);
			bellesipUtilsReceiver.stackSleep(10);
		}

		SLOGD << "Step 3: Assert that request received an answer (200) and is received.";
		BC_ASSERT_TRUE(isRequestAccepted);
		BC_ASSERT_TRUE(isRequestReceived);
	}
};

/*
 * Check that module router don't remove route to others.
 *
 * In this test the message contains two "Route:" headers :
 *  - One pointing to itself
 *  - One pointing to another proxy
 *  We want to assert that the header pointing to itself is removed.
 *  We want to assure that the module::Router is skipped (no contact is resolved) and
 *  the request directly forwarded to the other proxy, with the second route header preserved.
 *
 */
class OtherRouteHeaderNotRemovedTest : public RegistrarDbTest<DbImplementation::Internal> {
public:
	OtherRouteHeaderNotRemovedTest() noexcept : RegistrarDbTest(true){};

private:
	void onAgentConfiguration(ConfigManager& cfg) override {
		SLOGD << "Step 1: Setup";
		RegistrarDbTest::onAgentConfiguration(cfg);
		const auto* globalCfg = cfg.getRoot()->get<GenericStruct>("global");
		globalCfg->get<ConfigStringList>("transports")->set("sip:127.0.0.1:6060");
		globalCfg->get<ConfigStringList>("aliases")->set("test.flexisip.org");

		cfg.getRoot()->get<GenericStruct>("module::DoSProtection")->get<ConfigBoolean>("enabled")->set("false");

		auto registrarConf = cfg.getRoot()->get<GenericStruct>("module::Registrar");
		registrarConf->get<ConfigStringList>("reg-domains")->set("test.flexisip.org");
	}

	void testExec() override {
		bool isRequestAccepted = false;
		bool isRequestReceived = false;
		BellesipUtils bellesipUtilsReceiver{
		    "0.0.0.0", 8383, "TCP", nullptr, [&isRequestReceived](const belle_sip_request_event_t* event) {
			    isRequestReceived = true;
			    auto request = belle_sip_request_event_get_request(event);
			    BC_HARD_ASSERT_NOT_NULL(request);
			    auto message = BELLE_SIP_MESSAGE(request);
			    BC_HARD_ASSERT_NOT_NULL(message);
			    auto routes = belle_sip_message_get_headers(message, BELLE_SIP_ROUTE);
			    BC_HARD_ASSERT_NOT_NULL(routes);
			    if (bctbx_list_last_elem(routes) != bctbx_list_first_elem(routes)) {
				    BC_FAIL("Both routes were preserved");
			    } else {
				    auto* routeActual = (belle_sip_header_route_t*)bctbx_list_first_elem(routes)->data;
				    auto* routeExpected = belle_sip_header_route_parse("Route: <sip:127.0.0.1:8383;transport=tcp;lr>");
				    BC_ASSERT_TRUE(belle_sip_header_route_equals(routeActual, routeExpected) == 0);
			    }
		    }};

		BellesipUtils bellesipUtilsSender{"0.0.0.0", -1, "TCP",
		                                  [&isRequestAccepted](int status) {
			                                  if (status != 100) {
				                                  BC_ASSERT_EQUAL(status, 200, int, "%i");
				                                  isRequestAccepted = true;
			                                  }
		                                  },
		                                  nullptr};

		// Because we want to assert that module::Router is skipped and that no user is resolved we insert
		// a contact pointing to nowhere.
		mInserter->setAor("sip:user@test.flexisip.org")
		    .setExpire(30s)
		    .insert({"sip:user@127.0.0.1:9999;transport=tcp;"});
		BC_ASSERT_TRUE(this->waitFor([this] { return mInserter->finished(); }, 1s));

		SLOGD << "Step 2: Send message";
		// clang-format off
		bellesipUtilsSender.sendRawRequest("MESSAGE sip:user@test.flexisip.org SIP/2.0\r\n"
									 "Via: SIP/2.0/TCP 127.0.0.1:6060;branch=z9hG4bK.PAWTmCZv1;rport=49828\r\n"
									 "From: <sip:kijou@sip.linphone.org;gr=8aabdb1c>;tag=l3qXxwsO~\r\n"
									 "To: <sip:user@test.flexisip.org>\r\n"
									 "CSeq: 20 MESSAGE\r\n"
									 "Call-ID: Tvw6USHXYv\r\n"
									 "Max-Forwards: 70\r\n"
                                     "Route: <sip:127.0.0.1:6060;transport=tcp;lr>\r\n"
									 "Route: <sip:127.0.0.1:8383;transport=tcp;lr>\r\n"
									 "Supported: replaces, outbound, gruu\r\n"
									 "Date: Fri, 01 Apr 2022 11:18:26 GMT\r\n"
									 "Content-Type: text/plain\r\n",
									 "C'est pas faux \r\n\r\n");
		// clang-format on
		auto beforePlus2 = system_clock::now() + 2s;
		while ((!isRequestAccepted || !isRequestReceived) && beforePlus2 >= system_clock::now()) {
			waitFor(10ms);
			bellesipUtilsSender.stackSleep(10);
			bellesipUtilsReceiver.stackSleep(10);
		}

		SLOGD << "Step 3: Assert that request received an answer (200) and is received.";
		BC_ASSERT_TRUE(isRequestAccepted);
		BC_ASSERT_TRUE(isRequestReceived);
	}
};

template <typename Database>
void message_expires() {
	Database db{};
	Server proxyServer{[&db]() {
		auto config = db.configAsMap();
		config.emplace("global/transports", "sip:127.0.0.1:0;transport=udp");
		config.emplace("module::Registrar/reg-domains", "127.0.0.1");
		return config;
	}()};
	proxyServer.start();
	BcAssert asserter{};
	asserter.addCustomIterate([&root = *proxyServer.getRoot()] { root.step(1ms); });
	const auto& agent = proxyServer.getAgent();
	const auto routerModule = static_pointer_cast<ModuleRouter>(agent->findModule("Router"));
	auto responseCount = 0;
	BellesipUtils bellesipUtils{"0.0.0.0", 0, "UDP",
	                            [&responseCount](int status) {
		                            if (status != 100) {
			                            ++responseCount;
		                            }
	                            },
	                            nullptr};
	const string proxyPort = proxyServer.getFirstPort();
	const string clientPort = to_string(bellesipUtils.getListeningPort());
	ContactInserter inserter(*RegistrarDb::get());
	inserter.setAor("sip:message_expires@127.0.0.1")
	    .setExpire(0s)
	    .setContactParams({"message-expires=1609"})
	    .insert({"sip:message_expires@127.0.0.1:" + clientPort});
	BC_HARD_ASSERT_TRUE(asserter.iterateUpTo(5, [&inserter] { return inserter.finished(); }));
	asserter.addCustomIterate([&bellesipUtils] { bellesipUtils.stackSleep(1); });
	auto* forks = routerModule->mStats.mCountForks->start;
	BC_ASSERT_CPP_EQUAL(forks->read(), 0);

	bellesipUtils.sendRawRequest(
	    "OPTIONS sip:message_expires@127.0.0.1:" + proxyPort + " SIP/2.0\r\n" +
	    "From: <sip:message_expires_placeholder2@127.0.0.1>;tag=message_expires_placeholder1\r\n"
	    "To: <sip:message_expires@127.0.0.1>\r\n"
	    "Via: SIP/2.0/TCP 127.0.0.1\r\n"
	    "Call-ID: message_expires_placeholder4\r\n"
	    "CSeq: 55 OPTIONS\r\n");
	bellesipUtils.sendRawRequest(
	    "MESSAGE sip:message_expires@127.0.0.1:" + proxyPort + " SIP/2.0\r\n" +
	    "From: <sip:message_expires_placeholder6@127.0.0.1>;tag=message_expires_placeholder3\r\n"
	    "To: <sip:message_expires@127.0.0.1>\r\n"
	    "Via: SIP/2.0/TCP 127.0.0.1\r\n"
	    "Call-ID: message_expires_placeholder8\r\n"
	    "CSeq: 2178 MESSAGE\r\n"
	    "Content-Type: text/plain\r\n"
	    "\r\n"
	    "Expiration Date High Score: 24.3\r\n");
	BC_HARD_ASSERT_TRUE(asserter.iterateUpTo(5, [&responseCount] { return responseCount == 2; }));
	BC_ASSERT_CPP_EQUAL(forks->read(), 1);
}

namespace {
TestSuite
    _("Module router",
      {
          CLASSY_TEST(message_expires<DbImplementation::Internal>),
          CLASSY_TEST(message_expires<DbImplementation::Redis>),
          TEST_NO_TAG("Disable fallback route for requests not matching fallback-route-filter",
                      run<FallbackRouteFilterTest>),
          TEST_NO_TAG("Check that module router remove route to itself", run<SelfRouteHeaderRemovingTest>),
          TEST_NO_TAG("Check that module router don't remove route to others", run<OtherRouteHeaderNotRemovedTest>),
      });
} // namespace
} // namespace tester
} // namespace flexisip
