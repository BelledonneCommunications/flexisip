/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <chrono>

#include "flexisip/agent.hh"
#include "flexisip/module-router.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

#include "tester.hh"
#include "utils/bellesip-utils.hh"

using namespace std;
using namespace std::chrono_literals;
using namespace std::chrono;
using namespace flexisip;

static shared_ptr<sofiasip::SuRoot> root{};
static shared_ptr<Agent> agent{};
static bool responseReceived = false;
static bool requestReceived = false;

static void beforeEach() {
	responseReceived = false;
	requestReceived = false;
	root = make_shared<sofiasip::SuRoot>();
	agent = make_shared<Agent>(root);
}

static void afterEach() {
	agent->unloadConfig();
	RegistrarDb::resetDB();
	agent.reset();
	root.reset();
}

static void fallbackRouteFilter() {
	// Agent initialization
	auto cfg = GenericManager::get();
	cfg->load(string(TESTER_DATA_DIR).append("/config/flexisip_router.conf"));
	agent->loadConfig(cfg);

	auto registrarConf = GenericManager::get()->getRoot()->get<GenericStruct>("module::Registrar");
	registrarConf->get<ConfigStringList>("reg-domains")->set("127.0.0.1");

	auto routerConf = GenericManager::get()->getRoot()->get<GenericStruct>("module::Router");

	// Setting up a fallback-route and BelleSip stack waiting for request.
	routerConf->get<ConfigString>("fallback-route")->set("sip:127.0.0.1:8282;transport=udp");
	BellesipUtils bellesipUtilsFallback{"0.0.0.0", 8282, "UDP", [](int status) { requestReceived = true; }};

	// Configuring a filter to use the fallback only if, applied to the request, the filter is true.
	routerConf->get<ConfigBooleanExpression>("fallback-route-filter")
	    ->set("request.method != 'INVITE' || ( request.uri.user != 'conference-factory' && !(request.uri.user regexp "
	          "'chatroom-.*' ))");

	agent->start("", "");

	BellesipUtils bellesipUtils{"0.0.0.0", -1, "UDP", [](int status) {
		                            if (status != 100) {
			                            BC_ASSERT_EQUAL(status, 200, int, "%i");
			                            responseReceived = true;
		                            }
	                            }};

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
		root->step(100ms);
		bellesipUtils.stackSleep(100);
		bellesipUtilsFallback.stackSleep(100);
	}
	// ... so the fallback route MUST have received the request...
	BC_ASSERT_TRUE(requestReceived);
	// ... and the sender MUST have received the "200 Ok" from the fallback route.
	BC_ASSERT_TRUE(responseReceived);

	responseReceived = false;
	requestReceived = false;

	BellesipUtils bellesipUtils2{"0.0.0.0", -1, "UDP", [](int status) {
		                             if (status != 100) {
			                             BC_ASSERT_EQUAL(status, 404, int, "%i");
			                             responseReceived = true;
		                             }
	                             }};

	// This time we send a request not matching the filter...
	bellesipUtils2.sendRawRequest(
	    // Sip message
	    "INVITE sip:chatroom-1212@127.0.0.1:5260 SIP/2.0\r\n"
	    "Via: SIP/2.0/UDP "
	    "10.23.17.117:22600;branch=z9hG4bK-d8754z-4d7620d2feccbfac-1---d8754z-;rport=4820;received=202.165.193.129\r\n"
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
		root->step(100ms);
		bellesipUtils2.stackSleep(100);
		bellesipUtilsFallback.stackSleep(100);
	}

	// ... so the fallback route MUST NOT have received the request...
	BC_ASSERT_FALSE(requestReceived);
	// ... and the sender MUST have received the "404 Not Found" from flexisip (no user in the registrar db).
	BC_ASSERT_TRUE(responseReceived);
}

static test_t tests[] = {
    TEST_NO_TAG("Disable fallback route for requests not matching fallback-route-filter", fallbackRouteFilter),
};

test_suite_t router_suite = {
    "Module router", nullptr, nullptr, beforeEach, afterEach, sizeof(tests) / sizeof(tests[0]), tests};
