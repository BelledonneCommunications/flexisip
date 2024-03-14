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

#include "nat/flow-token-strategy.hh"

#include <memory>

#include <sofia-sip/msg.h>
#include <sofia-sip/tport.h>

#include "flexisip/logmanager.hh"

#include "flexisip-tester-config.hh"
#include "nat/contact-correction-strategy.hh"
#include "utils/nat-test-helper.hh"
#include "utils/string-formatter.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

#define HASH_KEY_FILE_PATH FLEXISIP_TESTER_INSTALL_DATA_SRCDIR "/config/flow-token-hash-key"

using namespace std;
using namespace sofiasip;

namespace flexisip::tester {

using RqSipEv = RequestSipEvent;
using RsSipEv = ResponseSipEvent;

namespace {

struct Helper : public NatTestHelper {
	explicit Helper(const string& boolExpr)
	    : NatTestHelper(),
	      mStrategy(mAgent.get(), SipBooleanExpressionBuilder::get().parse(boolExpr), HASH_KEY_FILE_PATH) {
	}

	static shared_ptr<MsgSip> getRegister(bool ob) {
		StringFormatter formatter{
		    "REGISTER sip:user@sip.example.org SIP/2.0\r\n"
		    "Via: SIP/2.0/TCP 10.0.2.10:5678;branch=z9hG4bK-3908207663;rport=8765;received=82.65.220.100\r\n"
		    "To: <sip:user@sip.example.org>\r\n"
		    "From: <sip:user@sip.example.org>;tag=465687829\r\n"
		    "Call-ID: stub-id.\r\n"
		    "Contact: <sip:user@sip.example.org;transport=tcp{parameter}>\r\n"
		    "CSeq: 1 REGISTER\r\n"
		    "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO\r\n"
		    "Content-Type: application/sdp\r\n"};

		const auto request = formatter.format({{"parameter", (ob ? ";ob" : "")}});

		const auto msg = make_shared<MsgSip>(0, request);
		auto* sockAddr = reinterpret_cast<sockaddr_in*>(msg->getSockAddr());
		sockAddr->sin_addr.s_addr = htonl(0x01020304);
		sockAddr->sin_port = htons(5678);
		sockAddr->sin_family = AF_INET;

		return msg;
	}

	static shared_ptr<MsgSip> getInvite(bool ob) {
		StringFormatter formatter{
		    "INVITE sip:callee@sip.example.org SIP/2.0\r\n"
		    "Via: SIP/2.0/TCP 10.0.2.10:5678;branch=z9hG4bK-3908207663;rport=8765;received=82.65.220.100\r\n"
		    "Max-Forwards: 70\r\n"
		    "To: <sip:callee@sip.example.org>\r\n"
		    "From: <sip:caller@sip.example.org>;tag=465687829\r\n"
		    "Call-ID: stub-id.\r\n"
		    "Contact: <sip:callee@sip.example.org;transport=tcp{parameter}>\r\n"
		    "CSeq: 1 INVITE\r\n"
		    "Accept: application/sdp\r\n"
		    "Content-Length: 0\r\n"};

		const auto request = formatter.format({{"parameter", (ob ? ";ob" : "")}});

		const auto msg = make_shared<MsgSip>(0, request);
		auto* sockAddr = reinterpret_cast<sockaddr_in*>(msg->getSockAddr());
		sockAddr->sin_addr.s_addr = htonl(0x01020304);
		sockAddr->sin_port = htons(5678);
		sockAddr->sin_family = AF_INET;

		return msg;
	}

	FlowTokenStrategy mStrategy;
};

/*
 * Test successful "record-route" addition, test it matches the address of the server and generated flow-token is valid.
 */
void addRecordRouteNatHelper() {
	const Helper helper{"false"};
	const FlowFactory flowFactory{HASH_KEY_FILE_PATH};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getRegister(true), helper.mTport);

	helper.mStrategy.addRecordRouteNatHelper(event);

	const auto* recordRoute = event->getSip()->sip_record_route;
	BC_HARD_ASSERT(&recordRoute[0] != nullptr);

	const auto* recordRouteUrl = recordRoute[0].r_url;
	BC_ASSERT_CPP_EQUAL(recordRouteUrl->url_host, "127.0.0.1"s);
	BC_ASSERT_CPP_EQUAL(recordRouteUrl->url_port, helper.mProxyPort);

	const auto flow = flowFactory.create(recordRouteUrl->url_user);
	BC_ASSERT_CPP_EQUAL(url_has_param(recordRouteUrl, "lr"), true);
	BC_ASSERT_CPP_EQUAL(flow.getData().getLocalAddress()->str(), "127.0.0.1:" + helper.mProxyPort);
	BC_ASSERT_CPP_EQUAL(flow.getData().getRemoteAddress()->str(), "1.2.3.4:5678");
	BC_ASSERT(flow.getData().getTransportProtocol() == FlowData::Transport::Protocol::tcp);
	BC_ASSERT(string(url_as_string(event->getHome(), recordRouteUrl)).find("transport=tcp"));
}

/*
 * Test successful "record-route" addition and url matches the address of the server.
 * Test it does not contain a flow-token since there are no information available in the "VIA" header.
 */
void addRecordRouteNatHelperNoVia() {
	const Helper helper{"false"};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getRegister(true), helper.mTport);
	// Remove "VIA" header from request.
	su_free(event->getHome(), event->getSip()->sip_via);

	helper.mStrategy.addRecordRouteNatHelper(event);

	const auto* recordRoute = event->getSip()->sip_record_route;
	BC_HARD_ASSERT(&recordRoute[0] != nullptr);

	const auto* recordRouteUrlStr = url_as_string(event->getHome(), recordRoute[0].r_url);
	BC_ASSERT_CPP_EQUAL(recordRouteUrlStr, "sip:127.0.0.1:" + helper.mProxyPort + ";transport=tcp;lr");
}

/*
 * Test successful "record-route" addition and url matches the address of the server.
 * Test it does not contain a flow-token since the "Contact" header does not contain the "ob" parameter.
 */
void addRecordRouteNatHelperNoObParameter() {
	const Helper helper{"false"};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getRegister(false), helper.mTport);

	helper.mStrategy.addRecordRouteNatHelper(event);

	const auto* recordRoute = event->getSip()->sip_record_route;
	BC_HARD_ASSERT(&recordRoute[0] != nullptr);

	const auto* recordRouteUrlStr = url_as_string(event->getHome(), recordRoute[0].r_url);
	BC_ASSERT_CPP_EQUAL(recordRouteUrlStr, "sip:127.0.0.1:" + helper.mProxyPort + ";transport=tcp;lr");
}

/*
 * Test return value matches lastRoute with host:port corrected with information present in the flow-token.
 */
void getTportDestFromLastRoute() {
	const Helper helper{"false"};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getInvite(true), helper.mTport);
	sip_route_t lastRoute{};
	lastRoute.r_url->url_type = url_sip;
	lastRoute.r_url->url_scheme = "sip";
	lastRoute.r_url->url_user = "eM5HfG6l5y7nYAJ/AAABE8RSQdxkIj0="; // {local=?, remote=82.65.220.100:8765, tcp}
	lastRoute.r_url->url_host = "sip.example.org";
	lastRoute.r_url->url_port = "5060";
	lastRoute.r_url->url_params = "ob";

	SLOGD << url_as_string(event->getHome(), lastRoute.r_url);

	const auto* dest = helper.mStrategy.getTportDestFromLastRoute(event, &lastRoute);

	BC_HARD_ASSERT(dest != nullptr);
	BC_ASSERT(dest != lastRoute.r_url);
	const auto expected = "sip:eM5HfG6l5y7nYAJ/AAABE8RSQdxkIj0=@82.65.220.100:8765;transport=tcp"s;
	BC_ASSERT_CPP_EQUAL(url_as_string(event->getHome(), dest), expected);
}

/*
 * Test an invalid flow-token in url should return nullptr.
 */
void getTportDestFromLastRouteWithFalsifiedFlowToken() {
	const Helper helper{"false"};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getInvite(false), helper.mTport);
	sip_route_t lastRoute{};
	lastRoute.r_url[0].url_user = "this++ipv4++token++is+falsified=";

	const auto* dest = helper.mStrategy.getTportDestFromLastRoute(event, &lastRoute);

	BC_HARD_ASSERT(dest == nullptr);
}

/*
 * Test successful "record-route" addition and url matches the address of the server.
 * Test the flow-token is also present in the url.
 */
void addRecordRouteForwardModule() {
	const Helper helper{"false"};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getInvite(true), helper.mTport);
	url_t lastRouteUrl{};
	lastRouteUrl.url_user = "stub-flow-token";
	lastRouteUrl.url_host = "sip.proxy.example.org";
	lastRouteUrl.url_port = "5060";
	lastRouteUrl.url_params = "ob";

	helper.mStrategy.addRecordRouteForwardModule(event, helper.mTport, &lastRouteUrl);

	const auto* recordRoute = event->getSip()->sip_record_route;
	BC_HARD_ASSERT(&recordRoute[0] != nullptr);
	const auto* recordRouteUrlStr = url_as_string(event->getHome(), recordRoute[0].r_url);
	BC_ASSERT_CPP_EQUAL(recordRouteUrlStr, "sip:stub-flow-token@127.0.0.1:" + helper.mProxyPort + ";transport=tcp;lr");
}

/*
 * Test successful "record-route" addition and url matches the address of the server.
 */
void addRecordRouteForwardModuleNoRouteUrl() {
	const Helper helper{"false"};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getInvite(true), helper.mTport);

	helper.mStrategy.addRecordRouteForwardModule(event, helper.mTport, nullptr);

	const auto* recordRoute = event->getSip()->sip_record_route;
	BC_HARD_ASSERT(&recordRoute[0] != nullptr);
	const auto* recordRouteUrlStr = url_as_string(event->getHome(), recordRoute[0].r_url);
	BC_ASSERT_CPP_EQUAL(recordRouteUrlStr, "sip:127.0.0.1:" + helper.mProxyPort + ";transport=tcp;lr");
}

/*
 * Test successful "Path" header addition, test it matches the address of the server and generated flow-token is valid.
 */
void addPathOnRegister() {
	const Helper helper{"false"};
	const FlowFactory flowFactory{HASH_KEY_FILE_PATH};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getRegister(true), helper.mTport);

	helper.mStrategy.addPathOnRegister(event, helper.mTport, nullptr);

	const auto* path = event->getSip()->sip_path;
	BC_HARD_ASSERT(path != nullptr);
	BC_HARD_ASSERT(path->r_url->url_user != nullptr);

	const auto* pathUrl = path->r_url;
	BC_ASSERT_CPP_EQUAL(pathUrl->url_host, "127.0.0.1"s);
	BC_ASSERT_CPP_EQUAL(pathUrl->url_port, helper.mProxyPort);

	const auto flow = flowFactory.create(path->r_url->url_user);
	BC_ASSERT_CPP_EQUAL(url_has_param(pathUrl, "lr"), true);
	BC_ASSERT_CPP_EQUAL(flow.getData().getLocalAddress()->str(), "127.0.0.1:" + helper.mProxyPort);
	BC_ASSERT_CPP_EQUAL(flow.getData().getRemoteAddress()->str(), "1.2.3.4:5678");
	BC_ASSERT(flow.getData().getTransportProtocol() == FlowData::Transport::Protocol::tcp);
	BC_ASSERT(string(url_as_string(event->getHome(), pathUrl)).find("transport=tcp"));
}

/*
 * Test successful "Path" header addition and url matches the server address.
 */
void addPathOnRegisterNotFirstHop() {
	const Helper helper{"false"};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getRegister(true), helper.mTport);
	// Remove "VIA" header in request.
	su_free(event->getHome(), event->getSip()->sip_via);

	helper.mStrategy.addPathOnRegister(event, helper.mTport, nullptr);

	const auto* path = event->getSip()->sip_path;
	BC_HARD_ASSERT(path != nullptr);
	const auto* pathUrlStr = url_as_string(event->getHome(), path->r_url);
	BC_ASSERT_CPP_EQUAL(pathUrlStr, "sip:127.0.0.1:" + helper.mProxyPort + ";transport=tcp;lr");
}

/*
 * Test successful "Path" header addition and url matches the address of the server.
 */
void addPathOnRegisterNotFirstHopWithUniq() {
	const Helper helper{"false"};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getRegister(true), helper.mTport);
	// Remove "VIA" header in request.
	su_free(event->getHome(), event->getSip()->sip_via);

	helper.mStrategy.addPathOnRegister(event, helper.mTport, "stub-uniq");

	const auto* path = event->getSip()->sip_path;
	BC_HARD_ASSERT(path != nullptr);
	const auto* pathUrlStr = url_as_string(event->getHome(), path->r_url);
	BC_ASSERT_CPP_EQUAL(pathUrlStr, "sip:127.0.0.1:" + helper.mProxyPort + ";transport=tcp;fs-proxy-id=stub-uniq;lr");
}

TestSuite _("NatTraversalStrategy::FlowToken",
            {
                CLASSY_TEST(addRecordRouteNatHelper),
                CLASSY_TEST(addRecordRouteNatHelperNoVia),
                CLASSY_TEST(addRecordRouteNatHelperNoObParameter),
                CLASSY_TEST(getTportDestFromLastRoute),
                CLASSY_TEST(getTportDestFromLastRouteWithFalsifiedFlowToken),
                CLASSY_TEST(addRecordRouteForwardModule),
                CLASSY_TEST(addRecordRouteForwardModuleNoRouteUrl),
                CLASSY_TEST(addPathOnRegister),
                CLASSY_TEST(addPathOnRegisterNotFirstHop),
                CLASSY_TEST(addPathOnRegisterNotFirstHopWithUniq),
            });

} // namespace

} // namespace flexisip::tester