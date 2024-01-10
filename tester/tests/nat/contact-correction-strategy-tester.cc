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

#include "nat/contact-correction-strategy.hh"

#include <memory>

#include <sofia-sip/msg.h>
#include <sofia-sip/msg_addr.h>

#include "flexisip/logmanager.hh"

#include "utils/nat-test-helper.hh"
#include "utils/string-formatter.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace sofiasip;

namespace flexisip::tester {

using RqSipEv = RequestSipEvent;
using RsSipEv = ResponseSipEvent;

namespace {

struct Helper : public NatTestHelper {
	static shared_ptr<MsgSip> getRegister(bool contactIsVerified) {
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

		const auto request = formatter.format({{"parameter", (contactIsVerified ? ";verified" : "")}});

		return make_shared<MsgSip>(0, request);
	}

	static shared_ptr<MsgSip> getInvite(bool contactIsVerified) {
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

		const auto request = formatter.format({{"parameter", (contactIsVerified ? ";verified" : "")}});

		const auto msg = make_shared<MsgSip>(0, request);
		auto* sockAddr = reinterpret_cast<sockaddr_in*>(msg->getSockAddr());
		sockAddr->sin_addr.s_addr = htonl(0x5241DC64);
		sockAddr->sin_port = htons(8765);
		sockAddr->sin_family = AF_INET;

		return msg;
	}

	ContactCorrectionStrategy mStrategy{mAgent.get(), "verified"};
};

/*
 * Test contact url from "Contact" header is fixed using information set in the "VIA" header.
 */
void preProcessOnRequestNatHelperFixContactFromVia() {
	const Helper helper{};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getRegister(false), helper.mTport);

	helper.mStrategy.preProcessOnRequestNatHelper(event);

	const auto* contact = event->getMsgSip()->getSip()->sip_contact;
	BC_HARD_ASSERT(contact != nullptr);
	BC_ASSERT_CPP_EQUAL(contact->m_url->url_host, "82.65.220.100"s);
	BC_ASSERT_CPP_EQUAL(contact->m_url->url_port, "8765"s);
}

/*
 * Test contact url from "Contact" header is not fixed ("verified" contact url parameter is present).
 */
void preProcessOnRequestNatHelperNoFixContactFromVia() {
	const Helper helper{};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getRegister(true), helper.mTport);

	helper.mStrategy.preProcessOnRequestNatHelper(event);

	const auto* contact = event->getMsgSip()->getSip()->sip_contact;
	BC_HARD_ASSERT(contact != nullptr);
	BC_ASSERT_CPP_EQUAL(contact->m_url->url_host, "sip.example.org"s);
	BC_ASSERT(contact->m_url->url_port == nullptr);
}

/*
 * Test successful "record-route" addition and url matches the address of the server.
 */
void addRecordRouteNatHelper() {
	const Helper helper{};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getRegister(false), helper.mTport);

	helper.mStrategy.addRecordRouteNatHelper(event);

	BC_HARD_ASSERT(event->getMsgSip()->getSip()->sip_record_route != nullptr);
	const auto* routeUrlStr = url_as_string(event->getHome(), event->getMsgSip()->getSip()->sip_record_route->r_url);
	BC_ASSERT_CPP_EQUAL(routeUrlStr, "sip:127.0.0.1:" + helper.mProxyPort + ";transport=tcp;lr");
}

/*
 * Test successful removal of "verified" contact url parameter when request goes through NatHelper::onResponse.
 */
void onResponseNatHelperRemoveVerified() {
	const Helper helper{};
	const auto event = make_shared<RsSipEv>(helper.mAgent, Helper::getInvite(true), helper.mTport);
	// Add one more "VIA" header and add response status 200.
	event->getSip()->sip_via->v_next = sip_via_dup(event->getHome(), event->getSip()->sip_via);
	event->getSip()->sip_status = static_cast<sip_status_t*>(su_alloc(event->getHome(), sizeof(sip_status_t)));
	event->getSip()->sip_status->st_status = 200;

	helper.mStrategy.onResponseNatHelper(event);

	BC_HARD_ASSERT(event->getSip()->sip_contact != nullptr);
	BC_ASSERT(url_has_param(event->getSip()->sip_contact->m_url, "verified") == false);
}

/*
 * Test successful addition of "verified" contact url parameter when request goes through NatHelper::onResponse.
 */
void onResponseNatHelperAddVerified() {
	const Helper helper{};
	const auto event = make_shared<RsSipEv>(helper.mAgent, Helper::getInvite(false), helper.mTport);
	// Add response status 200.
	event->getSip()->sip_status = static_cast<sip_status_t*>(su_alloc(event->getHome(), sizeof(sip_status_t)));
	event->getSip()->sip_status->st_status = 200;
	// Make sure it does not trigger the contact correction in fixContactInResponse.
	msg_addr(event->getMsgSip()->getMsg())->su_sa.sa_family = AF_UNSPEC;

	helper.mStrategy.onResponseNatHelper(event);

	BC_HARD_ASSERT(event->getSip()->sip_contact != nullptr);
	BC_ASSERT(url_has_param(event->getSip()->sip_contact->m_url, "verified") == true);
	const auto* contact = event->getMsgSip()->getSip()->sip_contact;
	BC_ASSERT_CPP_EQUAL(contact->m_url->url_host, "sip.example.org"s);
	BC_ASSERT(contact->m_url->url_port == nullptr);
}

/*
 * Test successful contact url correction and addition of "verified" contact url parameter when request goes through
 * NatHelper::onResponse.
 */
void onResponseNatHelperCorrectContactAndAddVerified() {
	const Helper helper{};
	const auto event = make_shared<RsSipEv>(helper.mAgent, Helper::getInvite(false), helper.mTport);
	// Add response status 200.
	event->getSip()->sip_status = static_cast<sip_status_t*>(su_alloc(event->getHome(), sizeof(sip_status_t)));
	event->getSip()->sip_status->st_status = 200;

	helper.mStrategy.onResponseNatHelper(event);

	BC_HARD_ASSERT(event->getSip()->sip_contact != nullptr);
	BC_ASSERT(url_has_param(event->getSip()->sip_contact->m_url, "verified") == true);
	const auto* contact = event->getMsgSip()->getSip()->sip_contact;
	BC_ASSERT_CPP_EQUAL(contact->m_url->url_host, "82.65.220.100"s);
	BC_ASSERT_CPP_EQUAL(contact->m_url->url_port, "8765"s);
}

/*
 * Test successful addition of "verified" contact url parameter when request goes through NatHelper::onResponse and that
 * contact url is correct.
 */
void onResponseNatHelperContactIsCorrectAndAddVerified() {
	const Helper helper{};
	const auto event = make_shared<RsSipEv>(helper.mAgent, Helper::getInvite(false), helper.mTport);
	// Add response status 200.
	event->getSip()->sip_status = static_cast<sip_status_t*>(su_alloc(event->getHome(), sizeof(sip_status_t)));
	event->getSip()->sip_status->st_status = 200;
	// Make sure contact is correct but is detected as needToFixed.
	auto* contact = event->getMsgSip()->getSip()->sip_contact;
	contact->m_url->url_host = "82.65.220.100";
	contact->m_url->url_port = "8765";

	helper.mStrategy.onResponseNatHelper(event);

	BC_ASSERT(url_has_param(event->getSip()->sip_contact->m_url, "verified") == true);
	BC_ASSERT_CPP_EQUAL(contact->m_url->url_host, "82.65.220.100"s);
	BC_ASSERT_CPP_EQUAL(contact->m_url->url_port, "8765"s);
}

/*
 * Test nullptr is returned.
 */
void getTportDestFromLastRoute() {
	const Helper helper{};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getInvite(false), helper.mTport);

	BC_ASSERT(helper.mStrategy.getTportDestFromLastRoute(event, nullptr) == nullptr);
}

/*
 * Test successful "record-route" addition and url matches the address of the server.
 */
void addRecordRouteForwardModule() {
	const Helper helper{};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getInvite(false), helper.mTport);

	helper.mStrategy.addRecordRouteForwardModule(event, helper.mTport, nullptr);

	const auto* recordRoute = event->getSip()->sip_record_route;
	BC_HARD_ASSERT(&recordRoute[0] != nullptr);
	const auto* recordRouteUrlStr = url_as_string(event->getHome(), recordRoute->r_url);
	BC_ASSERT_CPP_EQUAL(recordRouteUrlStr, "sip:127.0.0.1:" + helper.mProxyPort + ";transport=tcp;lr");
}

/*
 * Test successful "Path" header addition and url matches the address of the server.
 */
void addPathOnRegister() {
	const Helper helper{};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getInvite(false), helper.mTport);

	helper.mStrategy.addPathOnRegister(event, helper.mTport, nullptr);

	const auto* path = event->getSip()->sip_path;
	BC_HARD_ASSERT(path != nullptr);
	const auto* pathString = url_as_string(event->getHome(), path->r_url);
	BC_ASSERT_CPP_EQUAL(pathString, "sip:127.0.0.1:" + helper.mProxyPort + ";transport=tcp;lr");
}

/*
 * Test successful "Path" header addition and url matches the address of the server.
 */
void addPathOnRegisterWithUniq() {
	const Helper helper{};
	const auto event = make_shared<RqSipEv>(helper.mAgent, Helper::getInvite(false), helper.mTport);

	helper.mStrategy.addPathOnRegister(event, helper.mTport, "stub-uniq");

	const auto* path = event->getSip()->sip_path;
	BC_HARD_ASSERT(path != nullptr);
	const auto* pathString = url_as_string(event->getHome(), path->r_url);
	BC_ASSERT_CPP_EQUAL(pathString, "sip:127.0.0.1:" + helper.mProxyPort + ";transport=tcp;fs-proxy-id=stub-uniq;lr");
}

TestSuite _("NatTraversalStrategy::ContactCorrection",
            {
                TEST_NO_TAG_AUTO_NAMED(preProcessOnRequestNatHelperFixContactFromVia),
                TEST_NO_TAG_AUTO_NAMED(preProcessOnRequestNatHelperNoFixContactFromVia),
                TEST_NO_TAG_AUTO_NAMED(addRecordRouteNatHelper),
                TEST_NO_TAG_AUTO_NAMED(onResponseNatHelperRemoveVerified),
                TEST_NO_TAG_AUTO_NAMED(onResponseNatHelperAddVerified),
                TEST_NO_TAG_AUTO_NAMED(onResponseNatHelperCorrectContactAndAddVerified),
                TEST_NO_TAG_AUTO_NAMED(onResponseNatHelperContactIsCorrectAndAddVerified),
                TEST_NO_TAG_AUTO_NAMED(getTportDestFromLastRoute),
                TEST_NO_TAG_AUTO_NAMED(addRecordRouteForwardModule),
                TEST_NO_TAG_AUTO_NAMED(addPathOnRegister),
                TEST_NO_TAG_AUTO_NAMED(addPathOnRegisterWithUniq),
            });

} // namespace

} // namespace flexisip::tester