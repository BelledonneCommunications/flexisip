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

#include <memory>

#include <flexisip/logmanager.hh>
#include <flexisip/registrar/registar-listeners.hh>

#include "sofia-wrapper/nta-agent.hh"

#include "registrar/registrar-db.hh"
#include "utils/asserts.hh"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/core-assert.hh"
#include "utils/flow-test-helper.hh"
#include "utils/injected-module-info.hh"
#include "utils/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace sofiasip;

namespace flexisip::tester {

namespace {

namespace ContactCorrection {

/*
 * Test register of a user agent client that is "hidden" behind a NAT.
 *
 * The contact url in the "VIA" header contains a certain "ip:port" (here: 1.2.3.4:1234). The "VIA" header values
 * "rport" and "received" forms another "ip:port" (here: 5.6.7.8:5678).
 * The NatHelper module must fix contact "ip:port" to values found in the "VIA" header.
 */
void registerUser() {
	// Initialization --------------------------------------------------------------------------------------------------
	const string proxyHost = "127.0.0.1";
	const string expectedContactPort = "5678";
	const string expectedContactHost = "5.6.7.8";
	InjectedHooks injectedModuleHooks{
	    .injectAfterModule = "GarbageIn",
	    .onRequest =
	        [&expectedContactHost, &expectedContactPort](std::shared_ptr<RequestSipEvent>& ev) {
		        // Modify "rport" and "received" in "VIA" header, so it triggers "Contact" header correction.
		        auto* via = ev->getMsgSip()->getSip()->sip_via;
		        via->v_rport = expectedContactPort.c_str();
		        via->v_received = expectedContactHost.c_str();
	        },
	};
	Server proxy{
	    {
	        {"global/aliases", "localhost"},
	        {"global/transports", "sip:" + proxyHost + ":0;transport=tcp"},
	        {"module::Registrar/enabled", "true"},
	        {"module::Registrar/reg-domains", "localhost"},
	        {"module::NatHelper/enabled", "true"},
	        {"module::NatHelper/nat-traversal-strategy", "contact-correction"},
	        {"module::NatHelper/contact-correction-param", "verified"},
	    },
	    &injectedModuleHooks,
	};
	proxy.start();
	const auto proxyHostPort = proxyHost + ":"s + string(proxy.getFirstPort());
	const string proxyUri{"sip:" + proxyHostPort + ";transport=tcp"};

	NtaAgent client{proxy.getRoot(), "sip:" + proxyHost + ":0;transport=tcp"};
	BcAssert asserter{[&proxy] { proxy.getRoot()->step(1ms); }};
	// -----------------------------------------------------------------------------------------------------------------

	ostringstream request{};
	request << "REGISTER sip:user@localhost SIP/2.0\r\n"
	        << "From: <sip:user@localhost>;tag=stub-tag\r\n"
	        << "To: <sip:user@localhost>\r\n"
	        << "CSeq: 20 REGISTER\r\n"
	        << "Call-ID: stub-id.\r\n"
	        << "Supported: replaces, outbound, gruu, path, record-aware\r\n"
	        << "Contact: <sip:user@1.2.3.4:1234;transport=tcp>\r\n"
	        << "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO\r\n"
	        << "Expires: 60\r\n";

	const auto transaction = client.createOutgoingTransaction(make_unique<MsgSip>(0, request.str()), proxyUri);

	BC_ASSERT(asserter.iterateUpTo(
	    5, [&transaction]() { return transaction->getStatus() == 200 and transaction->isCompleted(); }, 2s));

	const auto response = transaction->getResponse();
	BC_ASSERT_CPP_EQUAL(response->getSip()->sip_contact->m_url->url_host, expectedContactHost);
	BC_ASSERT_CPP_EQUAL(response->getSip()->sip_contact->m_url->url_port, expectedContactPort);
}

/*
 * Test call establishment when contact-correction feature is enabled in module::NatHelper.
 */
void makeCall() {
	// Initialization --------------------------------------------------------------------------------------------------
	const string proxyHost = "127.0.0.1";
	InjectedHooks injectedModuleHooks{
	    .injectAfterModule = "GarbageIn",
	    .onRequest =
	        [](std::shared_ptr<RequestSipEvent>& ev) {
		        const auto* sip = ev->getSip();
		        const auto sipm = ev->getMsgSip()->getSipMethod();
		        if (sipm == sip_method_register or (sipm == sip_method_invite and sip->sip_to->a_tag == nullptr)) {
			        // Modify "Contact" header host:port, so it triggers "Contact" header correction.
			        auto* contact = sip->sip_contact;
			        contact->m_url->url_host = "1.2.3.4";
			        contact->m_url->url_port = "1234";
		        }
	        },
	};
	Server proxy{
	    {
	        {"global/aliases", "localhost"},
	        {"global/transports", "sip:" + proxyHost + ":0;transport=tcp"},
	        {"module::MediaRelay/enabled", "false"},
	        {"module::Registrar/enabled", "true"},
	        {"module::Registrar/reg-domains", "localhost"},
	        {"module::NatHelper/enabled", "true"},
	        {"module::NatHelper/nat-traversal-strategy", "contact-correction"},
	        {"module::NatHelper/contact-correction-param", "verified"},
	    },
	    &injectedModuleHooks,
	};
	proxy.start();

	auto builder = ClientBuilder(*proxy.getAgent());
	builder.setIce(OnOff::Off);
	auto caller = builder.build("sip:caller@localhost");
	auto callee = builder.build("sip:callee@localhost");
	CoreAssert asserter{caller.getCore(), proxy, callee.getCore()};
	// -----------------------------------------------------------------------------------------------------------------
	const auto call = caller.call(callee);
	BC_HARD_ASSERT(call != nullptr);
	call->terminate();
}

} // namespace ContactCorrection

namespace FlowToken {

/*
 * Test register of a user agent client that is "hidden" behind a NAT.
 *
 * The UAC sends a register request through a certain flow (association of ip:port and transport protocol). The proxy
 * adds a "Path" header to the contact information in the RegistrarDB. This "Path" header contains a sip uri. The user
 * part of the sip uri contains a flow-token.
 * Information in the flow-token must match the flow used to send the REGISTER request.
 */
void registerUser() {
	// Initialization --------------------------------------------------------------------------------------------------
	string clientPort{};
	const string proxyHost = "127.0.0.1";
	InjectedHooks injectedModuleHooks{
	    .onRequest =
	        [&clientPort](std::shared_ptr<RequestSipEvent>& ev) {
		        // Retrieve client port that was randomly chosen.
		        clientPort = ev->getMsgSip()->getSip()->sip_via->v_rport;
	        },
	};
	Server proxy{
	    {
	        {"global/aliases", "localhost"},
	        {"global/transports", "sip:" + proxyHost + ":0;transport=tcp"},
	        {"module::Registrar/enabled", "true"},
	        {"module::Registrar/reg-domains", "localhost"},
	        {"module::NatHelper/enabled", "true"},
	        {"module::NatHelper/nat-traversal-strategy", "flow-token"},
	        {"module::NatHelper/force-flow-token", "true"},
	    },
	    &injectedModuleHooks,
	};
	proxy.start();
	const auto proxyHostPort = proxyHost + ":"s + string(proxy.getFirstPort());
	const string proxyUri{"sip:" + proxyHostPort + ";transport=tcp"};

	class ContactInfoGetter : public ContactUpdateListener {
	public:
		~ContactInfoGetter() override = default;

		void onContactUpdated(const std::shared_ptr<ExtendedContact>&) override {
		}
		void onRecordFound(const std::shared_ptr<Record>& r) override {
			mPath = r->getExtendedContacts().latest()->get()->mPath.front();
		};
		void onError(const SipStatus&) override {
		}
		void onInvalid(const SipStatus&) override {
		}

		string mPath;
	};

	const FlowFactory flowFactory{FLOW_TOKEN_HASH_KEY_FILE_PATH};
	const auto contactInfoGetter = make_shared<ContactInfoGetter>();
	NtaAgent client{proxy.getRoot(), "sip:" + proxyHost + ":0;transport=tcp"};
	BcAssert asserter{[&proxy] { proxy.getRoot()->step(1ms); }};
	// -----------------------------------------------------------------------------------------------------------------

	ostringstream request{};
	request << "REGISTER sip:user@localhost SIP/2.0\r\n"
	        << "From: <sip:user@localhost>;tag=stub-tag\r\n"
	        << "To: <sip:user@localhost>\r\n"
	        << "CSeq: 20 REGISTER\r\n"
	        << "Call-ID: stub-id.\r\n"
	        << "Supported: replaces, outbound, gruu, path, record-aware\r\n"
	        << "Contact: <sip:user@1.2.3.4:1234;transport=tcp;ob>\r\n"
	        << "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO\r\n"
	        << "Expires: 60\r\n";

	const auto transaction = client.createOutgoingTransaction(make_unique<MsgSip>(0, request.str()), proxyUri);

	BC_ASSERT(asserter.iterateUpTo(
	    5, [&transaction]() { return transaction->getStatus() == 200 and transaction->isCompleted(); }, 2s));

	// Fetch contact from the DB because the "Path" header is not provided in the response of the REGISTER request.

	proxy.getAgent()->getRegistrarDb().fetch(SipUri("sip:user@localhost"), contactInfoGetter);
	const auto flow = flowFactory.create(contactInfoGetter->mPath.substr(4, 32));
	BC_ASSERT(flow.isFalsified() == false);
	BC_ASSERT_CPP_EQUAL(flow.getData().getLocalAddress()->str(), proxyHostPort);
	BC_ASSERT_CPP_EQUAL(flow.getData().getRemoteAddress()->str(), proxyHost + ":" + clientPort);
	BC_ASSERT(flow.getData().getTransportProtocol() == FlowData::Transport::Protocol::tcp);
}

/*
 * Test call establishment when flow-token feature is enabled in module::NatHelper.
 */
void makeCall() {
	// Initialization --------------------------------------------------------------------------------------------------
	const string proxyHost = "127.0.0.1";
	Server proxy{{
	    {"global/aliases", "localhost"},
	    {"global/transports", "sip:" + proxyHost + ":0;transport=tcp"},
	    {"module::MediaRelay/enabled", "false"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "localhost"},
	    {"module::NatHelper/enabled", "true"},
	    {"module::NatHelper/nat-traversal-strategy", "flow-token"},
	    {"module::NatHelper/force-flow-token", "true"},
	}};
	proxy.start();

	auto builder = ClientBuilder(*proxy.getAgent());
	builder.setIce(OnOff::Off);
	auto caller = builder.build("sip:caller@localhost");
	auto callee = builder.build("sip:callee@localhost");
	CoreAssert asserter{caller.getCore(), proxy, callee.getCore()};
	// -----------------------------------------------------------------------------------------------------------------
	const auto call = caller.call(callee);
	BC_HARD_ASSERT(call != nullptr);
	call->terminate();
}

} // namespace FlowToken

TestSuite _("NatTraversal",
            {
                CLASSY_TEST(ContactCorrection::registerUser),
                CLASSY_TEST(ContactCorrection::makeCall),
                CLASSY_TEST(FlowToken::registerUser),
                CLASSY_TEST(FlowToken::makeCall),
            });

} // namespace

} // namespace flexisip::tester