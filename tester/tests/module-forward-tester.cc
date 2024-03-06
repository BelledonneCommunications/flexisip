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

#include "module-forward.hh"

#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "flexisip/event.hh"

#include "transaction/outgoing-transaction.hh"
#include "utils/asserts.hh"
#include "utils/contact-inserter.hh"
#include "utils/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace sofiasip;

namespace flexisip::tester {

namespace {

struct Helper {
	class MockedOutgoingTransaction : public OutgoingTransaction {
	public:
		explicit MockedOutgoingTransaction(const std::shared_ptr<Agent>& agent) : OutgoingTransaction(agent) {
		}

		/*
		 * Code executed when the request is being sent.
		 * It intercepts the request before it is actually sent so that we can verify content of the request to be
		 * forwarded.
		 */
		void send(const std::shared_ptr<MsgSip>& msg, url_string_t const* u, tag_type_t, tag_value_t, ...) override {
			auto* home = msg->getHome();

			mRequestSent = true;
			mRequestUri = u ? url_as_string(home, u->us_url) : "";
			if (const auto* sip = msg->getSip(); sip != nullptr) {
				mRequestMethod = sip->sip_request ? sip->sip_request->rq_method : sip_method_unknown;

				auto* it = sip->sip_route;
				while (it != nullptr) {
					mRoutes.emplace_back(url_as_string(home, sip->sip_route->r_url));
					it = it->r_next;
				}
			}
		}

		std::weak_ptr<Agent> getAgent() noexcept override {
			return OutgoingTransaction::getAgent();
		};

		vector<string> mRoutes{};
		string mRequestUri{};
		bool mRequestSent{false};
		sip_method_t mRequestMethod{};
	};

	struct Contact {
		string aor{};
		string uri{};
		string uid{};
		vector<string> path{};
	};
};

/*
 * Context: mid-dialog request intended to a GRUU address.
 * Test the request is actually sent to the sip address in the Route header.
 */
void forwardMidDialogRequestRouteIsNotUs() {
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	    {"module::Forward/enabled", "true"},
	}};
	proxy.start();

	string routeUri = "<sip:unreachable-route:0;transport=tcp>";
	Helper::Contact caller{
	    .aor = "sip:caller@sip.example.org",
	    .uri = "sip:caller@unreachable-domain:0",
	    .uid = "caller-uid",
	    .path = {"<sip:unreachable-domain:0;transport=tcp>"},
	};
	Helper::Contact callee{
	    .aor = "sip:callee@sip.example.org",
	    .uri = "sip:callee@unreachable-domain:0",
	    .uid = "callee-uid",
	    .path =
	        {
	            "<sip:127.0.0.1:"s + proxy.getFirstPort() + ";transport=tcp>",
	            "<sip:unreachable-domain:0;transport=tcp>",
	        },
	};

	stringstream request;
	request << "BYE " << callee.aor << ";gr=" << callee.uid << " SIP/2.0\r\n"
	        << "Via: SIP/2.0/TCP 127.0.0.1\r\n"
	        << "From: \"Caller\" <" << caller.aor << ">;tag=stub-from-tag\r\n"
	        << "To: \"Callee\" <" << callee.aor << ">;tag=stub-to-tag\r\n"
	        << "CSeq: 21 BYE\r\n"
	        << "Call-ID: stub-id\r\n"
	        << "Route: " << routeUri << "\r\n"
	        << "User-Agent: stub-user-agent\r\n"
	        << "Content-Length: 0\r\n";

	auto transaction = make_shared<Helper::MockedOutgoingTransaction>(proxy.getAgent());
	auto event = make_shared<RequestSipEvent>(proxy.getAgent(), make_shared<MsgSip>(0, request.str()), nullptr);
	event->setOutgoingAgent(transaction);

	const auto module = dynamic_pointer_cast<ForwardModule>(proxy.getAgent()->findModule("Forward"));
	module->onRequest(event);

	BC_HARD_ASSERT(transaction->mRequestSent == true);
	BC_ASSERT(transaction->mRequestMethod == sip_method_bye);
	BC_ASSERT_CPP_EQUAL(transaction->mRequestUri, routeUri.substr(1, routeUri.size() - 2));
	BC_ASSERT_CPP_EQUAL(transaction->mRoutes.size(), 1);
	BC_ASSERT_CPP_EQUAL(transaction->mRoutes.front(), transaction->mRequestUri);
}

/*
 * Context: mid-dialog request intended to a GRUU address.
 * Test the path indicated in the registrar database (for a given contact) is correctly transformed into a route and
 * used to forward the request.
 */
void forwardMidDialogRequestPathIsNextHop() {
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	    {"module::Forward/enabled", "true"},
	}};
	proxy.start();

	Helper::Contact caller{
	    .aor = "sip:caller@sip.example.org",
	    .uri = "sip:caller@unreachable-domain:0",
	    .uid = "caller-uid",
	    .path = {"<sip:unreachable-domain:0;transport=tcp>"},
	};
	Helper::Contact callee{
	    .aor = "sip:callee@sip.example.org",
	    .uri = "sip:callee@unreachable-domain:0",
	    .uid = "callee-uid",
	    .path =
	        {
	            "<sip:127.0.0.1:"s + proxy.getFirstPort() + ";transport=tcp>",
	            "<sip:unreachable-domain:0;transport=tcp>",
	            "<sip:127.0.0.1:"s + proxy.getFirstPort() + ";transport=tcp>",
	        },
	};

	BcAssert asserter{};
	ContactInserter inserter{proxy.getAgent()->getRegistrarDb()};
	inserter.setAor(callee.aor)
	    .setExpire(1min)
	    .withGruu(true)
	    .setPath(callee.path)
	    .insert({.contact = callee.uri, .uniqueId = callee.uid});
	BC_HARD_ASSERT(asserter.iterateUpTo(5, [&inserter]() { return inserter.finished(); }, 2s));

	stringstream request;
	request << "BYE " << callee.aor << ";gr=" << callee.uid << " SIP/2.0\r\n"
	        << "Via: SIP/2.0/TCP 127.0.0.1\r\n"
	        << "From: \"Caller\" <" << caller.aor << ">;tag=stub-from-tag\r\n"
	        << "To: \"Callee\" <" << callee.aor << ">;tag=stub-to-tag\r\n"
	        << "CSeq: 21 BYE\r\n"
	        << "Call-ID: stub-id\r\n"
	        << "User-Agent: stub-user-agent\r\n"
	        << "Content-Length: 0\r\n";

	auto transaction = make_shared<Helper::MockedOutgoingTransaction>(proxy.getAgent());
	auto event = make_shared<RequestSipEvent>(proxy.getAgent(), make_shared<MsgSip>(0, request.str()), nullptr);
	event->setOutgoingAgent(transaction);

	const auto module = dynamic_pointer_cast<ForwardModule>(proxy.getAgent()->findModule("Forward"));
	module->onRequest(event);

	BC_HARD_ASSERT(transaction->mRequestSent == true);
	BC_ASSERT(transaction->mRequestMethod == sip_method_bye);
	BC_ASSERT_CPP_EQUAL(transaction->mRequestUri, callee.path[1].substr(1, callee.path[1].size() - 2) + ";lr");
	BC_ASSERT_CPP_EQUAL(transaction->mRoutes.size(), 2);
	BC_ASSERT_CPP_EQUAL(transaction->mRoutes.front(), transaction->mRequestUri);
}

/*
 * Context: mid-dialog request intended to a GRUU address.
 * Test the path indicated in the registrar database (for a given contact) is us so the destination should be set to the
 * contact uri.
 */
void forwardMidDialogRequestPathIsUsSoUseContactUrl() {
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	    {"module::Forward/enabled", "true"},
	}};
	proxy.start();

	Helper::Contact caller{
	    .aor = "sip:caller@sip.example.org",
	    .uri = "sip:caller@unreachable-domain:0",
	    .uid = "caller-uid",
	    .path = {"<sip:unreachable-domain:0;transport=tcp>"},
	};
	Helper::Contact callee{
	    .aor = "sip:callee@sip.example.org",
	    .uri = "sip:callee@unreachable-domain:0",
	    .uid = "callee-uid",
	    .path = {"<sip:127.0.0.1:"s + proxy.getFirstPort() + ";transport=tcp>"},
	};

	BcAssert asserter{};
	ContactInserter inserter{proxy.getAgent()->getRegistrarDb()};
	inserter.setAor(callee.aor)
	    .setExpire(1min)
	    .withGruu(true)
	    .setPath(callee.path)
	    .insert({.contact = callee.uri, .uniqueId = callee.uid});
	BC_HARD_ASSERT(asserter.iterateUpTo(5, [&inserter]() { return inserter.finished(); }, 2s));

	stringstream request;
	request << "BYE " << callee.aor << ";gr=" << callee.uid << " SIP/2.0\r\n"
	        << "Via: SIP/2.0/TCP 127.0.0.1\r\n"
	        << "From: \"Caller\" <" << caller.aor << ">;tag=stub-from-tag\r\n"
	        << "To: \"Callee\" <" << callee.aor << ">;tag=stub-to-tag\r\n"
	        << "CSeq: 21 BYE\r\n"
	        << "Call-ID: stub-id\r\n"
	        << "User-Agent: stub-user-agent\r\n"
	        << "Content-Length: 0\r\n";

	auto transaction = make_shared<Helper::MockedOutgoingTransaction>(proxy.getAgent());
	auto event = make_shared<RequestSipEvent>(proxy.getAgent(), make_shared<MsgSip>(0, request.str()), nullptr);
	event->setOutgoingAgent(transaction);

	const auto module = dynamic_pointer_cast<ForwardModule>(proxy.getAgent()->findModule("Forward"));
	module->onRequest(event);

	BC_HARD_ASSERT(transaction->mRequestSent == true);
	BC_ASSERT(transaction->mRequestMethod == sip_method_bye);
	BC_ASSERT_CPP_EQUAL(transaction->mRequestUri, callee.uri);
	BC_ASSERT(transaction->mRoutes.empty());
}

TestSuite _("ForwardModule",
            {
                CLASSY_TEST(forwardMidDialogRequestRouteIsNotUs),
                CLASSY_TEST(forwardMidDialogRequestPathIsNextHop),
                CLASSY_TEST(forwardMidDialogRequestPathIsUsSoUseContactUrl),
            });

} // namespace

} // namespace flexisip::tester

