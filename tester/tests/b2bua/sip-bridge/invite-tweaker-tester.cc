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

#include "b2bua/sip-bridge/invite-tweaker.hh"

#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/core-assert.hh"
#include "utils/server/injected-module-info.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace flexisip::tester {
namespace {

using namespace flexisip::b2bua::bridge;
using namespace std::chrono_literals;

// Create an INVITE with a different username for the TO header and the request URI to test diffent INVITE modifiers
void test() {
	const SipUri expectedToAddress{"sip:*%23expected-to@to.example.org:666;custom-param=%26$To"};
	InjectedHooks hooks{
	    .onRequest =
	        [&expectedToAddress](std::unique_ptr<RequestSipEvent>&& requestEvent) {
		        const auto* sip = requestEvent->getSip();
		        if (sip->sip_request->rq_method != sip_method_invite) return std::move(requestEvent);

		        // Mangle To header
		        sip->sip_to->a_url[0] = *expectedToAddress.get();
		        return std::move(requestEvent);
	        },
	};
	Server proxy{
	    {
	        // Requesting bind on port 0 to let the kernel find any available port
	        {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	        {"module::Registrar/enabled", "true"},
	        {"module::Registrar/reg-domains", "sip.example.org"},
	    },
	    &hooks,
	};
	proxy.start();
	auto builder = ClientBuilder(proxy.getAgent());
	builder.setRegistration(OnOff::Off);
	const auto caller = builder.build("sip:expected-from@sip.example.org;custom-param=%40/From");
	const auto b2bua = builder.build(expectedToAddress.str());
	SipUri expectedRequestUri = SipUri("sip:expected-request-uri@127.0.0.1:" + std::to_string(b2bua.getTcpPort()) +
	                                   ";custom-param=RequestUri;transport=tcp");
	caller.invite(expectedRequestUri.str());
	BC_HARD_ASSERT_TRUE(b2bua.hasReceivedCallFrom(caller, CoreAssert{proxy, caller, b2bua}));
	const auto forgedCall = ClientCall::getLinphoneCall(*b2bua.getCurrentCall());
	// Ensure initial INVITE has been correctly created
	{
		const auto& requestUri = forgedCall->getRequestAddress();
		BC_HARD_ASSERT(requestUri != nullptr);
		BC_ASSERT_CPP_EQUAL(requestUri->getUsername(), "expected-request-uri");
		BC_ASSERT_CPP_EQUAL(requestUri->getUriParam("custom-param"), "RequestUri");
		const auto& toAddress = forgedCall->getToAddress();
		BC_HARD_ASSERT(toAddress != nullptr);
		BC_ASSERT_CPP_EQUAL(toAddress->getUsername(), "*#expected-to");
		BC_ASSERT_CPP_EQUAL(toAddress->getUriParam("custom-param"), "&$To");
		const auto& fromAddress = forgedCall->getRemoteAddress();
		BC_ASSERT_CPP_EQUAL(fromAddress->getUsername(), "expected-from");
		BC_ASSERT_CPP_EQUAL(fromAddress->getUriParam("custom-param"), "@/From");
	}
	auto& b2buaCore = *b2bua.getCore();
	auto forgedAccountAddress = b2buaCore.createAddress("sip:%25=expected-account@account.example.org");
	BC_HARD_ASSERT(forgedAccountAddress != nullptr);
	auto forgedAccountParams = b2buaCore.createAccountParams();
	BC_HARD_ASSERT(forgedAccountParams != nullptr);
	forgedAccountParams->setIdentityAddress(forgedAccountAddress);
	auto forgedLinphoneAccount = b2buaCore.createAccount(forgedAccountParams);
	BC_HARD_ASSERT(forgedLinphoneAccount != nullptr);
	const std::string_view expectedAlias{"sip:expected-alias@alias.example.org;custom-param=Alias"};
	Account forgedAccount{forgedLinphoneAccount, 0x7E57, expectedAlias};

	{
		const auto& outgoingCallParams = b2buaCore.createCallParams(forgedCall);
		const auto& toAddress =
		    InviteTweaker{{.to = "sip:{incoming.requestUri.user}@stub.example.org{incoming.requestUri.uriParameters}"},
		                  b2buaCore}
		        .tweakInvite(*forgedCall, forgedAccount, *outgoingCallParams);
		BC_ASSERT_CPP_EQUAL(toAddress->asStringUriOnly(),
		                    "sip:expected-request-uri@stub.example.org;custom-param=RequestUri;transport=tcp");
		BC_ASSERT_CPP_EQUAL(outgoingCallParams->getFromHeader(), "sip:%25=expected-account@account.example.org");
	}

	{
		const auto& outgoingCallParams = b2buaCore.createCallParams(forgedCall);
		const auto& toAddress = InviteTweaker{{.to = "{incoming.to}"}, b2buaCore}.tweakInvite(
		    *forgedCall, forgedAccount, *outgoingCallParams);
		BC_ASSERT_CPP_EQUAL(toAddress->asStringUriOnly(), expectedToAddress.str());
	}

	{
		const auto& outgoingCallParams = b2buaCore.createCallParams(forgedCall);
		const auto& toAddress = InviteTweaker{{.to = "{incoming.requestUri}"}, b2buaCore}.tweakInvite(
		    *forgedCall, forgedAccount, *outgoingCallParams);
		BC_ASSERT_CPP_EQUAL(toAddress->getUsername(), "expected-request-uri");
		BC_ASSERT_CPP_EQUAL(toAddress->getDomain(), "127.0.0.1");
	}

	{
		const auto& outgoingCallParams = b2buaCore.createCallParams(forgedCall);
		const auto& toAddress =
		    InviteTweaker{{.to = "sip:{account.uri.user}@{incoming.to.hostport}{incoming.from.uriParameters}"},
		                  b2buaCore}
		        .tweakInvite(*forgedCall, forgedAccount, *outgoingCallParams);
		BC_ASSERT_CPP_EQUAL(toAddress->asStringUriOnly(),
		                    "sip:%25=expected-account@to.example.org:666;custom-param=%40/From");
	}

	{
		const auto& outgoingCallParams = b2buaCore.createCallParams(forgedCall);
		const auto& toAddress = InviteTweaker{{.to = "{account.alias}"}, b2buaCore}.tweakInvite(
		    *forgedCall, forgedAccount, *outgoingCallParams);
		BC_ASSERT_CPP_EQUAL(toAddress->asStringUriOnly(), expectedAlias);
	}

	{
		const auto& outgoingCallParams = b2buaCore.createCallParams(forgedCall);
		std::ignore = InviteTweaker{{.to = "sip:stub@example.org", .from = "{incoming.from}"}, b2buaCore}.tweakInvite(
		    *forgedCall, forgedAccount, *outgoingCallParams);
		BC_ASSERT_CPP_EQUAL(outgoingCallParams->getFromHeader(),
		                    "sip:expected-from@sip.example.org;custom-param=%40/From");
	}
}

TestSuite _{
    "b2bua::sip-bridge::InviteTweaker",
    {
        CLASSY_TEST(test),
    },
};

} // namespace
} // namespace flexisip::tester