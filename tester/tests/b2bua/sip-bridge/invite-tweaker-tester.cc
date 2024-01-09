/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "b2bua/sip-bridge/invite-tweaker.hh"

#include <linphone/misc.h>

#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/client-core.hh"
#include "utils/injected-module-info.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace flexisip::tester {
namespace {
using namespace flexisip::b2bua::bridge;
using namespace std::chrono_literals;

void test() {
	const SipUri expectedToAddress{"sip:expected-to@to.example.org:666;custom-param=To"};
	InjectedHooks hooks{
	    .onRequest =
	        [&expectedToAddress](const std::shared_ptr<RequestSipEvent>& requestEvent) {
		        const auto* sip = requestEvent->getSip();
		        // Mangle To header
		        sip->sip_to->a_url[0] = *expectedToAddress.get();
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
	const auto& builder = ClientBuilder(*proxy.getAgent());
	const auto& caller = builder.build("sip:expected-from@sip.example.org;custom-param=From");
	const auto& b2bua = builder.build("sip:expected-request-uri@sip.example.org;custom-param=RequestUri");
	caller.invite(b2bua);
	BC_HARD_ASSERT_TRUE(b2bua.hasReceivedCallFrom(caller));
	const auto forgedCall = ClientCall::getLinphoneCall(*b2bua.getCurrentCall());
	{
		const auto& requestUri = forgedCall->getRequestAddress();
		BC_HARD_ASSERT(requestUri != nullptr);
		BC_ASSERT_CPP_EQUAL(requestUri->getUsername(), "expected-request-uri");
		BC_ASSERT_CPP_EQUAL(requestUri->getUriParam("custom-param"), "RequestUri");
		const auto& toAddress = forgedCall->getToAddress();
		BC_HARD_ASSERT(toAddress != nullptr);
		BC_ASSERT_CPP_EQUAL(toAddress->getUsername(), "expected-to");
		BC_ASSERT_CPP_EQUAL(toAddress->getUriParam("custom-param"), "To");
		const auto& fromAddress = forgedCall->getRemoteAddress();
		BC_ASSERT_CPP_EQUAL(fromAddress->getUsername(), "expected-from");
		BC_ASSERT_CPP_EQUAL(fromAddress->getUriParam("custom-param"), "From");
	}
	auto& b2buaCore = *b2bua.getCore();
	auto forgedAccountAddress = b2buaCore.createAddress("sip:expected-account@account.example.org");
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
		BC_ASSERT_CPP_EQUAL(outgoingCallParams->getFromHeader(), "");
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
		BC_ASSERT_CPP_EQUAL(toAddress->asStringUriOnly(), "sip:expected-account@to.example.org:666;custom-param=From");
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
		BC_ASSERT_CPP_EQUAL(outgoingCallParams->getFromHeader(), "sip:expected-from@sip.example.org;custom-param=From");
	}
}

TestSuite _{
    "b2bua::bridge::InviteTweaker",
    {
        CLASSY_TEST(test),
    },
};
} // namespace
} // namespace flexisip::tester
