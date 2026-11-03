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

#include "b2bua/sip-bridge/invite-tweaker.hh"

#include "b2bua/sip-bridge/accounts/account.hh"
#include "b2bua/sip-bridge/linphone-call-context.hh"
#include "exceptions/bad-configuration.hh"
#include "tweaker-tester.hh"
#include "utils/client-core.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip::tester {
namespace {

using namespace flexisip::b2bua::bridge;

struct SuiteHelper {
	std::shared_ptr<linphone::Core> core{minimalCore()};
	std::shared_ptr<Account> account{
	    makeAccount(core, "sip:eellac@external.example.org", "sip:callee@flexisip.example.org"),
	};
	std::shared_ptr<LinphoneCallContext> context{
	    make_shared<LinphoneCallContext>(makeAddress("sip:caller@flexisip.example.org"),
	                                     makeAddress("sip:callee@flexisip.example.org"),
	                                     makeAddress("sip:callee@flexisip.example.org")),
	};
};

std::shared_ptr<SuiteHelper> sSuite{};

// Render an outgoing INVITE with the given configuration and account, without any server or client involved.
// Returns the tweaked To address and the call params it has been rendered into.
std::pair<std::shared_ptr<linphone::Address>, std::shared_ptr<linphone::CallParams>>
tweakInvite(const std::shared_ptr<linphone::Core>& core,
            const LinphoneCallContext& context,
            const config::v2::OutgoingInvite& config,
            const Account& account) {
	const auto outgoingCallParams = core->createCallParams(nullptr);
	BC_HARD_ASSERT(outgoingCallParams != nullptr);

	return {
	    InviteTweaker{config, *core}.tweakInvite(context, account, *outgoingCallParams),
	    outgoingCallParams,
	};
}

/**
 * Test case: The To and From headers are rendered with the account selected for the outgoing call.
 * That account also places the call.
 */
void toAndFromHeadersAreRenderedWithTheSelectedAccount() {
	const auto& [toAddress, outgoingCallParams] = tweakInvite(sSuite->core, *sSuite->context,
	                                                          {
	                                                              .to = "{account.uri}",
	                                                              .from = "{account.uri}",
	                                                          },
	                                                          *sSuite->account);

	const auto expectedAddress = sSuite->account->getLinphoneAccount()->getContactAddress()->asStringUriOnly();
	BC_ASSERT_CPP_EQUAL(toAddress->asStringUriOnly(), expectedAddress);
	BC_ASSERT_CPP_EQUAL(outgoingCallParams->getFromHeader(), expectedAddress);
	const auto placingAccountIdentity = outgoingCallParams->getAccount()->getParams()->getIdentityAddress()->asString();
	BC_ASSERT_CPP_EQUAL(placingAccountIdentity, expectedAddress);
}

/**
 * Test case: the From template is left empty.
 * It defaults to the {account.uri} of the selected account.
 */
void emptyFromTemplateDefaultsToTheAccountUri() {
	const auto& [toAddress, outgoingCallParams] = tweakInvite(sSuite->core, *sSuite->context,
	                                                          {
	                                                              .to = "{account.uri}",
	                                                              .from = "",
	                                                          },
	                                                          *sSuite->account);

	const auto expectedAddress = sSuite->account->getLinphoneAccount()->getContactAddress()->asStringUriOnly();
	BC_ASSERT_CPP_EQUAL(toAddress->asStringUriOnly(), expectedAddress);
	BC_ASSERT_CPP_EQUAL(outgoingCallParams->getFromHeader(), expectedAddress);
}

/**
 * Test case: the To and From templates are static.
 * The selected account still places the call, with its own identity.
 */
void staticHeadersAreRenderedAsIs() {
	const string staticToAddress{"sip:static-to@external.example.org"};
	const string staticFromAddress{"sip:static-from@external.example.org"};

	const auto& [toAddress, outgoingCallParams] = tweakInvite(sSuite->core, *sSuite->context,
	                                                          {
	                                                              .to = staticToAddress,
	                                                              .from = staticFromAddress,
	                                                          },
	                                                          *sSuite->account);

	BC_ASSERT_CPP_EQUAL(toAddress->asStringUriOnly(), staticToAddress);
	BC_ASSERT_CPP_EQUAL(outgoingCallParams->getFromHeader(), staticFromAddress);
	const auto expectedPlacingIdentity =
	    sSuite->account->getLinphoneAccount()->getParams()->getIdentityAddress()->asString();
	BC_ASSERT_CPP_EQUAL(outgoingCallParams->getAccount()->getParams()->getIdentityAddress()->asString(),
	                    expectedPlacingIdentity);
}

/**
 * Test case: the To and From headers contain escaped characters.
 * The tweaker should correctly handle and preserve these characters.
 */
void escapedCharacters() {
	const string expectedToAddress{"sip:*%23callee@flexisip.example.org:12345"};
	const string expectedFromAddress{"\"From\" sip:caller@flexisip.example.org;custom-param=%40/From"};
	const string expectedRequestUri{"sip:request-uri@127.0.0.1:54321;custom-param=RequestUri;transport=tcp"};

	const LinphoneCallContext context{
	    .to = makeAddress(expectedToAddress),
	    .from = makeAddress(expectedFromAddress),
	    .requestUri = makeAddress(expectedRequestUri),
	};

	const auto& [toAddress, outgoingCallParams] = tweakInvite(sSuite->core, context,
	                                                          {
	                                                              .to = "{incoming.to.displayName} {incoming.to}",
	                                                              .from = "{incoming.from.displayName} {incoming.from}",
	                                                          },
	                                                          *sSuite->account);

	BC_ASSERT_CPP_EQUAL(toAddress->asStringUriOnly(), expectedToAddress);
	BC_ASSERT_CPP_EQUAL(outgoingCallParams->getFromHeader(), expectedFromAddress);
}

/**
 * Test case: an outbound proxy override is set.
 * The outgoing call is placed by the surrogate account created for the override, routed to the override URI, and the
 * surrogate account is not registered.
 */
void outboundProxyOverridePlacesTheCallWithASurrogateAccount() {
	const auto& [toAddress, outgoingCallParams] =
	    tweakInvite(sSuite->core, *sSuite->context,
	                {
	                    .to = "{account.uri}",
	                    .from = "sip:static-from@external.example.org",
	                    .outboundProxy = "<sip:outbound-proxy.example.org;transport=tcp>",
	                },
	                *sSuite->account);

	BC_ASSERT_CPP_EQUAL(toAddress->asStringUriOnly(), "sip:eellac@external.example.org");

	const auto& placingAccount = outgoingCallParams->getAccount();
	BC_HARD_ASSERT(placingAccount != nullptr);
	BC_ASSERT_CPP_EQUAL(placingAccount->getParams()->getIdentityAddress()->asStringUriOnly(),
	                    "sip:flexisip-b2bua-invite-tweaker@localhost");
	BC_ASSERT_FALSE(placingAccount->getParams()->registerEnabled());

	const auto& routes = placingAccount->getParams()->getRoutesAddresses();
	BC_ASSERT_CPP_EQUAL(routes.size(), 1);
	BC_ASSERT_CPP_EQUAL(routes.front()->asStringUriOnly(), "sip:outbound-proxy.example.org;transport=tcp");
}

/**
 * Test case: the outbound proxy override is not a valid SIP URI.
 * The constructor should throw an exception.
 */
void invalidOutboundProxyOverrideIsRejected() {
	const auto core = minimalCore();

	BC_ASSERT_THROWN((InviteTweaker{
	                     {
	                         .to = "sip:static-to@external.example.org",
	                         .from = "sip:static-from@external.example.org",
	                         .outboundProxy = "not a SIP URI",
	                     },
	                     *core,
	                 }),
	                 BadConfiguration);
}

TestSuite _{
    "b2bua::sip-bridge::InviteTweaker",
    {
        CLASSY_TEST(toAndFromHeadersAreRenderedWithTheSelectedAccount),
        CLASSY_TEST(emptyFromTemplateDefaultsToTheAccountUri),
        CLASSY_TEST(staticHeadersAreRenderedAsIs),
        CLASSY_TEST(escapedCharacters),
        CLASSY_TEST(outboundProxyOverridePlacesTheCallWithASurrogateAccount),
        CLASSY_TEST(invalidOutboundProxyOverrideIsRejected),
    },
    Hooks{}.beforeEach([] { sSuite = make_shared<SuiteHelper>(); }).afterEach([] { sSuite.reset(); }),
};

} // namespace
} // namespace flexisip::tester
