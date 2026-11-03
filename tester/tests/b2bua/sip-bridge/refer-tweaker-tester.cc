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

#include "b2bua/sip-bridge/refer-tweaker.hh"

#include "b2bua/sip-bridge/accounts/account.hh"
#include "b2bua/sip-bridge/configuration/v2/v2.hh"
#include "b2bua/sip-bridge/linphone-call-context.hh"
#include "tweaker-tester.hh"
#include "utils/client-core.hh"
#include "utils/string-interpolation/exceptions.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip::tester {
namespace {

using namespace flexisip::b2bua::bridge;

// The call context of a transfer: the 'to', 'from' and 'requestUri' fields all designate the transfer target.
LinphoneCallContext makeTransferContext() {
	return {
	    .to = makeAddress("sip:transfer-target@external.example.org"),
	    .from = makeAddress("sip:transfer-target@external.example.org"),
	    .requestUri = makeAddress("sip:transfer-target@external.example.org"),
	};
}

struct SuiteHelper {
	std::shared_ptr<linphone::Core> core{minimalCore()};
	std::shared_ptr<Account> account{
	    makeAccount(core, "sip:eellac@external.example.org", "sip:callee@flexisip.example.org"),
	};
	LinphoneCallContext context{makeTransferContext()};
};

std::shared_ptr<SuiteHelper> sSuite{};

/**
 * Test case: the Refer-To header is rendered with the To translation rule.
 * The rule only uses 'incoming' variables here.
 */
void referToIsRenderedWithTheToRule() {
	const ReferTweaker tweaker{config::v2::OutgoingInvite{
	    .to = "{incoming.to}",
	    .from = "sip:unused-from@external.example.org",
	}};

	const auto referTo = tweaker.tweakRefer(sSuite->context, *sSuite->account, ReferTweaker::HeaderTranslation::To);
	BC_ASSERT(referTo != nullptr);
	BC_ASSERT_CPP_EQUAL(referTo->asStringUriOnly(), "sip:transfer-target@external.example.org");
}

/**
 * Test case: the Refer-To header is rendered with the From translation rule.
 * The rule only uses 'account' variables here.
 */
void referToIsRenderedWithTheFromRule() {
	const ReferTweaker tweaker{config::v2::OutgoingInvite{
	    .to = "sip:unused-to@external.example.org",
	    .from = "{account.uri}",
	}};

	const auto referTo = tweaker.tweakRefer(sSuite->context, *sSuite->account, ReferTweaker::HeaderTranslation::From);
	BC_ASSERT(referTo != nullptr);
	BC_ASSERT_CPP_EQUAL(referTo->asStringUriOnly(), "sip:eellac@external.example.org");
}

/**
 * Test case: the From translation rule mixes 'incoming' and 'account' variables.
 */
void mixedIncomingAndAccountTemplate() {
	const ReferTweaker tweaker{config::v2::OutgoingInvite{
	    .to = "sip:unused-to@external.example.org",
	    .from = "sip:{account.uri.user}@{incoming.to.hostport}",
	}};

	const auto referTo = tweaker.tweakRefer(sSuite->context, *sSuite->account, ReferTweaker::HeaderTranslation::From);
	BC_ASSERT(referTo != nullptr);
	BC_ASSERT_CPP_EQUAL(referTo->asStringUriOnly(), "sip:eellac@external.example.org");
}

/**
 * Test case: the From translation rule is left empty.
 * It defaults to the {account.uri} of the account.
 */
void emptyFromRuleDefaultsToTheAccountUri() {
	const ReferTweaker tweaker{config::v2::OutgoingInvite{
	    .to = "sip:unused-to@external.example.org",
	    .from = "",
	}};

	const auto referTo = tweaker.tweakRefer(sSuite->context, *sSuite->account, ReferTweaker::HeaderTranslation::From);
	BC_ASSERT(referTo != nullptr);
	BC_ASSERT_CPP_EQUAL(referTo->asStringUriOnly(), "sip:eellac@external.example.org");
}

/**
 * Test case: the transfer context binds the To, From and request-URI fields to the Refer-To target.
 * Every 'incoming' field of a template therefore resolves to the Refer-To data, whichever the translation rule.
 */
void everyIncomingFieldResolvesToTheReferToTarget() {
	const ReferTweaker tweaker{config::v2::OutgoingInvite{
	    .to = "sip:{incoming.to.user}@{incoming.to.hostport}",
	    .from = "sip:{incoming.from.user}@{incoming.requestUri.hostport}",
	}};

	const auto toRule = tweaker.tweakRefer(sSuite->context, *sSuite->account, ReferTweaker::HeaderTranslation::To);
	BC_ASSERT(toRule != nullptr);
	BC_ASSERT_CPP_EQUAL(toRule->asStringUriOnly(), "sip:transfer-target@external.example.org");

	const auto fromRule = tweaker.tweakRefer(sSuite->context, *sSuite->account, ReferTweaker::HeaderTranslation::From);
	BC_ASSERT(fromRule != nullptr);
	BC_ASSERT_CPP_EQUAL(fromRule->asStringUriOnly(), "sip:transfer-target@external.example.org");
}

/**
 * Test case: a template uses an unknown variable.
 * The tweaker must reject the configuration at construction time, for either translation rule.
 */
void unknownTokenIsRejectedAtConstruction() {
	// Unknown field in a known namespace, in the To rule.
	BC_ASSERT_THROWN((ReferTweaker{config::v2::OutgoingInvite{
	                     .to = "{incoming.unknown}",
	                     .from = "sip:static@external.example.org",
	                 }}),
	                 utils::string_interpolation::ResolutionError);
	// Unknown namespace, in the From rule.
	BC_ASSERT_THROWN((ReferTweaker{config::v2::OutgoingInvite{
	                     .to = "sip:static@external.example.org",
	                     .from = "{unknown.variable}",
	                 }}),
	                 utils::string_interpolation::ResolutionError);
}

TestSuite _{
    "b2bua::sip-bridge::ReferTweaker",
    {
        CLASSY_TEST(referToIsRenderedWithTheToRule),
        CLASSY_TEST(referToIsRenderedWithTheFromRule),
        CLASSY_TEST(mixedIncomingAndAccountTemplate),
        CLASSY_TEST(emptyFromRuleDefaultsToTheAccountUri),
        CLASSY_TEST(everyIncomingFieldResolvesToTheReferToTarget),
        CLASSY_TEST(unknownTokenIsRejectedAtConstruction),
    },
    Hooks{}.beforeEach([] { sSuite = make_shared<SuiteHelper>(); }).afterEach([] { sSuite.reset(); }),
};

} // namespace
} // namespace flexisip::tester
