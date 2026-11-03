/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "b2bua/sip-bridge/accounts/selection-strategy/find-in-pool.hh"

#include "b2bua/sip-bridge/accounts/loaders/static-account-loader.hh"
#include "b2bua/sip-bridge/accounts/selection-strategy/pick-random-in-pool.hh"
#include "tests/b2bua/sip-bridge/tweaker-tester.hh"
#include "utils/client-core.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace flexisip::tester {
namespace {

using namespace std;
using namespace flexisip::b2bua;
using namespace flexisip::b2bua::bridge;
using namespace flexisip::b2bua::bridge::account_strat;

// A pool of a few static accounts, loaded synchronously over a minimal Linphone core: no SIP traffic involved.
auto poolWithStaticAccounts() {
	auto poolConfig = R"({
		"outboundProxy": "<sip:some.provider.example.com;transport=tls>",
		"registrationRequired": false,
		"maxCallsPerLine": 55,
		"loader": [
			{
				"uri": "sip:stub-account1@some.provider.example.com",
				"alias": "sip:expected-from@sip.example.org"
			},
			{
				"uri": "sip:expected-to@sip.example.org"
			},
			{
				"uri": "sip:stub-account2@some.provider.example.com",
				"alias": "sip:no-placeholder@static.example.com"
			}
		]
	})"_json.get<config::v2::AccountPool>();
	auto& staticLoader = get<config::v2::StaticLoader>(poolConfig.loader);
	return make_shared<AccountPool>(make_shared<sofiasip::SuRoot>(), reinterpret_pointer_cast<B2buaCore>(minimalCore()),
	                                "test account pool", poolConfig,
	                                make_unique<StaticAccountLoader>(std::move(staticLoader)));
}

// A call context hand-built from plain SIP URIs: no Linphone call is needed to exercise the strategies.
auto callContext(const string& from, const string& to) {
	const auto factory = linphone::Factory::get();
	return LinphoneCallContext{
	    .to = factory->createAddress(to),
	    .from = factory->createAddress(from),
	    .requestUri = factory->createAddress(to),
	};
}

/**
 * Test how a few basic FindInPool strategies choose accounts with different configs.
 */
void chooseAccountForThisCall() {
	const string incomingFrom{"sip:expected-from@sip.example.org"};
	const string incomingTo{"sip:expected-to@sip.example.org"};
	const auto pool = poolWithStaticAccounts();

	{
		auto config = R"({"by": "alias", "source": "{from}"})"_json.get<config::v2::account_selection::FindInPool>();
		const auto account = FindInPool(pool, config).chooseAccountForThisCall(callContext(incomingFrom, incomingTo));

		BC_HARD_ASSERT(account != nullptr);
		BC_ASSERT_CPP_EQUAL(account->getAlias().str(), incomingFrom);
	}

	{
		auto config = R"({"by": "uri", "source": "{to}"})"_json.get<config::v2::account_selection::FindInPool>();
		const auto account = FindInPool(pool, config).chooseAccountForThisCall(callContext(incomingFrom, incomingTo));

		BC_HARD_ASSERT(account != nullptr);
		BC_ASSERT_CPP_EQUAL(account->getLinphoneAccount()->getParams()->getIdentityAddress()->asStringUriOnly(),
		                    incomingTo);
	}

	{
		auto config = R"({"by": "alias", "source": "sip:no-placeholder@static.example.com"})"_json
		                  .get<config::v2::account_selection::FindInPool>();
		const auto account = FindInPool(pool, config).chooseAccountForThisCall(callContext(incomingFrom, incomingTo));

		BC_HARD_ASSERT(account != nullptr);
		BC_ASSERT_CPP_EQUAL(account->getAlias().str(), "sip:no-placeholder@static.example.com");
	}

	{
		auto config = R"({"by": "uri", "source": "{from}"})"_json.get<config::v2::account_selection::FindInPool>();
		const auto account =
		    FindInPool(pool, config).chooseAccountForThisCall(callContext("sip:unknown@sip.example.org", incomingTo));

		BC_ASSERT(account == nullptr);
	}
}

// A SUBSCRIBE event as the B2BUA would receive it, placed by the given subscriber on a minimal core: no SIP traffic
// is involved.
auto makeSubscribeEvent(const string& subscriberUri) {
	const auto core = minimalCore();
	const auto subscriber = makeAccount(core, subscriberUri, "sip:subscriber-alias@sip.example.org");
	core->setDefaultAccount(subscriber->getLinphoneAccount());

	const auto resource = linphone::Factory::get()->createAddress("sip:mwi@sip.example.org");
	return core->createSubscribe(resource, "message-summary", 600);
}

/**
 * The event strategy resolves the subscriber account of an incoming SUBSCRIBE event, or nothing when the pool does
 * not contain it.
 */
void chooseAccountForThisEvent() {
	const auto pool = poolWithStaticAccounts();

	auto config =
	    R"({"by": "{uri.user}", "source": "{from.user}"})"_json.get<config::v2::account_selection::FindInPool>();

	{
		// The subscriber is searched by the event From user, which the pool contains.
		const auto account =
		    FindInPool(pool, config).chooseAccountForThisEvent(*makeSubscribeEvent("sip:expected-to@sip.example.org"));

		BC_HARD_ASSERT(account != nullptr);
		BC_ASSERT_CPP_EQUAL(account->getLinphoneAccount()->getParams()->getIdentityAddress()->asStringUriOnly(),
		                    "sip:expected-to@sip.example.org");
	}

	{
		// The subscriber is searched by the event From user, which the pool does not contain.
		const auto account =
		    FindInPool(pool, config).chooseAccountForThisEvent(*makeSubscribeEvent("sip:unknown@sip.example.org"));

		BC_ASSERT(account == nullptr);
	}
}

auto stubPool() {
	return make_shared<AccountPool>(make_shared<sofiasip::SuRoot>(), reinterpret_pointer_cast<B2buaCore>(minimalCore()),
	                                "stub pool", config::v2::AccountPool(),
	                                make_unique<StaticAccountLoader>(config::v2::StaticLoader()));
}

void allValidTokensInSourceTemplate() {
	auto allSupportedSubstitutions = ""
	                                 "{from}"
	                                 "{from.displayName}"
	                                 "{from.user}"
	                                 "{from.hostport}"
	                                 "{from.uriParameters}"
	                                 "{to}"
	                                 "{to.displayName}"
	                                 "{to.user}"
	                                 "{to.hostport}"
	                                 "{to.uriParameters}"
	                                 "{requestUri}"
	                                 "{requestUri.displayName}"
	                                 "{requestUri.user}"
	                                 "{requestUri.hostport}"
	                                 "{requestUri.uriParameters}"
	                                 ""s;

	FindInPool(stubPool(), {.source = std::move(allSupportedSubstitutions)});
}

void invalidTokenInSource() {
	try {
		std::ignore = FindInPool{stubPool(), {.source = "{from.uriParameters} is valid, but {from.invalid} is not"}};
		BC_FAIL("expected exception");
	} catch (const utils::string_interpolation::ResolutionError& err) {
		BC_ASSERT_CPP_EQUAL(err.offendingToken.cast(err.invalidTemplate), "invalid");
		SLOGD << "Preview of caught exception .what(): " << err.what();
	}
}

/**
 * The account field a FindInPool rule matches against is told by its 'by' template: the account uri, the
 * account alias, or nothing when the template indexes other data.
 */
void matchedFieldIsToldByTheByTemplate() {
	const auto pool = poolWithStaticAccounts();

	const auto matchedField = [&](std::string_view by) {
		return FindInPool(pool, config::v2::account_selection::FindInPool{.by = std::string{by}, .source = "{to}"})
		    .matchedField();
	};

	BC_ASSERT_CPP_EQUAL(matchedField("uri"), AccountSelectionStrategy::MatchedField::Uri);
	BC_ASSERT_CPP_EQUAL(matchedField("{uri}"), AccountSelectionStrategy::MatchedField::Uri);
	BC_ASSERT_CPP_EQUAL(matchedField("{uri.user}"), AccountSelectionStrategy::MatchedField::Uri);
	BC_ASSERT_CPP_EQUAL(matchedField("alias"), AccountSelectionStrategy::MatchedField::Alias);
	BC_ASSERT_CPP_EQUAL(matchedField("{alias.user}"), AccountSelectionStrategy::MatchedField::Alias);
	BC_ASSERT_CPP_EQUAL(matchedField("{alias.hostport}"), AccountSelectionStrategy::MatchedField::Alias);
	BC_ASSERT_CPP_EQUAL(matchedField("static-value"), AccountSelectionStrategy::MatchedField::None);
	BC_ASSERT_CPP_EQUAL(PickRandomInPool(pool).matchedField(), AccountSelectionStrategy::MatchedField::None);
}

TestSuite _{
    "b2bua::sip-bridge::account_strat::FindInPool",
    {
        CLASSY_TEST(chooseAccountForThisCall),
        CLASSY_TEST(chooseAccountForThisEvent),
        CLASSY_TEST(matchedFieldIsToldByTheByTemplate),
        CLASSY_TEST(allValidTokensInSourceTemplate),
        CLASSY_TEST(invalidTokenInSource),
    },
};

} // namespace
} // namespace flexisip::tester