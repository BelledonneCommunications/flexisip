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
#include "linphone/misc.h"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/server/injected-module-info.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace flexisip::tester {
namespace {

using namespace std;
using namespace flexisip::b2bua;
using namespace flexisip::b2bua::bridge;
using namespace flexisip::b2bua::bridge::account_strat;

/** Spin up a proxy and some clients to forge a linphone::Call, then set up a pool of a few static accounts.
 *  Test how a few basic FindInPool strategies choose accounts with different configs
 */
void chooseAccountForThisCall() {
	const std::string incomingFrom{"sip:expected-from@sip.example.org"};
	const SipUri incomingTo{"sip:expected-to@sip.example.org"};
	InjectedHooks hooks{
	    .onRequest =
	        [&incomingTo](std::unique_ptr<RequestSipEvent>&& requestEvent) {
		        const auto* sip = requestEvent->getSip();
		        // Mangle To header
		        sip->sip_to->a_url[0] = *incomingTo.get();
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
	const auto& builder = ClientBuilder(*proxy.getAgent());
	const auto& caller = builder.build(incomingFrom);
	const auto& b2buaStub = builder.build("stub@sip.example.org");
	caller.invite(b2buaStub);
	BC_HARD_ASSERT_TRUE(b2buaStub.hasReceivedCallFrom(caller, CoreAssert{proxy, caller, b2buaStub}));
	const auto forgedCall = ClientCall::getLinphoneCall(*b2buaStub.getCurrentCall());
	// For this test, it's okay that this client core isn't configured exactly as that of a B2buaServer
	const auto& b2buaStubCore = reinterpret_pointer_cast<B2buaCore>(b2buaStub.getCore());
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
	const auto templateParams = b2buaStubCore->createAccountParams();
	auto& staticLoader = get<config::v2::StaticLoader>(poolConfig.loader);
	const auto pool = make_shared<AccountPool>(proxy.getRoot(), b2buaStubCore, "test account pool", poolConfig,
	                                           make_unique<StaticAccountLoader>(std::move(staticLoader)));

	{
		const auto account =
		    FindInPool(pool,
		               R"({"by": "alias", "source": "{from}"})"_json.get<config::v2::account_selection::FindInPool>())
		        .chooseAccountForThisCall(*forgedCall);
		BC_HARD_ASSERT(account != nullptr);
		BC_ASSERT_CPP_EQUAL(account->getAlias().str(), incomingFrom);
	}

	{
		const auto account =
		    FindInPool(pool, R"({"by": "uri", "source": "{to}"})"_json.get<config::v2::account_selection::FindInPool>())
		        .chooseAccountForThisCall(*forgedCall);
		BC_HARD_ASSERT(account != nullptr);
		BC_ASSERT_CPP_EQUAL(account->getLinphoneAccount()->getParams()->getIdentityAddress()->asStringUriOnly(),
		                    incomingTo.str());
	}

	{
		const auto account =
		    FindInPool(pool, R"({"by": "alias", "source": "sip:no-placeholder@static.example.com"})"_json
		                         .get<config::v2::account_selection::FindInPool>())
		        .chooseAccountForThisCall(*forgedCall);
		BC_HARD_ASSERT(account != nullptr);
		BC_ASSERT_CPP_EQUAL(account->getAlias().str(), "sip:no-placeholder@static.example.com");
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
	                                 "{from.user}"
	                                 "{from.hostport}"
	                                 "{from.uriParameters}"
	                                 "{to}"
	                                 "{to.user}"
	                                 "{to.hostport}"
	                                 "{to.uriParameters}"
	                                 "{requestUri}"
	                                 "{requestUri.user}"
	                                 "{requestUri.hostport}"
	                                 "{requestUri.uriParameters}"
	                                 ""s;

	FindInPool(stubPool(), {.source = std::move(allSupportedSubstitutions)});
}

void invalidTokenInSource() {
	try {
		std::ignore = FindInPool{
		    stubPool(),

		    {.source = "{from.uriParameters} is valid, but {from.invalid} is not"},

		};
		BC_FAIL("expected exception");
	} catch (const utils::string_interpolation::ResolutionError& err) {
		BC_ASSERT_CPP_EQUAL(err.offendingToken.cast(err.invalidTemplate), "invalid");
		SLOGD << "Preview of caught exception .what(): " << err.what();
	}
}

TestSuite _{
    "b2bua::sip-bridge::account_strat::FindInPool",
    {
        CLASSY_TEST(chooseAccountForThisCall),
        CLASSY_TEST(allValidTokensInSourceTemplate),
        CLASSY_TEST(invalidTokenInSource),
    },
};

} // namespace
} // namespace flexisip::tester