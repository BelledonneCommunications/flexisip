/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "b2bua/sip-bridge/accounts/selection-strategy/find-in-pool.hh"

#include <linphone/misc.h>

#include "b2bua/sip-bridge/accounts/loaders/static-account-loader.hh"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/client-core.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace flexisip::tester {
namespace {
using namespace std;
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
	        [&incomingTo](const std::shared_ptr<RequestSipEvent>& requestEvent) {
		        const auto* sip = requestEvent->getSip();
		        // Mangle To header
		        sip->sip_to->a_url[0] = *incomingTo.get();
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
	const auto& b2bua = builder.build("stub@sip.example.org");
	caller.invite(b2bua);
	BC_HARD_ASSERT_TRUE(b2bua.hasReceivedCallFrom(caller));
	const auto forgedCall = ClientCall::getLinphoneCall(*b2bua.getCurrentCall());
	auto& b2buaCore = b2bua.getCore();
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
	const auto templateParams = b2buaCore->createAccountParams();
	auto& staticLoader = get<config::v2::StaticLoader>(poolConfig.loader);
	const auto pool = make_shared<AccountPool>(proxy.getRoot(), b2buaCore, "test account pool", poolConfig,
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

	FindInPool(nullptr, {.source = std::move(allSupportedSubstitutions)});
}

void invalidTokenInSource() {
	try {
		std::ignore = FindInPool{
		    nullptr,

		    {.source = "{from.uriParameters} is valid, but {from.invalid} is not"},

		};
		BC_FAIL("expected exception");
	} catch (const utils::string_interpolation::ResolutionError& err) {
		BC_ASSERT_CPP_EQUAL(err.offendingToken.cast(err.invalidTemplate), "invalid");
		SLOGD << "Preview of caught exception .what(): " << err.what();
	}
}

TestSuite _{
    "b2bua::bridge::account_strat::FindInPool",
    {
        CLASSY_TEST(chooseAccountForThisCall),
        CLASSY_TEST(allValidTokensInSourceTemplate),
        CLASSY_TEST(invalidTokenInSource),
    },
};
} // namespace
} // namespace flexisip::tester
