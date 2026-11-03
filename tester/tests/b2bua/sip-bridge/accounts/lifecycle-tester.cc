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

#include "b2bua/sip-bridge/sip-bridge.hh"

#include <chrono>

#include "linphone++/linphone.hh"
#include <json/reader.h>

#include "b2bua/b2bua-server.hh"
#include "registrardb-internal.hh"
#include "utils/bc-utils.hh"
#include "utils/core-assert.hh"
#include "utils/server/b2bua-and-proxy-server.hh"
#include "utils/server/proxy-server.hh"
#include "utils/string-formatter.hh"
#include "utils/temp-file.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

#include "../helpers.hh"

using namespace linphone;

namespace flexisip::tester {
namespace {

using namespace std;
using namespace std::chrono_literals;
using namespace std::string_literals;

/** Test non-(un)registration of accounts on b2bua server shutdown.
 *
 * A Flexisip proxy will play the role of an external proxy.
 * The B2BUA is configured with 2 statically defined accounts.
 * Test that when the B2BUA server shuts down, accounts are still present in the registrarDB, which mean they did not
 * (un)register.
 *
 */
void disableAccountsUnregistrationOnServerShutdown() {
	const auto domain = "example.org";
	StringFormatter jsonConfig{R"json({
        "schemaVersion": 2,
        "providers": [
            {
                "name": "Accounts",
                "triggerCondition": { "strategy": "Always" },
                "accountToUse": { "strategy": "Random" },
                "onAccountNotFound": "decline",
                "outgoingInvite": { "to": "{incoming.to}" },
                "accountPool": "RegisteredAccounts"
            }
        ],
        "accountPools": {
            "RegisteredAccounts": {
                "outboundProxy": "<sip:127.0.0.1:port;transport=tcp>",
                "registrationRequired": true,
                "unregisterOnServerShutdown": false,
                "maxCallsPerLine": 1,
                "loader": [
                    {"uri": "sip:user-1@domain"},
                    {"uri": "sip:user-2@domain"}
                ]
            }
        }
    })json",
	                           '', ''};
	TempFile providersJson{};
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", domain},
	    {"b2bua-server/application", "sip-bridge"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server::sip-bridge/providers", providersJson.getFilename()},
	    // B2bua use writable-dir instead of var folder
	    {"b2bua-server/data-directory", bcTesterWriteDir()},
	}};
	proxy.start();
	providersJson.writeStream() << jsonConfig.format({{"port", proxy.getFirstPort()}, {"domain", domain}});
	const auto b2buaLoop = std::make_shared<sofiasip::SuRoot>();
	const auto b2buaServer = std::make_shared<B2buaServer>(b2buaLoop, proxy.getConfigManager());
	b2buaServer->init();

	CoreAssert(proxy, b2buaLoop)
	    .iterateUpTo(
	        5,
	        [&sipProviders =
	             dynamic_cast<const b2bua::bridge::SipBridge&>(b2buaServer->getApplication()).getProviders()] {
		        for (const auto& provider : sipProviders) {
			        for (const auto& [_, account] : provider.getAccountPool()) {
				        FAIL_IF(!account->isAvailable());
			        }
		        }
		        // b2bua accounts registered
		        return ASSERTION_PASSED();
	        },
	        70ms)
	    .assert_passed();

	// Graceful async shutdown.
	const auto& asyncCleanup = b2buaServer->stop();
	const auto& registeredUsers =
	    dynamic_cast<const RegistrarDbInternal&>(proxy.getRegistrarDb()->getRegistrarBackend()).getAllRecords();
	BC_ASSERT_CPP_EQUAL(registeredUsers.size(), 2);

	constexpr static auto timeout = 500ms;
	BcAssert()
	    .iterateUpTo(
	        1, [&asyncCleanup]() { return LOOP_ASSERTION(asyncCleanup->finished()); }, timeout)
	    .assert_passed();
	proxy.getRoot()->step(1ms);
	BC_ASSERT_CPP_EQUAL(registeredUsers.size(), 2);
}

// Assert that when a call ends, the appropriate account is updated
void callRelease() {
	using namespace flexisip::b2bua;
	auto server = make_shared<B2buaAndProxyServer>("config/flexisip_b2bua.conf");
	// We start with 4 empty slots total, divided into 2 lines
	auto providers = {V1ProviderDesc{
	    "2 lines 2 slots",
	    ".*",
	    outboundProxy,
	    false,
	    2,
	    {
	        V1AccountDesc{
	            "sip:line1@sip.provider1.com",
	            "",
	            "",
	        },
	        {V1AccountDesc{
	            "sip:line2@sip.provider1.com",
	            "",
	            "",
	        }},
	    },
	}};
	auto& accman = server->configureExternalProviderBridge(std::move(providers));
	const auto reader = unique_ptr<Json::CharReader>(Json::CharReaderBuilder().newCharReader());
	auto getLinesInfo = [&accman, &reader]() {
		const auto raw = accman.handleCommand("SIP_BRIDGE", vector<string>{"INFO"});
		auto info = Json::Value();
		BC_ASSERT_TRUE(reader->parse(raw.begin().base(), raw.end().base(), &info, nullptr));
		return std::move(info["providers"][0]["accounts"]);
	};
	InternalClient callers[] = {InternalClient("sip:caller1@sip.company1.com", server->getAgent()),
	                            InternalClient("sip:caller2@sip.company1.com", server->getAgent()),
	                            InternalClient("sip:caller3@sip.company1.com", server->getAgent())};
	ExternalClient callees[] = {ExternalClient("sip:callee1@sip.provider1.com", server->getAgent()),
	                            ExternalClient("sip:callee2@sip.provider1.com", server->getAgent()),
	                            ExternalClient("sip:callee3@sip.provider1.com", server->getAgent())};
	// Let's setup a long-running background call that will take the first slot
	// X | _
	// _ | _
	callers[0].call(callees[0]);

	// Call A will take the next slot, so either
	// X | X   OR   X | _
	// _ | _        X | _
	callers[1].call(callees[1]);
	auto lines = getLinesInfo();
	const bool calls_routed_through_different_lines = lines[0]["freeSlots"] == lines[1]["freeSlots"];
	if (calls_routed_through_different_lines) {
		BC_ASSERT_TRUE(lines[0]["freeSlots"] == 1);
	}

	// Call B then fills up a third slot, resulting in
	// X | X
	// X | _
	callers[2].call(callees[2]);

	// We then pick the appropriate call to get back to
	// X | X
	// _ | _
	if (calls_routed_through_different_lines) {
		callers[2].endCurrentCall(callees[2]); // End call B
	} else {
		callers[1].endCurrentCall(callees[1]); // End call A
	}

	// If the `onCallEnd` hook didn't do its job correctly, then we're likely not to end up with what we expect
	lines = getLinesInfo();
	BC_ASSERT_TRUE(lines[0]["freeSlots"] == 1 && lines[1]["freeSlots"] == 1);
}

TestSuite _{
    "b2bua::sip-bridge::lifecycle",
    {
        CLASSY_TEST(disableAccountsUnregistrationOnServerShutdown),
        CLASSY_TEST(callRelease),
    },
};

} // namespace
} // namespace flexisip::tester
