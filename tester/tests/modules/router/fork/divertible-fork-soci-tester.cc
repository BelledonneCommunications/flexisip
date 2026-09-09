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

#include <fstream>
#include <string_view>

#include <fstream>
#include <string_view>

#include "flexisip/module-router.hh"

#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/server/mysql/mysql-server.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

using namespace std;
using namespace linphone;

namespace flexisip::tester {
namespace {
std::optional<TmpDir> kSuiteDir;

// Initiate a call to a disconnected mobile device, check that the mobile received the call when reconnecting.
// Force usage of SchedulorInjector which can change proxy behavior on reconnection.
void forwardCallOnDeviceRegistration() {
	MysqlServer sDbServer{};
	sDbServer.waitReady();
	constexpr string_view accountNoDiversion = R"(
    [
		{
			"type": "account",
			"payload": {
				"id": 1,
				"sip_uri": "sip:initial-callee@sip.example.org",
				"call_forwardings": [
				]
			}
		}
	]
)";
	auto accounts = kSuiteDir->path() / "conditional-diverted-call-account";
	std::ofstream(accounts) << accountNoDiversion;
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"global/advanced-account-data", accounts},
	    {"module::Router/fork-late", "true"},
	    {"module::Router/call-fork-timeout", "2s"},
	    {"module::Router/message-database-enabled", "true"}, // active SchedulorInjector
	    {"module::Router/message-database-backend", "mysql"},
	    {"module::Router/message-database-connection-string", sDbServer.connectionString()},
	    {"module::Router/enable-call-diversions", "true"},
	    {"module::MediaRelay/enabled", "true"},
	}};
	proxy.start();

	auto builder = make_unique<ClientBuilder>(proxy.getAgent());
	auto caller = builder->make("sip:caller@sip.example.org");
	auto initialCallee = builder->setApplePushConfig().make("sip:initial-callee@sip.example.org;device=iOS");
	auto asserter = CoreAssert{proxy, caller, initialCallee};

	// Wait for client registration.
	asserter
	    .waitUntil(2s,
	               [&initialCallee] {
		               FAIL_IF(initialCallee->getAccount()->getState() != RegistrationState::Ok);
		               return ASSERTION_PASSED();
	               })
	    .hard_assert_passed();
	initialCallee->disconnect();

	// Caller invites initial callee.
	auto callerCall = ClientCall::tryFrom(caller->invite("sip:initial-callee@sip.example.org"));
	BC_HARD_ASSERT(callerCall.has_value());
	const auto& router = dynamic_pointer_cast<ModuleRouter>(proxy.getAgent()->findModuleByRole("Router"));
	BC_HARD_ASSERT(router != nullptr);
	const auto stats = router->mStats.mForkStats->mCountDivertibleCallForks;
	asserter
	    .waitUntil(1s,
	               [&stats] {
		               FAIL_IF(stats->start->read() != 1);
		               return ASSERTION_PASSED();
	               })
	    .hard_assert_passed();

	// Reconnect mobile device.
	initialCallee->reconnect();
	asserter
	    .waitUntil(2s,
	               [&initialCallee] {
		               FAIL_IF(!initialCallee->getCurrentCall());
		               return ASSERTION_PASSED();
	               })
	    .assert_passed();
}

// Test features interaction, in particular usage of SchedulorInjector.
TestSuite kSuite{
    "DivertibleForkSoci",
    {
        CLASSY_TEST(forwardCallOnDeviceRegistration),
    },
    Hooks()
        .beforeSuite([] {
	        kSuiteDir.emplace(kSuite.getName());
	        return 0;
        })
        .afterSuite([] {
	        kSuiteDir.reset();
	        return 0;
        }),
};
} // namespace
} // namespace flexisip::tester