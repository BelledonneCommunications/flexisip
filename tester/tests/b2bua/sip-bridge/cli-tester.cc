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

#include "b2bua/b2bua-core.hh"
#include "b2bua/b2bua-server.hh"
#include "flexisip/configmanager.hh"
#include "flexisip/logmanager.hh"
#include "helpers.hh"
#include "utils/client-builder.hh"
#include "utils/core-assert.hh"
#include "utils/server/b2bua-and-proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace linphone;

namespace flexisip::tester {
namespace {

using namespace std;
using namespace std::chrono_literals;
using namespace std::string_literals;

// Should display no memory leak when run in sanitizer mode
void cli() {
	using namespace flexisip::b2bua;
	const auto stubCore =
	    B2buaCore::create(*linphone::Factory::get(), *ConfigManager{}.getRoot()->get<GenericStruct>(configSection));
	bridge::SipBridge sipBridge{make_shared<sofiasip::SuRoot>(), stubCore,
	                            bridge::config::v2::fromV1({
	                                {
	                                    .name = "provider1",
	                                    .pattern = "regex1",
	                                    .outboundProxy = "sip:107.20.139.176:682;transport=scp",
	                                    .registrationRequired = false,
	                                    .maxCallsPerLine = 682,
	                                    .accounts =
	                                        {
	                                            {
	                                                .uri = "sip:account1@sip.example.org",
	                                                .userid = "",
	                                                .password = "",
	                                            },
	                                        },
	                                },
	                            }),
	                            nullptr};

	// Not a command handled by the bridge
	auto output = sipBridge.handleCommand("REGISTRAR_DUMP", vector<string>{"INFO"});
	auto expected = "";
	BC_ASSERT_TRUE(output == expected);

	// Unknown subcommand
	output = sipBridge.handleCommand("SIP_BRIDGE", {});
	expected = "Valid subcommands for SIP_BRIDGE:\n"
	           "  INFO  displays information on the current state of the bridge.";
	BC_ASSERT_TRUE(output == expected);
	output = sipBridge.handleCommand("SIP_BRIDGE", vector<string>{"anything"});
	BC_ASSERT_TRUE(output == expected);

	// INFO command
	output = sipBridge.handleCommand("SIP_BRIDGE", vector<string>{"INFO"});
	// Fields are sorted alphabetically, and `:` are surrounded by whitespace (` : `) even before linebreaks
	// (Yes, that's important when writing assertions like the following)
	// (No, it can't be configured in Jsoncpp, or I didn't find where)
	expected = R"({
	"providers" : 
	[
		{
			"accounts" : 
			[
				{
					"address" : "sip:account1@sip.example.org",
					"freeSlots" : 682,
					"registerEnabled" : false,
					"status" : "OK"
				}
			],
			"name" : "provider1"
		}
	]
})";
	if (!BC_ASSERT_TRUE(output == expected)) {
		SLOGD << "SIP BRIDGE INFO: " << output;
		SLOGD << "EXPECTED INFO  : " << expected;
		BC_ASSERT_TRUE(output.size() == strlen(expected));
		for (size_t i = 0; i < output.size(); i++) {
			if (output[i] != expected[i]) {
				SLOGD << "DIFFERING AT INDEX " << i << " ('" << output[i] << "' != '" << expected[i] << "')";
				break;
			}
		}
	}
}

void parseRegisterAuthenticate() {
	using namespace flexisip::b2bua;
	auto server = make_shared<B2buaAndProxyServer>("config/flexisip_b2bua.conf", false);
	server->getConfigManager()
	    ->getRoot()
	    ->get<GenericStruct>("b2bua-server")
	    ->get<ConfigString>("application")
	    ->set("sip-bridge");
	server->start();
	auto& sipBridge = dynamic_cast<flexisip::b2bua::bridge::SipBridge&>(server->getModule());
	ClientBuilder builder{server->getAgent()};

	// Only one account is registered and available
	InternalClient intercom = builder.build("sip:intercom@sip.company1.com");
	ExternalClient phone =
	    builder.setPassword("YKNKdW6rS9sET6G7").build("sip:+39066471266@auth.provider1.com;user=phone");
	if (!intercom.call(phone)) return;
	BC_ASSERT_TRUE(phone.getCallLog()->getRemoteAddress()->asString() == "sip:registered@auth.provider1.com");

	// Other accounts couldn't register, and can't be used to bridge calls
	auto other_intercom = InternalClient("sip:otherintercom@sip.company1.com", server->getAgent());
	ExternalClient other_phone = builder.setPassword("RPtTmGH75GWku6bF").build("sip:+39067864963@auth.provider1.com");
	const auto invite = other_intercom.invite(other_phone);
	BC_ASSERT_PTR_NOT_NULL(invite);
	BC_ASSERT_FALSE(other_phone.hasReceivedCallFrom(
	    other_intercom, CoreAssert{server, other_intercom.getCore(), other_phone.getCore()}));

	const auto info = sipBridge.handleCommand("SIP_BRIDGE", vector<string>{"INFO"});
	auto parsed = nlohmann::json::parse(info);
	auto& accounts = parsed["providers"][0]["accounts"];
	const std::unordered_set<nlohmann::json> parsedAccountSet{accounts.begin(), accounts.end()};
	accounts.clear();

	BC_ASSERT_CPP_EQUAL(parsed, R"({
        "providers" :
        [
            {
                "accounts" : [ ],
                "name" : "provider1"
            }
        ]
    })"_json);

	const auto expectedAccounts = R"([
        {
            "address" : "sip:registered@auth.provider1.com",
            "freeSlots" : 0,
            "registerEnabled" : true,
            "status" : "OK"
        },
        {
            "address" : "sip:unregistered@auth.provider1.com",
            "status" : "Registration failed: Bad credentials"
        },
        {
            "address" : "sip:wrongpassword@auth.provider1.com",
            "status" : "Registration failed: Bad credentials"
        }
    ])"_json;
	decltype(parsedAccountSet) expectedAccountSet{expectedAccounts.begin(), expectedAccounts.end()};
	BC_ASSERT_CPP_EQUAL(parsedAccountSet, expectedAccountSet);

	intercom.endCurrentCall(phone);
}

TestSuite _{
    "b2bua::sip-bridge::cli",
    {
        CLASSY_TEST(cli),
        CLASSY_TEST(parseRegisterAuthenticate),
    },
};

} // namespace
} // namespace flexisip::tester
