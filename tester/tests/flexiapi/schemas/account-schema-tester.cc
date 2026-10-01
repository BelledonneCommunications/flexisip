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

#include "flexiapi/schemas/account/account-json.hh"

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

using namespace std;
using namespace flexisip::flexiapi;
using namespace flexisip::tester;

namespace {
namespace call_forwarding {
void forwardToAccountUri() {
	const auto callForwarding = nlohmann::json{
	    {"type", "no_answer"},
	    {"sip_account_id", "1234"},
	    {"sip_uri", "sip:contact@sip.example.org"},
	    {"enabled", true},
	};
	CallForwarding result{};
	from_json(callForwarding, result);

	BC_ASSERT_CPP_EQUAL(result.type, CallForwarding::Type::NoAnswer);
	BC_ASSERT_CPP_EQUAL(result.sip_uri.str(), "sip:contact@sip.example.org");
	BC_ASSERT_CPP_EQUAL(result.uriType, UriType::Account);
	BC_ASSERT_TRUE(result.enabled);
}

void forwardToVoicemail() {
	const auto callForwarding = nlohmann::json{
	    {"type", "always"},
	    {"voicemail_account_id", "8888"},
	    {"sip_uri", ""},
	    {"enabled", false},
	};
	CallForwarding result{};
	from_json(callForwarding, result);

	BC_ASSERT_CPP_EQUAL(result.type, CallForwarding::Type::Always);
	BC_ASSERT_CPP_EQUAL(result.uriType, UriType::Voicemail);
	BC_ASSERT_FALSE(result.enabled);
}

void invalidUriType() {
	const auto callForwarding = nlohmann::json{
	    {"type", "no_answer"},
	    // Voicemail id and an account id are mutually exclusive; they must not be set at the same time.
	    {"voicemail_account_id", "8888"},
	    {"sip_account_id", "1234"},
	    {"sip_uri", "sipcontact@sip.example.org"},
	    {"enabled", true},
	};
	CallForwarding result{};
	BC_ASSERT_THROWN(from_json(callForwarding, result), nlohmann::json::parse_error);
}

void invalidSipUri() {
	const auto callForwarding = nlohmann::json{
	    {"type", "no_answer"},
	    {"sip_account_id", "1234"},
	    // Missing `:` in sip_uri
	    {"sip_uri", "sipcontact@sip.example.org"},
	    {"enabled", true},
	};
	CallForwarding result{};
	BC_ASSERT_THROWN(from_json(callForwarding, result), nlohmann::json::parse_error);
}

void emptySipUri() {
	const auto callForwarding = nlohmann::json{
	    {"type", "no_answer"},
	    {"sip_account_id", "1234"},
	    {"sip_uri", ""},
	    {"enabled", true},
	};
	CallForwarding result{};
	BC_ASSERT_THROWN(from_json(callForwarding, result), nlohmann::json::parse_error);
}
} // namespace call_forwarding

const TestSuite kSuite = {
    "FlexiapiAccountSchema",
    {
        CLASSY_TEST(call_forwarding::forwardToAccountUri),
        CLASSY_TEST(call_forwarding::forwardToVoicemail),
        CLASSY_TEST(call_forwarding::invalidUriType),
        CLASSY_TEST(call_forwarding::invalidSipUri),
        CLASSY_TEST(call_forwarding::emptySipUri),
    },
};
} // namespace