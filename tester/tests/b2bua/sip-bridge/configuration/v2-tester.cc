/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "b2bua/sip-bridge/configuration/v2/v2.hh"

#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace flexisip::tester {
namespace {
using namespace b2bua::bridge::config;

void v1ConfigExpressedAsEquivalentV2Config() {
	// /!\ this is not a valid config. We're only testing parsing, not validation
	const auto j = R"json({
		"schemaVersion": 2,
		"providers": [
		  {
			"name": "Pattern matching (legacy) provider, new style",
			"triggerCondition": {
			  "source": "${incoming.from}",
			  "strategy": "MatchRegex",
			  "pattern": "sip:+33.*"
			},
			"accountToUse": {
			  "strategy": "Random"
			},
			"onAccountNotFound": "decline",
			"outgoingInvite": {
			  "to": "sip:${incoming.requestUri.userinfo}@${account.uri.hostport}${incoming.requestUri.uriParameters}"
			},
			"accountPool": "MyIncredibleTestAccountPool"
		  }
		],
		"accountPools": {
			"MyIncredibleTestAccountPool": {
				"outboundProxy": "<sip:some.provider.example.com;transport=tls>",
				"registrationRequired": true,
				"maxCallsPerLine": 500,
				"loader": [
						{
						  "uri": "sip:account1@some.provider.example.com",
						  "userid": "userid1",
						  "secretType": "clrtxt",
						  "secret": "correct horse battery staple",
						  "alias": "sip:alias@internal.domain.example.com"
						},
						{
						  "uri": "sip:account2@some.provider.example.com",
						  "secretType": "md5",
						  "secret": "e465a46b6d674197fdef9691c85597f6"
						}
				]
			}
		}
	})json"_json;

	auto deserialized = j.get<v2::Root>();

	BC_ASSERT_CPP_EQUAL(deserialized.schemaVersion, 2);
	BC_HARD_ASSERT_CPP_EQUAL(deserialized.accountPools.size(), 1);
	BC_ASSERT_CPP_EQUAL(deserialized.accountPools.begin()->first, "MyIncredibleTestAccountPool");
	const auto& accountPool = deserialized.accountPools.begin()->second;
	BC_ASSERT_CPP_EQUAL(accountPool.outboundProxy, "<sip:some.provider.example.com;transport=tls>");
	BC_ASSERT_CPP_EQUAL(accountPool.registrationRequired, true);
	BC_ASSERT_CPP_EQUAL(accountPool.maxCallsPerLine, 500);
	const auto& staticLoader = std::get<v2::StaticLoader>(accountPool.loader);
	BC_HARD_ASSERT_CPP_EQUAL(staticLoader.size(), 2);
	BC_ASSERT_CPP_EQUAL(staticLoader[0].uri, "sip:account1@some.provider.example.com");
	BC_ASSERT_CPP_EQUAL(staticLoader[0].userid, "userid1");
	BC_ASSERT_ENUM_EQUAL(staticLoader[0].secretType, v2::SecretType::Cleartext);
	BC_ASSERT_CPP_EQUAL(staticLoader[0].secret, "correct horse battery staple");
	BC_ASSERT_CPP_EQUAL(staticLoader[0].alias, "sip:alias@internal.domain.example.com");
	BC_ASSERT_CPP_EQUAL(staticLoader[1].uri, "sip:account2@some.provider.example.com");
	BC_ASSERT_ENUM_EQUAL(staticLoader[1].secretType, v2::SecretType::MD5);
	BC_ASSERT_CPP_EQUAL(staticLoader[1].secret, "e465a46b6d674197fdef9691c85597f6");
	BC_ASSERT_CPP_EQUAL(staticLoader[1].userid, "");
	BC_ASSERT_CPP_EQUAL(staticLoader[1].alias, "");
	BC_HARD_ASSERT_CPP_EQUAL(deserialized.providers.size(), 1);
	BC_ASSERT_CPP_EQUAL(deserialized.providers[0].name, "Pattern matching (legacy) provider, new style");
	const auto& matchRegex = std::get<v2::trigger_cond::MatchRegex>(deserialized.providers[0].triggerCondition);
	BC_ASSERT_CPP_EQUAL(matchRegex.source, "${incoming.from}");
	BC_ASSERT_CPP_EQUAL(matchRegex.pattern, "sip:+33.*");
	std::ignore = std::get<v2::account_selection::Random>(deserialized.providers[0].accountToUse);
	BC_ASSERT_ENUM_EQUAL(deserialized.providers[0].onAccountNotFound, v2::OnAccountNotFound::Decline);
	BC_ASSERT_CPP_EQUAL(deserialized.providers[0].outgoingInvite.to,
	                    "sip:${incoming.requestUri.userinfo}@${account.uri.hostport}${incoming."
	                    "requestUri.uriParameters}");
	BC_ASSERT_CPP_EQUAL(deserialized.providers[0].outgoingInvite.from, "");
	BC_ASSERT_CPP_EQUAL(deserialized.providers[0].accountPool, "MyIncredibleTestAccountPool");
}

void v1ConfigToV2() {
	auto v1 = R"json([
		{
		"name": "provider1",
		"pattern": "sip:.*",
		"outboundProxy": "<sip:127.0.0.1:5860;transport=tcp>",
		"maxCallsPerLine": 2,
		"accounts": [ 
			{
			"uri": "sip:bridge@sip.provider1.com",
			"password": "wow such password"
			}
		]
		}
	])json"_json.get<v1::Root>();

	auto v2 = v2::fromV1(std::move(v1));

	BC_ASSERT_CPP_EQUAL(v2.schemaVersion, 2);
	BC_HARD_ASSERT_CPP_EQUAL(v2.accountPools.size(), 1);
	BC_ASSERT_CPP_EQUAL(v2.accountPools.begin()->first, "Account pool - provider1");
	const auto& accountPool = v2.accountPools.begin()->second;
	BC_ASSERT_CPP_EQUAL(accountPool.outboundProxy, "<sip:127.0.0.1:5860;transport=tcp>");
	BC_ASSERT_CPP_EQUAL(accountPool.registrationRequired, false);
	BC_ASSERT_CPP_EQUAL(accountPool.maxCallsPerLine, 2);
	const auto& staticLoader = std::get<v2::StaticLoader>(accountPool.loader);
	BC_HARD_ASSERT_CPP_EQUAL(staticLoader.size(), 1);
	BC_ASSERT_CPP_EQUAL(staticLoader[0].uri, "sip:bridge@sip.provider1.com");
	BC_ASSERT_CPP_EQUAL(staticLoader[0].userid, "");
	BC_ASSERT_ENUM_EQUAL(staticLoader[0].secretType, v2::SecretType::Cleartext);
	BC_ASSERT_CPP_EQUAL(staticLoader[0].secret, "wow such password");
	BC_ASSERT_CPP_EQUAL(staticLoader[0].alias, "");
	BC_HARD_ASSERT_CPP_EQUAL(v2.providers.size(), 1);
	BC_ASSERT_CPP_EQUAL(v2.providers[0].name, "provider1");
	const auto& matchRegex = std::get<v2::trigger_cond::MatchRegex>(v2.providers[0].triggerCondition);
	BC_ASSERT_CPP_EQUAL(matchRegex.source, "${incoming.requestUri}");
	BC_ASSERT_CPP_EQUAL(matchRegex.pattern, "sip:.*");
	std::ignore = std::get<v2::account_selection::Random>(v2.providers[0].accountToUse);
	BC_ASSERT_ENUM_EQUAL(v2.providers[0].onAccountNotFound, v2::OnAccountNotFound::Decline);
	BC_ASSERT_CPP_EQUAL(v2.providers[0].outgoingInvite.to, "sip:{incoming.requestUri.user}@{account.uri.hostport}"
	                                                       "{incoming.requestUri.uriParameters}");
	BC_ASSERT_CPP_EQUAL(v2.providers[0].outgoingInvite.from, "");
	BC_ASSERT_CPP_EQUAL(v2.providers[0].accountPool, "Account pool - provider1");
}

// Start from a parseable config of only required fields, then try to remove them one at a time.
void requiredFields() {
	// /!\ this is not a valid config. We're only testing parsing, not validation
	const auto j = R"json({
		"schemaVersion": 2,
		"providers": [
		  {
			"name": "stub value 1",
			"triggerCondition": {
			  "strategy": "MatchRegex",
			  "source": "stub value 2",
			  "pattern": "stub value 3"
			},
			"accountToUse": {
			  "strategy": "Random"
			},
			"onAccountNotFound": "decline",
			"outgoingInvite": {
			  "to": "stub value 4"
			},
			"accountPool": "stub value 5"
		  },
		  {
			"name": "stub value 10",
			"triggerCondition": {
			  "strategy": "Always"
			},
			"accountToUse": {
			  "strategy": "FindInPool",
			  "source": "stub value 11",
			  "by": "stub value 12"
			},
			"onAccountNotFound": "nextProvider",
			"outgoingInvite": { "to": "stub value 13" },
			"accountPool": "stub value 14"
		  }
		],
		"accountPools": {
			"stub value 6": {
				"outboundProxy": "stub value 7",
				"registrationRequired": true,
				"maxCallsPerLine": 8,
				"loader": [
					{
						"uri": "stub value 9"
					}
				]
			}
		}
	})json"_json;
	constexpr std::array requiredFields = {
	    std::pair{"", "schemaVersion"},
	    std::pair{"", "providers"},
	    std::pair{"/providers/0", "name"},
	    std::pair{"/providers/0", "triggerCondition"},
	    std::pair{"/providers/0/triggerCondition", "strategy"},
	    std::pair{"/providers/0/triggerCondition", "source"},
	    std::pair{"/providers/0/triggerCondition", "pattern"},
	    std::pair{"/providers/0", "accountToUse"},
	    std::pair{"/providers/0/accountToUse", "strategy"},
	    std::pair{"/providers/0", "onAccountNotFound"},
	    std::pair{"/providers/0", "outgoingInvite"},
	    std::pair{"/providers/0/outgoingInvite", "to"},
	    std::pair{"/providers/0", "accountPool"},
	    std::pair{"/providers/1/triggerCondition", "strategy"},
	    std::pair{"/providers/1/accountToUse", "strategy"},
	    std::pair{"/providers/1/accountToUse", "source"},
	    std::pair{"/providers/1/accountToUse", "by"},
	    std::pair{"", "accountPools"},
	    std::pair{"/accountPools/stub value 6", "outboundProxy"},
	    std::pair{"/accountPools/stub value 6", "registrationRequired"},
	    std::pair{"/accountPools/stub value 6", "maxCallsPerLine"},
	    std::pair{"/accountPools/stub value 6", "loader"},
	    std::pair{"/accountPools/stub value 6/loader/0", "uri"},
	};

	// Deserializes without error
	std::ignore = j.get<v2::Root>();

	for (const auto& [path, name] : requiredFields) {
		using json_pointer = nlohmann::json::json_pointer;
		auto workingCopy = j;
		auto& object = workingCopy[*path == '\0' ? json_pointer() : json_pointer(path)];
		if (object.is_null()) {
			std::ostringstream msg{};
			msg << "No object found at '" << path << "'";
			bc_assert(__FILE__, __LINE__, false, msg.str().c_str());
			continue;
		}

		object.erase(name);
		try {
			std::ignore = workingCopy.get<v2::Root>();

			std::ostringstream msg{};
			msg << "Expected field '" << name << "' in '" << path << "' to be required";
			bc_assert(__FILE__, __LINE__, false, msg.str().c_str());
		} catch (const nlohmann::json::exception& parseErr) {
			constexpr auto MISSING_KEY = 403;
			BC_ASSERT_CPP_EQUAL(parseErr.id, MISSING_KEY);
		}
	}
}

TestSuite _{
    "b2bua::sip-bridge::configuration::v2",
    {
        CLASSY_TEST(v1ConfigExpressedAsEquivalentV2Config),
        CLASSY_TEST(v1ConfigToV2),
        CLASSY_TEST(requiredFields),
    },
};
} // namespace
} // namespace flexisip::tester
