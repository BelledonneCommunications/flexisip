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

#include <unordered_set>

#include "b2bua/sip-bridge/accounts/loaders/static-account-loader.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace flexisip::tester {
namespace {

using namespace std;
using namespace flexisip::b2bua::bridge;
using namespace flexisip::b2bua::bridge::config::v2;

void nominalInitialLoadTest() {
	// Static loader only move parsed config, this is a trivial test.
	auto loaderConfig = R"([
            {
                "uri": "sip:account1@first.provider.example.com",
                "realm": "some.provider.example.com",
                "alias": "sip:expected-from@sip.example.org"
            },
            {
                "uri": "sip:account2@second.provider.example.com",
                "userid": "userId",
                "secretType": "sha-256",
                "secret": "p@$sw0rd",
                "realm": "some.provider.example.com",
                "outboundProxy": "sip.example.org"
            },
            {
                "uri": "sip:account3@third.provider.example.org",
                "userid": "anotherId",
                "secretType": "md5",
                "secret": "hash",
                "realm": "aNewRealm",
                "outboundProxy": "sip.example.org",
                "registrar": "<sip:sip.another-example.org;transport=tcp>",
                "protocol": "TCP"
            },
            {
                "uri": "sip:account4@fourth.provider.example.org",
                "userid": "anotherId",
                "secretType": "SHA256",
                "secret": "hash",
                "realm": "aNewRealm",
                "registrar": "<sips:sip.another-example.org>"
            }
        ]
    )"_json.get<config::v2::StaticLoader>();

	auto expectedAccounts = loaderConfig;

	StaticAccountLoader loader{std::move(loaderConfig)};

    auto actualAccounts = loader.loadAll();
    BC_HARD_ASSERT_CPP_EQUAL(actualAccounts, expectedAccounts);

	BC_ASSERT_CPP_EQUAL(actualAccounts[0].getOutboundProxyUri(), "sip:first.provider.example.com");
	BC_ASSERT_CPP_EQUAL(actualAccounts[0].getRegistrarUri(), "sip:first.provider.example.com");
	BC_ASSERT_CPP_EQUAL(actualAccounts[1].getOutboundProxyUri(), "sip:sip.example.org");
	BC_ASSERT_CPP_EQUAL(actualAccounts[1].getRegistrarUri(), "sip:second.provider.example.com");
	BC_ASSERT_ENUM_EQUAL(actualAccounts[1].getSecretType(), SecretType::SHA256);
	BC_ASSERT_CPP_EQUAL(actualAccounts[2].getOutboundProxyUri(), "sip:sip.example.org;transport=tcp");
	BC_ASSERT_CPP_EQUAL(actualAccounts[2].getRegistrarUri(), "<sip:sip.another-example.org;transport=tcp>");
	BC_ASSERT_ENUM_EQUAL(actualAccounts[2].getSecretType(), SecretType::MD5);
	// Testing both lower and upper case for the protocol parameter.
	BC_ASSERT_CPP_EQUAL(actualAccounts[2].getProtocol(), "TCP");
	BC_ASSERT_CPP_EQUAL(actualAccounts[3].getOutboundProxyUri(), "sip:fourth.provider.example.org");
	BC_ASSERT_CPP_EQUAL(actualAccounts[3].getRegistrarUri(), "<sips:sip.another-example.org>");
	// If the secret type does not match what is expected ("sha256"), the loader will fall back to the default value.
	BC_ASSERT_ENUM_EQUAL(actualAccounts[3].getSecretType(), SecretType::MD5);
	// Testing both lower and upper case for the protocol parameter.
	BC_ASSERT_CPP_EQUAL(actualAccounts[3].getProtocol(), "udp");

    // Can be called any number of times.
	actualAccounts = loader.loadAll();
	BC_HARD_ASSERT_CPP_EQUAL(actualAccounts, expectedAccounts);

	BC_ASSERT_CPP_EQUAL(actualAccounts[0].getOutboundProxyUri(), "sip:first.provider.example.com");
	BC_ASSERT_CPP_EQUAL(actualAccounts[0].getRegistrarUri(), "sip:first.provider.example.com");
	BC_ASSERT_CPP_EQUAL(actualAccounts[1].getOutboundProxyUri(), "sip:sip.example.org");
	BC_ASSERT_CPP_EQUAL(actualAccounts[1].getRegistrarUri(), "sip:second.provider.example.com");
	BC_ASSERT_ENUM_EQUAL(actualAccounts[1].getSecretType(), SecretType::SHA256);
	BC_ASSERT_CPP_EQUAL(actualAccounts[2].getOutboundProxyUri(), "sip:sip.example.org;transport=tcp");
	BC_ASSERT_CPP_EQUAL(actualAccounts[2].getRegistrarUri(), "<sip:sip.another-example.org;transport=tcp>");
	BC_ASSERT_ENUM_EQUAL(actualAccounts[2].getSecretType(), SecretType::MD5);
	// Testing both lower and upper case for the protocol parameter.
	BC_ASSERT_CPP_EQUAL(actualAccounts[2].getProtocol(), "TCP");
	BC_ASSERT_CPP_EQUAL(actualAccounts[3].getOutboundProxyUri(), "sip:fourth.provider.example.org");
	BC_ASSERT_CPP_EQUAL(actualAccounts[3].getRegistrarUri(), "<sips:sip.another-example.org>");
	// If the secret type does not match what is expected ("sha256"), the loader will fall back to the default value.
	BC_ASSERT_ENUM_EQUAL(actualAccounts[3].getSecretType(), SecretType::MD5);
	// Testing both lower and upper case for the protocol parameter.
	BC_ASSERT_CPP_EQUAL(actualAccounts[3].getProtocol(), "udp");
}

const TestSuite _{
    "b2bua::sip-bridge::account::StaticAccountLoader",
    {
        CLASSY_TEST(nominalInitialLoadTest),
    },
};

} // namespace
} // namespace flexisip::tester