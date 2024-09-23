/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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
				"uri": "sip:account1@some.provider.example.com",
				"alias": "sip:expected-from@sip.example.org"
			},
			{
				"uri": "sip:account2@some.provider.example.com",
				"userid": "userID",
				"secretType": "clrtxt",
				"secret": "p@$sword",
				"outboundProxy": "sip.linphone.org"
			}
		]
	)"_json.get<config::v2::StaticLoader>();

	auto expectedAccounts = loaderConfig;

	StaticAccountLoader loader{std::move(loaderConfig)};

	auto actualAccounts = loader.initialLoad();

	BC_ASSERT_CPP_EQUAL(actualAccounts, expectedAccounts);

	// Calling again returns an empty vector. This is not necessarily wanted behaviour, but it's better to document it.
	BC_ASSERT_CPP_EQUAL(loader.initialLoad(), decltype(expectedAccounts){});
}

const TestSuite _{
    "b2bua::sip-bridge::account::StaticAccountLoader",
    {
        CLASSY_TEST(nominalInitialLoadTest),
    },
};

} // namespace
} // namespace flexisip::tester