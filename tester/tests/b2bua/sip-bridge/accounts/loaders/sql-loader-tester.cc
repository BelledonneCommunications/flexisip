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

#include <soci/session.h>
#include <soci/sqlite3/soci-sqlite3.h>

#include "b2bua/sip-bridge/accounts/loaders/sql-account-loader.hh"
#include "utils/core-assert.hh"
#include "utils/lazy.hh"
#include "utils/soci-helper.hh"
#include "utils/string-formatter.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

namespace flexisip::tester {
namespace {

using namespace std;
using namespace soci;
using namespace nlohmann;
using namespace flexisip::b2bua::bridge;
using namespace flexisip::b2bua::bridge::config::v2;

struct SqlScope {
	const TmpDir tmpDir{"tmpDirForSqlLoader"};
	const std::string tmpDbFileName = tmpDir.path().string() + "/database_filename";
	SqlScope() {
		soci::session sql{sqlite3, tmpDbFileName};
		try {
			sql << R"sql(CREATE TABLE users (
						username TEXT PRIMARY KEY,
						domain TEXT,
						user_id TEXT,
                        realm TEXT NULL,
						secret TEXT,
                        secret_type TEXT DEFAULT 'MD5',
						alias_username TEXT,
						alias_domain TEXT,
						outbound_proxy TEXT NULL,
                        registrar TEXT NULL,
                        protocol TEXT DEFAULT 'UDP'))sql";
			sql << R"sql(INSERT INTO users VALUES ("account1", "some.provider.example.com", "", NULL, "", NULL, "expected-from", "sip.example.org", NULL, NULL, NULL))sql";
			sql << R"sql(INSERT INTO users VALUES ("account2", "some.provider.example.com", "userId", NULL, "p@$sw0rd", "clrtxt", "", "", "<sip:sip.another.example.org;transport=udp>", NULL, NULL))sql";
			sql << R"sql(INSERT INTO users VALUES ("account3", "other.provider.example.org", "anotherId", "aNewRealm", "hash", "MD5", "", "", "sips:sip.outbound.proxy.example.org", "sip.registrar.example.org", "TCP"))sql";
		} catch (const soci_error& e) {
			auto msg = "Error initializing DB: "s + e.what();
			BC_HARD_FAIL(msg.c_str());
		}
	}
};
auto sSuiteScope = Lazy<SqlScope>();

void nominalInitialSqlLoadTest() {
	auto expectedAccounts = R"([
			{
				"uri": "sip:account1@some.provider.example.com",
                "realm": "some.provider.example.com",
				"alias": "sip:expected-from@sip.example.org"
			},
			{
				"uri": "sip:account2@some.provider.example.com",
				"userid": "userId",
				"secretType": "clrtxt",
				"secret": "p@$sw0rd",
                "realm": "some.provider.example.com",
				"outboundProxy": "<sip:sip.another.example.org;transport=udp>"
			},
			{
				"uri": "sip:account3@other.provider.example.org",
				"userid": "anotherId",
				"secretType": "md5",
				"secret": "hash",
                "realm": "aNewRealm",
				"outboundProxy": "sips:sip.outbound.proxy.example.org",
                "registrar": "sip.registrar.example.org",
                "protocol": "tcp"
			}
		]
	)"_json.get<std::vector<Account>>();

	// clang-format off
	auto sqlLoaderConf = nlohmann::json::parse(StringFormatter{
		R"({
			"dbBackend": "sqlite3",
			"initQuery": "SELECT * from users",
			"updateQuery": "not tested here",
			"connection": "@database_filename@"
		}
	)",'@', '@'}
	.format({{"database_filename", sSuiteScope->tmpDbFileName}}))
	.get<SQLLoader>();
	// clang-format on

	SQLAccountLoader loader{make_shared<sofiasip::SuRoot>(), sqlLoaderConf};
	auto actualAccounts = loader.loadAll();

	BC_ASSERT_CPP_EQUAL(expectedAccounts, actualAccounts);
}

void initialSqlLoadTestWithEmptyFields() {
	auto expectedAccounts = R"([
			{
				"uri": "sip:account1@some.provider.example.com",
                "realm": "some.provider.example.com",
				"alias": "sip:expected-from@sip.example.org"
			},
			{
				"uri": "sip:account2@some.provider.example.com",
                "realm": "some.provider.example.com"
			},
			{
				"uri": "sip:account3@other.provider.example.org",
                "realm": "other.provider.example.org",
                "registrar": "sip.registrar.example.org",
                "protocol": "tcp"
			}
		]
	)"_json.get<std::vector<Account>>();

	// clang-format off
	auto sqlLoaderConf = nlohmann::json::parse(StringFormatter{
	    R"({
			"dbBackend": "sqlite3",
			"initQuery": "SELECT username, domain, \"\" as user_id, NULL as realm, \"unknown\" as secret_type, \"\" as secret, alias_username, alias_domain, NULL as outbound_proxy, registrar, protocol from users",
			"updateQuery": "not tested here",
			"connection": "@database_filename@"
		}
	)",'@', '@'}
	.format({{"database_filename", sSuiteScope->tmpDbFileName}}))
	.get<SQLLoader>();
	// clang-format on

	SQLAccountLoader loader{make_shared<sofiasip::SuRoot>(), sqlLoaderConf};
	auto actualAccounts = loader.loadAll();

	BC_ASSERT_CPP_EQUAL(expectedAccounts, actualAccounts);
}

void initialSqlLoadTestUriCantBeNull() {
	// clang-format off
	auto sqlLoaderConf = nlohmann::json::parse(StringFormatter{
	    R"({
			"dbBackend": "sqlite3",
			"initQuery": "SELECT NULL as username, domain from users",
			"updateQuery": "not tested here",
			"connection": "@database_filename@"
		}
	)",'@', '@'}
	.format({{"database_filename", sSuiteScope->tmpDbFileName}}))
	.get<SQLLoader>();
	// clang-format on

	SQLAccountLoader loader{make_shared<sofiasip::SuRoot>(), sqlLoaderConf};
	BC_ASSERT_THROWN(loader.loadAll(), DatabaseException)
}

void nominalUpdateSqlTest() {
	auto suRoot = make_shared<sofiasip::SuRoot>();
	// clang-format off
	auto sqlLoaderConf = nlohmann::json::parse(StringFormatter{
	    R"({
			"dbBackend": "sqlite3",
			"initQuery": "not tested here",
            "updateQuery": "SELECT username, domain, user_id, \"newRealm\" as realm, \"sha-256\" as secret_type, secret, alias_username, alias_domain, outbound_proxy, registrar, protocol from users where user_id = :identifier",
			"connection": "@database_filename@"
		}
	)",'@', '@'}
	.format({{"database_filename", sSuiteScope->tmpDbFileName}}))
	.get<SQLLoader>();
	// clang-format on

	SQLAccountLoader loader{suRoot, sqlLoaderConf};

	optional<Account> actualAccount;
	string actualUri;

	RedisAccountPub fakePub{SipUri{"sip:account2@some.provider.example.com"}, "userId"};
	loader.accountUpdateNeeded(
	    fakePub, [&actualAccount, &actualUri](const string& uri, const optional<Account>& actualAccountCb) {
		    actualAccount = actualAccountCb;
		    actualUri = uri;
	    });

	auto expectedAccount = R"(
				{
					"uri": "sip:account2@some.provider.example.com",
					"userid": "userId",
                    "realm": "newRealm",
					"secretType": "sha-256",
					"secret": "p@$sw0rd",
					"outboundProxy": "<sip:sip.another.example.org;transport=udp>"
				}
		)"_json.get<Account>();

	CoreAssert asserter{suRoot};
	asserter
	    .wait([&actualAccount, &expectedAccount] {
		    FAIL_IF(actualAccount != expectedAccount);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();
	if (!actualAccount.has_value()) {
		BC_HARD_FAIL("No account found");
	}
	BC_HARD_ASSERT_CPP_EQUAL(*actualAccount, expectedAccount);
	BC_ASSERT_ENUM_EQUAL(expectedAccount.getSecretType(), SecretType::SHA256);
	BC_ASSERT_ENUM_EQUAL(actualAccount->getSecretType(), SecretType::SHA256);
	BC_HARD_ASSERT_CPP_EQUAL(actualUri, "sip:account2@some.provider.example.com");
}

void updateSqlTestDeletion() {
	auto suRoot = make_shared<sofiasip::SuRoot>();
	// clang-format off
	auto sqlLoaderConf = nlohmann::json::parse(StringFormatter{
	    R"({
			"dbBackend": "sqlite3",
			"initQuery": "not tested here",
			"updateQuery": "SELECT username, domain, user_id, secret, alias_username, alias_domain, outbound_proxy from users where user_id = :identifier",
			"connection": "@database_filename@"
		}
	)",'@', '@'}
	.format({{"database_filename", sSuiteScope->tmpDbFileName}}))
	.get<SQLLoader>();
	// clang-format on

	SQLAccountLoader loader{suRoot, sqlLoaderConf};

	optional<Account> actualAccount;
	string actualUri;

	RedisAccountPub fakePub{SipUri{"sip:martinus@test.linphone.org"}, "notInDb"};
	loader.accountUpdateNeeded(
	    fakePub, [&actualAccount, &actualUri](const string& uri, const optional<Account>& actualAccountCb) {
		    actualAccount = actualAccountCb;
		    actualUri = uri;
	    });

	CoreAssert asserter{suRoot};
	asserter
	    .wait([&actualUri] {
		    FAIL_IF(actualUri != "sip:martinus@test.linphone.org");
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();
	BC_HARD_ASSERT_CPP_EQUAL(actualUri, "sip:martinus@test.linphone.org");
	if (actualAccount.has_value()) {
		BC_HARD_FAIL("optional<Account> was not empty during deletion scenario.");
	}
}

const TestSuite _{
    "b2bua::sip-bridge::account::SqlAccountLoader",
    {
        CLASSY_TEST(nominalInitialSqlLoadTest),
        CLASSY_TEST(initialSqlLoadTestWithEmptyFields),
        CLASSY_TEST(initialSqlLoadTestUriCantBeNull),
        CLASSY_TEST(nominalUpdateSqlTest),
        CLASSY_TEST(updateSqlTestDeletion),
    },
    Hooks().afterSuite([] {
	    sSuiteScope.reset();
	    return 0;
    }),
};

} // namespace
} // namespace flexisip::tester