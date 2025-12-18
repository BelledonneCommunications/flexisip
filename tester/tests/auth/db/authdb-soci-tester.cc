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

#include "auth/db/authdb.hh"

#include <future>
#include <tuple>
#include <vector>

#include "bctoolbox/tester.h"

#include "flexisip/configmanager.hh"
#include "flexisip/module.hh"
#include "tester.hh"
#include "utils/server/mysql/mysql-server.hh"
#include "utils/string-utils.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std::chrono_literals;

namespace flexisip::tester {
namespace {

class DbBackend {
public:
	virtual ~DbBackend() = default;

	virtual void clear() const = 0;
	virtual void setConfig(const GenericStruct& authModuleConfig) const = 0;
};

class PasswordRequestListener : public AuthDbListener {
public:
	auto getFuture() {
		return mResult.get_future();
	}

private:
	void onResult(AuthDbResult result, const std::vector<passwd_algo_t>& passwd) override {
		mResult.set_value(std::make_tuple(result, passwd));
	}
	void onResult(AuthDbResult, const std::string&) override {
		BC_FAIL("This test does not expect a plain text password result");
	}

	std::promise<std::tuple<AuthDbResult, std::vector<passwd_algo_t>>> mResult{};
};

constexpr char kDomainAndAuthId[] = R"SQL(
	SELECT :id, 'SHA-DDOCK'
	UNION SELECT :domain, :authid;
)SQL";

constexpr char kDomain[] = R"SQL(
	SELECT :id, 'SHA-DDOCK'
	UNION SELECT :domain, "authid-stand-in";
)SQL";

constexpr char kAuthId[] = R"SQL(
	SELECT :id, 'SHA-DDOCK'
	UNION SELECT "domain-stand-in", :authid;
)SQL";

constexpr char kNone[] = R"SQL(
	SELECT :id, 'SHA-DDOCK'
	UNION SELECT "domain-stand-in", "authid-stand-in";
)SQL";

void customPasswordRequestParamInjection(const std::unique_ptr<DbBackend>& backend, const std::string& request) {
	Random random{tester::random::seed()};

	const auto injectedPassword = random.string().generate(0x10);
	std::string empty{};
	RootConfigStruct configRoot{"flexisip-tester", "Fake configuration for testing purposes", {}, empty};
	for (const auto& init : ConfigManager::defaultInit()) {
		init(configRoot);
	}

	const auto& moduleInfos = ModuleInfoManager::get()->getModuleChain();
	for (const auto& moduleInfo : moduleInfos) {
		const auto& name = moduleInfo->getModuleName();
		if (name == "Presence" || name == "Authentication") {
			moduleInfo->declareConfig(configRoot);
		}
	}
	const auto& authModuleConfig = *configRoot.get<GenericStruct>("module::Authentication");
	authModuleConfig.get<ConfigInt>("soci-poolsize")->set("1");
	authModuleConfig.get<ConfigString>("soci-password-request")->set(request);
	backend->setConfig(authModuleConfig);
	PasswordRequestListener listener{};
	SociAuthDB authDb{configRoot};

	authDb.getPasswordFromBackend(injectedPassword, "domain-stand-in", "authid-stand-in", &listener);

	auto future = listener.getFuture();

	BC_HARD_ASSERT_TRUE(future.wait_for(1s) == std::future_status::ready);
	const auto result = future.get();
	BC_HARD_ASSERT_CPP_EQUAL(std::get<0>(result), AuthDbResult::PASSWORD_FOUND);
	const auto& rows = std::get<1>(result);
	BC_HARD_ASSERT_CPP_EQUAL(rows.size(), 2);
	// Order of rows is not guaranteed, so we have switch over the two rows with a loop
	for (const auto& row : rows) {
		if (row.algo == "SHA-DDOCK") {
			BC_ASSERT_CPP_EQUAL(row.pass, StringUtils::toLower(injectedPassword));
		} else {
			// Assert that optional parameters were correctly injected.
			// The fake SQL query passes them over as another row
			BC_ASSERT_CPP_EQUAL(row.algo, "authid-stand-in");
			BC_ASSERT_CPP_EQUAL(row.pass, "domain-stand-in");
		}
	}
}

namespace sqlite3 {

class SqliteBackend : public DbBackend {
public:
	void clear() const override {
	}

	void setConfig(const GenericStruct& authModuleConfig) const override {
		authModuleConfig.get<ConfigString>("soci-backend")->set("sqlite3");
		authModuleConfig.get<ConfigString>("soci-connection-string")->set("/dev/zero");
	}
};

std::unique_ptr<DbBackend> sSqliteBackend{};

void customPasswordRequestParamInjectionDomainAndAuthId() {
	customPasswordRequestParamInjection(sSqliteBackend, kDomainAndAuthId);
}

void customPasswordRequestParamInjectionDomain() {
	customPasswordRequestParamInjection(sSqliteBackend, kDomain);
}

void customPasswordRequestParamInjectionAuthId() {
	customPasswordRequestParamInjection(sSqliteBackend, kAuthId);
}

void customPasswordRequestParamInjectionNone() {
	customPasswordRequestParamInjection(sSqliteBackend, kNone);
}

TestSuite _{
    "SociAuthDB::sqlite3",
    {
        CLASSY_TEST(customPasswordRequestParamInjectionDomainAndAuthId),
        CLASSY_TEST(customPasswordRequestParamInjectionDomain),
        CLASSY_TEST(customPasswordRequestParamInjectionAuthId),
        CLASSY_TEST(customPasswordRequestParamInjectionNone),
    },
    Hooks{}
        .beforeSuite([] {
	        sSqliteBackend = std::make_unique<SqliteBackend>();
	        return 0;
        })
        .beforeEach([] { sSqliteBackend->clear(); })
        .afterSuite([] {
	        sSqliteBackend.reset();
	        return 0;
        }),
};

} // namespace sqlite3

namespace mysql {

class MySqlBackend : public DbBackend {
public:
	MySqlBackend() : mServer(std::make_unique<MysqlServer>()) {
		mServer->waitReady();
	}

	void clear() const override {
		mServer->clear();
	}

	void setConfig(const GenericStruct& authModuleConfig) const override {
		authModuleConfig.get<ConfigString>("soci-backend")->set("mysql");
		authModuleConfig.get<ConfigString>("soci-connection-string")->set(mServer->connectionString());
	}

private:
	std::unique_ptr<MysqlServer> mServer{};
};

std::unique_ptr<DbBackend> sMySqlBackend{};

void customPasswordRequestParamInjectionDomainAndAuthId() {
	customPasswordRequestParamInjection(sMySqlBackend, kDomainAndAuthId);
}

void customPasswordRequestParamInjectionDomain() {
	customPasswordRequestParamInjection(sMySqlBackend, kDomain);
}

void customPasswordRequestParamInjectionAuthId() {
	customPasswordRequestParamInjection(sMySqlBackend, kAuthId);
}

void customPasswordRequestParamInjectionNone() {
	customPasswordRequestParamInjection(sMySqlBackend, kNone);
}

TestSuite _{
    "SociAuthDB::mysql",
    {
        CLASSY_TEST(customPasswordRequestParamInjectionDomainAndAuthId),
        CLASSY_TEST(customPasswordRequestParamInjectionDomain),
        CLASSY_TEST(customPasswordRequestParamInjectionAuthId),
        CLASSY_TEST(customPasswordRequestParamInjectionNone),
    },
    Hooks()
        .beforeSuite([] {
	        sMySqlBackend = std::make_unique<MySqlBackend>();
	        return 0;
        })
        .beforeEach([] { sMySqlBackend->clear(); })
        .afterSuite([] {
	        sMySqlBackend.reset();
	        return 0;
        }),
};

} // namespace mysql
} // namespace
} // namespace flexisip::tester