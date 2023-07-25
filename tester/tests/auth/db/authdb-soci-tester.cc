/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "auth/db/authdb.hh"

#include <future>
#include <optional>
#include <tuple>
#include <vector>

#include <bctoolbox/tester.h>

#include <flexisip/configmanager.hh>
#include <flexisip/module.hh>

#include "presence-server.hh"
#include "tester.hh"
#include "utils/mysql-server.hh"
#include "utils/string-utils.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std::chrono_literals;

namespace flexisip {
namespace tester {

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

std::optional<MysqlServer> sMysqlSuiteServer{std::nullopt};

class MySqlBackend {
public:
	MySqlBackend() {
		if (!sMysqlSuiteServer) {
			sMysqlSuiteServer.emplace();
		}
	}

	void waitReady() {
		sMysqlSuiteServer->waitReady();
	}

	void setConfig(const GenericStruct& authModuleConfig) {
		authModuleConfig.get<ConfigString>("soci-backend")->set("mysql");
		authModuleConfig.get<ConfigString>("soci-connection-string")->set(sMysqlSuiteServer->connectionString());
	}
};

class SqliteBackend {
public:
	void waitReady() {
	}

	void setConfig(const GenericStruct& authModuleConfig) {
		authModuleConfig.get<ConfigString>("soci-backend")->set("sqlite3");
		authModuleConfig.get<ConfigString>("soci-connection-string")->set("/dev/zero");
	}
};

static const char domainAndAuthId[] = R"SQL(
	SELECT :id, 'SHA-DDOCK'
	UNION SELECT :domain, :authid;
)SQL";

static const char domain[] = R"SQL(
	SELECT :id, 'SHA-DDOCK'
	UNION SELECT :domain, "authid-stand-in";
)SQL";

static const char authId[] = R"SQL(
	SELECT :id, 'SHA-DDOCK'
	UNION SELECT "domain-stand-in", :authid;
)SQL";

static const char none[] = R"SQL(
	SELECT :id, 'SHA-DDOCK'
	UNION SELECT "domain-stand-in", "authid-stand-in";
)SQL";

template <typename Backend, const char request[]>
void customPasswordRequestParamInjection() {
	Backend backend{};
	const auto injectedPassword = tester::randomString(0x10);
	RootConfigStruct configRoot{"flexisip-tester", "Fake configuration for testing purposes", {}};
	PresenceServer::Init{configRoot};
	const auto& moduleInfos = ModuleInfoManager::get()->getRegisteredModuleInfo();
	for (const auto& moduleInfo : moduleInfos) {
		const auto& name = moduleInfo->getModuleName();
		if (name == "Presence" || name == "Authentication") {
			moduleInfo->create(nullptr)->declare(&configRoot);
		}
	}
	const auto& authModuleConfig = *configRoot.get<GenericStruct>("module::Authentication");
	authModuleConfig.get<ConfigInt>("soci-poolsize")->set("1");
	authModuleConfig.get<ConfigString>("soci-password-request")->set(request);
	backend.setConfig(authModuleConfig);
	PasswordRequestListener listener{};
	backend.waitReady();
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

namespace {
TestSuite _("SociAuthDB",
            {
                CLASSY_TEST((customPasswordRequestParamInjection<SqliteBackend, domainAndAuthId>)),
                CLASSY_TEST((customPasswordRequestParamInjection<SqliteBackend, domain>)),
                CLASSY_TEST((customPasswordRequestParamInjection<SqliteBackend, authId>)),
                CLASSY_TEST((customPasswordRequestParamInjection<SqliteBackend, none>)),
                CLASSY_TEST((customPasswordRequestParamInjection<MySqlBackend, domainAndAuthId>)),
                CLASSY_TEST((customPasswordRequestParamInjection<MySqlBackend, domain>)),
                CLASSY_TEST((customPasswordRequestParamInjection<MySqlBackend, authId>)),
                CLASSY_TEST((customPasswordRequestParamInjection<MySqlBackend, none>)),
            },
            Hooks().afterSuite([] {
	            sMysqlSuiteServer = std::nullopt;
	            return 0;
            }));
}
} // namespace tester
} // namespace flexisip
