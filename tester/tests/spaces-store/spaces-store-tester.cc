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
#include <memory>

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "exceptions/bad-configuration.hh"
#include "flexisip/configmanager.hh"
#include "spaces-store/spaces-store.hh"
#include "utils/string-utils.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

using namespace std;
using namespace flexisip;
using namespace flexisip::tester;

namespace {

const vector<string> kTestDomains{"domain1.example.org", "domain2.example.org", "domain3.example.org"};

const auto makeAccountsData = [](const string& domain) {
	return nlohmann::json::array({{
	    {"type", "account"},
	    {"payload",
	     {
	         {"id", 0},
	         {"sip_uri", "sip:user@" + domain},
	         {
	             "call_forwardings",
	             nlohmann::json::array({
	                 {
	                     {"type", "always"},
	                     {"sip_uri", "sip:other-user@" + domain},
	                     {"forward_to", "sip_uri"},
	                     {"enabled", true},
	                 },
	             }),
	         },
	     }},
	}});
};

const auto makeSpace = [](const string& domain,
                          const std::optional<filesystem::path>& accountsFilePath = std::nullopt) {
	return nlohmann::json{
	    {"name", "space-" + domain},
	    {"domain", domain},
	    {"accounts", accountsFilePath.value_or("")},
	    {
	        "realm",
	        {
	            {"realm", "realm-" + domain},
	            {
	                "bearer",
	                {
	                    {"authz_server", "https://issuer-" + domain},
	                    {"audience", "audience-" + domain},
	                    {"sip_id_claim", "sip-id"},
	                },
	            },
	        },
	    },
	};
};

namespace legacy {

void setAccountsStoreConfiguration(const std::shared_ptr<ConfigManager>& cfg,
                                   const std::filesystem::path& filePath,
                                   const std::string& domain) {
	ofstream ofs(filePath);
	ofs << makeAccountsData(domain);
	cfg->getGlobal()->get<ConfigString>("advanced-account-data")->set(filePath.string());
}

void testAccountsStore(SpacesStore& store, const string& expectedDomain) {
	const auto accountsStore = store.getAccountsStore(expectedDomain);
	BC_ASSERT_TRUE(accountsStore.has_value());
}

void setSpacesDataConfiguration(const std::shared_ptr<ConfigManager>& cfg, const std::vector<std::string>& domains) {
	const auto authzCfg = cfg->getRoot()->getModuleSectionByRole("Authorization");
	authzCfg->get<ConfigBoolean>("enabled")->set("true");
	authzCfg->get<ConfigString>("auth-domains-mode")->set("static");
	authzCfg->get<ConfigStringList>("auth-domains")->set(string_utils::join(domains));
}

void testSpacesData(const SpacesStore& store, const vector<string>& expectedDomains) {
	for (const auto& domain : expectedDomains) {
		BC_ASSERT_TRUE(store.hasDomain(domain));
	}
}

/*
 * Test legacy configuration with only static (file) AccountsStore.
 */
void accountsStoreOnly() {
	TmpDir dir("legacy-accounts-data");
	const auto cfg = make_shared<ConfigManager>();
	setAccountsStoreConfiguration(cfg, dir.path() / "accounts.json", kTestDomains.front());

	const auto spacesStore = SpacesStore::make(make_shared<sofiasip::SuRoot>(), cfg, nullptr);
	BC_ASSERT_TRUE(spacesStore != nullptr);

	testAccountsStore(*spacesStore, kTestDomains.front());
}

/*
 * Test legacy configuration with only static (file) SpacesData.
 */
void spacesDataOnly() {
	const auto cfg = make_shared<ConfigManager>();
	setSpacesDataConfiguration(cfg, kTestDomains);

	const auto spacesStore = SpacesStore::make(make_shared<sofiasip::SuRoot>(), cfg, nullptr);
	BC_ASSERT_TRUE(spacesStore != nullptr);

	testSpacesData(*spacesStore, kTestDomains);
}

/*
 * Test legacy configuration with both static SpacesData and AccountsStore is not supported.
 */
void accountsStoreAndSpacesData() {
	const auto cfg = make_shared<ConfigManager>();
	setAccountsStoreConfiguration(cfg, "some/path/to/file.json", kTestDomains.front());
	setSpacesDataConfiguration(cfg, kTestDomains);

	BC_ASSERT_THROWN(SpacesStore::make(make_shared<sofiasip::SuRoot>(), cfg, nullptr), BadConfiguration);
}

/*
 * Test that legacy configuration cannot be used together with new 'global/domains-configuration' for AccountsStore.
 */
void accountsStoreConfigConflict() {
	const auto cfg = make_shared<ConfigManager>();
	cfg->getGlobal()->get<ConfigString>("advanced-account-data")->set("legacy-options");
	cfg->getGlobal()->get<ConfigString>("domains-configuration")->set("/some/path");

	BC_ASSERT_THROWN(SpacesStore::make(make_shared<sofiasip::SuRoot>(), cfg, nullptr), BadConfiguration);
}

/**
 * Test that legacy configuration cannot be used together with new 'global/domains-configuration' for SpacesData.
 */
void spacesDataConfigConflict() {
	const auto cfg = make_shared<ConfigManager>();
	cfg->getGlobal()->get<ConfigString>("domains-configuration")->set("/some/path");
	const auto authzCfg = cfg->getRoot()->getModuleSectionByRole("Authorization");
	authzCfg->get<ConfigBoolean>("enabled")->set("true");
	authzCfg->get<ConfigString>("auth-domains-mode")->set("static");

	BC_ASSERT_THROWN(SpacesStore::make(make_shared<sofiasip::SuRoot>(), cfg, nullptr), BadConfiguration);

	authzCfg->get<ConfigString>("auth-domains-mode")->set("flexiapi");

	BC_ASSERT_THROWN(SpacesStore::make(make_shared<sofiasip::SuRoot>(), cfg, nullptr), BadConfiguration);

	authzCfg->get<ConfigString>("auth-domains-mode")->set("legacy");
	authzCfg->get<ConfigStringList>("auth-domains")->set("example.org");

	BC_ASSERT_THROWN(SpacesStore::make(make_shared<sofiasip::SuRoot>(), cfg, nullptr), BadConfiguration);
}

} // namespace legacy

/**
 * Test successful creation of SpacesStore with valid 'global/domains-configuration' configuration.
 */
void createSpacesStore() {
	const TmpDir dir("spaces-config");
	const auto domainsConfigFilePath = dir.path() / "spaces.json";

	vector<string> accountsPaths{};
	nlohmann::json domainsConfig = nlohmann::json::array();
	for (const auto& domain : kTestDomains) {
		const auto accountsDataFilePath = dir.path() / ("accounts-" + domain + ".json");
		accountsPaths.push_back(accountsDataFilePath);

		ofstream ofs(accountsDataFilePath);
		ofs << makeAccountsData(domain);

		domainsConfig.push_back(makeSpace(domain, accountsDataFilePath));
	}

	{
		ofstream ofs(domainsConfigFilePath);
		ofs << domainsConfig;
	}

	const auto cfg = make_shared<ConfigManager>();
	cfg->getGlobal()->get<ConfigString>("domains-configuration")->set(domainsConfigFilePath.string());

	const auto spacesStore = SpacesStore::make(make_shared<sofiasip::SuRoot>(), cfg, nullptr);
	BC_ASSERT_TRUE(spacesStore != nullptr);

	for (const auto& domain : kTestDomains) {
		BC_ASSERT_TRUE(spacesStore->hasDomain(domain));
		BC_ASSERT_TRUE(spacesStore->getAccountsStore(domain).has_value());
	}
}

void createSpacesStoreInvalidJson() {
	const TmpDir dir("spaces-config");
	const auto domainsConfigFilePath = dir.path() / "spaces.json";

	{
		ofstream ofs(domainsConfigFilePath);
		ofs << "invalid json";
	}

	const auto cfg = make_shared<ConfigManager>();
	cfg->getGlobal()->get<ConfigString>("domains-configuration")->set(domainsConfigFilePath.string());

	BC_ASSERT_THROWN(SpacesStore::make(make_shared<sofiasip::SuRoot>(), cfg, nullptr), BadConfiguration);
}

void createSpacesStoreInvalidJsonSchema() {
	const TmpDir dir("spaces-config");
	const auto domainsConfigFilePath = dir.path() / "spaces.json";

	{
		ofstream ofs(domainsConfigFilePath);
		ofs << nlohmann::json::array({{{"invalid", "schema"}}});
	}

	const auto cfg = make_shared<ConfigManager>();
	cfg->getGlobal()->get<ConfigString>("domains-configuration")->set(domainsConfigFilePath.string());

	BC_ASSERT_THROWN(SpacesStore::make(make_shared<sofiasip::SuRoot>(), cfg, nullptr), BadConfiguration);
}

const TestSuite kSuite = {
    "SpacesStore",
    {
        CLASSY_TEST(legacy::accountsStoreOnly),
        CLASSY_TEST(legacy::spacesDataOnly),
        CLASSY_TEST(legacy::accountsStoreAndSpacesData),
        CLASSY_TEST(legacy::accountsStoreConfigConflict),
        CLASSY_TEST(legacy::spacesDataConfigConflict),
        CLASSY_TEST(createSpacesStore),
        CLASSY_TEST(createSpacesStoreInvalidJson),
        CLASSY_TEST(createSpacesStoreInvalidJsonSchema),
    },
};
} // namespace
