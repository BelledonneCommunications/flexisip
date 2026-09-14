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

#include "spaces-store/spaces-store.hh"

#include <fstream>
#include <memory>

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "core-assert.hh"
#include "exceptions/bad-configuration.hh"
#include "flexiapi/config.hh"
#include "flexisip/configmanager.hh"
#include "http-mock/http-mock.hh"
#include "utils/string-utils.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

using namespace std;
using namespace flexisip;
using namespace flexisip::flexiapi;
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
 * Test that legacy configuration cannot be used together with new 'global::domains/domains-configuration' for
 * AccountsStore.
 */
void accountsStoreConfigConflict() {
	const auto cfg = make_shared<ConfigManager>();
	cfg->getGlobal()->get<ConfigString>("advanced-account-data")->set("legacy-options");
	cfg->getRoot()
	    ->get<GenericStruct>("global::domains")
	    ->get<ConfigString>("domains-configuration")
	    ->set("/some/path");

	BC_ASSERT_THROWN(SpacesStore::make(make_shared<sofiasip::SuRoot>(), cfg, nullptr), BadConfiguration);
}

/**
 * Test that legacy configuration cannot be used together with new 'global::domains/domains-configuration' for
 * SpacesData.
 */
void spacesDataConfigConflict() {
	const auto cfg = make_shared<ConfigManager>();
	cfg->getRoot()
	    ->get<GenericStruct>("global::domains")
	    ->get<ConfigString>("domains-configuration")
	    ->set("/some/path");
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
 * Test successful creation of SpacesStore with valid 'global::domains/domains-configuration' file configuration.
 */
void createSpacesStoreWithFile() {
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
	cfg->getRoot()
	    ->get<GenericStruct>("global::domains")
	    ->get<ConfigString>("domains-configuration")
	    ->set(domainsConfigFilePath.string());

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
	cfg->getRoot()
	    ->get<GenericStruct>("global::domains")
	    ->get<ConfigString>("domains-configuration")
	    ->set(domainsConfigFilePath.string());

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
	cfg->getRoot()
	    ->get<GenericStruct>("global::domains")
	    ->get<ConfigString>("domains-configuration")
	    ->set(domainsConfigFilePath.string());

	BC_ASSERT_THROWN(SpacesStore::make(make_shared<sofiasip::SuRoot>(), cfg, nullptr), BadConfiguration);
}

/**
 * Test successful creation of SpacesStore with valid 'global::domains/domains-configuration' flexiapi configuration.
 * Also check that the 'host' field of the spaces is used to reach the account-manager for sub-spaces.
 */
void createSpacesStoreWithFlexiapi() {
	// HTTP mocks creation
	constexpr auto apiPath = "/api/spaces";
	constexpr auto subDomainApiPath = "/api/resolve/user@domain";
	std::string subDomainHost{"127.0.0.2"};
	std::string subDomain{"a.example.org"};

	http_mock::HttpMock server{apiPath};
	nlohmann::json spaces = {
	    {
	        {"domain", "example.org"},
	        {"name", "example"},
	        {"host", "127.0.0.1"},
	    },
	    {
	        {"domain", subDomain},
	        {"name", "a"},
	        {"host", subDomainHost},
	    },
	};

	BC_HARD_ASSERT_TRUE(server.addResponseToGET(apiPath, spaces.dump()));
	const auto port = server.serveAsync();

	std::atomic_int requestsReceived = 0;
	http_mock::HttpMock subDomainServer{{subDomainApiPath}, &requestsReceived};
	subDomainServer.setListeningAddress(subDomainHost);
	BC_HARD_ASSERT_CPP_EQUAL(subDomainServer.serveAsync(to_string(port)), port);

	// SpacesStore creation
	const auto cfg = make_shared<ConfigManager>();
	cfg->getRoot()->get<GenericStruct>("global::domains")->get<ConfigString>("domains-configuration")->set("flexiapi");
	cfg->getRoot()
	    ->get<GenericStruct>("global::flexiapi")
	    ->get<ConfigString>("url")
	    ->set("https://127.0.0.1:" + to_string(port));

	auto sofiaRoot = make_shared<sofiasip::SuRoot>();
	auto http2Client = flexiapi::createClient(cfg, *sofiaRoot);
	const auto spacesStore = SpacesStore::make(sofiaRoot, cfg, http2Client);

	// Check initial request made by the SpacesStore to /api/spaces
	CoreAssert asserter{sofiaRoot};
	asserter
	    .iterateUpTo(
	        10, [&spacesStore, &subDomain] { return LOOP_ASSERTION(spacesStore->hasDomain(subDomain)); }, 200ms)
	    .hard_assert_passed();

	// Check that subdomains use their own FlexiAPI client
	auto flexiApiClient = spacesStore->getFlexiApiClient(subDomain).lock();
	BC_HARD_ASSERT_NOT_NULL(flexiApiClient);
	flexiApiClient->resolveByUri(
	    flexiapi::ApiFormattedUri(SipUri("sip:user@domain")),
	    [](const std::shared_ptr<HttpMessage>&, const std::shared_ptr<HttpResponse>&) {},
	    [](const std::shared_ptr<HttpMessage>&) {});

	asserter.iterateUpTo(
	            10, [&requestsReceived] { return LOOP_ASSERTION(requestsReceived == 1); }, 200ms)
	    .assert_passed();
}

const TestSuite kSuite = {
    "SpacesStore",
    {
        CLASSY_TEST(legacy::accountsStoreOnly),
        CLASSY_TEST(legacy::spacesDataOnly),
        CLASSY_TEST(legacy::accountsStoreAndSpacesData),
        CLASSY_TEST(legacy::accountsStoreConfigConflict),
        CLASSY_TEST(legacy::spacesDataConfigConflict),
        CLASSY_TEST(createSpacesStoreWithFile),
        CLASSY_TEST(createSpacesStoreInvalidJson),
        CLASSY_TEST(createSpacesStoreInvalidJsonSchema),
        CLASSY_TEST(createSpacesStoreWithFlexiapi),
    },
};
} // namespace
