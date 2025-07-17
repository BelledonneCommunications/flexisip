/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "flexisip/module-auth.hh"
#include "flexisip/module-registrar.hh"
#include "flexisip/module-router.hh"
#include "flexisip/module.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

#include "agent.hh"
#include "registrar/registrar-db.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip {
namespace tester {
namespace {
class DummyModule : public Module {
	friend std::shared_ptr<Module> ModuleInfo<DummyModule>::create(Agent*);

public:
	void onRequest([[maybe_unused]] std::shared_ptr<RequestSipEvent>& ev) override {
	}
	void onResponse([[maybe_unused]] std::shared_ptr<ResponseSipEvent>& ev) override {
	}

private:
	using Module::Module;
};

class DummyRegistrarModule : public DummyModule {
	using DummyModule::DummyModule;
};

class DummyAuthModule : public DummyModule {
	using DummyModule::DummyModule;
};

constexpr auto routerParamName = "use-global-domain";
constexpr auto dummyRouterParamName = "parser-test";
class DummyRouterModule : public ModuleRouter {
	friend std::shared_ptr<Module> ModuleInfo<DummyRouterModule>::create(Agent*);

public:
	using ModuleRouter::ModuleRouter;

	void onLoad(const GenericStruct* mc) override {
		ModuleRouter::onLoad(mc);
		testDummyRouterParameterRead = mc->get<ConfigBoolean>(routerParamName)->read();
		testRouterParameterRead = mc->get<ConfigBoolean>(dummyRouterParamName)->read();
	}

	bool testRouterParameterRead{false};
	bool testDummyRouterParameterRead{false};
};

/**
 * Check that the sorted list of ModuleInfo are in accordance with the 'after'
 * declaration of all the registered modules.
 */
void moduleSorting() noexcept {
	auto* moduleManager = ModuleInfoManager::get();
	const auto& registeredModules = moduleManager->getRegisteredModuleInfo();
	auto sortedModules = moduleManager->buildModuleChain();

	for (const auto* module : registeredModules) {
		// Each registered module must be present in the sorted list.
		auto modulePosIt = find(sortedModules.cbegin(), sortedModules.cend(), module);
		if (BC_ASSERT_FALSE(modulePosIt == sortedModules.cend())) break;

		// Check whether the current module is actually placed after the modules which it has declared
		// in its 'after' attribute.
		for (const auto& previousModuleName : module->getAfter()) {
			BC_ASSERT(find_if(sortedModules.cbegin(), modulePosIt, [&previousModuleName](const auto* m) {
				          return m->getModuleName() == previousModuleName;
			          }) != modulePosIt);
		}
	}
};

/**
 * Check the replacement of Registrar, Authentication and Router modules.
 */
void moduleReplacement() {
	auto* moduleManager = ModuleInfoManager::get();

	std::vector<std::string> expectedOrder{};
	for (const auto& moduleInfo : moduleManager->buildModuleChain()) {
		const auto& moduleName = moduleInfo->getModuleName();
		if (moduleName == "Authentication" || moduleName == "Registrar" || moduleName == "Router") {
			expectedOrder.emplace_back("Dummy" + moduleInfo->getModuleName());
		} else {
			expectedOrder.emplace_back(moduleInfo->getModuleName());
		}
	}

	// Create a ConfigManager
	auto cfg = std::make_shared<ConfigManager>();
	auto& rootCfg = *cfg->getEditableRoot();

	// By instantiating these ModuleInfo in the stack we ensure that they are unregistered
	// from the ModuleInfoManager when the test is completed.
	ModuleInfo<DummyRegistrarModule> dummyRegistrarInfo{
	    "DummyRegistrar",
	    "",
	    {""},
	    ModuleInfoBase::ModuleOid::Plugin,
	    [](GenericStruct& mc) { ModuleRegistrar::declareConfig(mc); },
	    ModuleClass::Production,
	    "Registrar",
	};
	dummyRegistrarInfo.declareConfig(rootCfg);

	ModuleInfo<DummyAuthModule> dummyAuthInfo{
	    "DummyAuthentication",
	    "",
	    {""},
	    ModuleInfoBase::ModuleOid::Plugin,
	    [](GenericStruct& mc) { Authentication::declareConfig(mc); },
	    ModuleClass::Production,
	    "Authentication",
	};
	dummyAuthInfo.declareConfig(rootCfg);

	// Check also that a module can use the parameters of a replaced module and add its own parameters.
	// Add a load method to check parsing.
	ModuleInfo<DummyRouterModule> dummyRouterInfo{
	    "DummyRouter",
	    "",
	    {""},
	    ModuleInfoBase::ModuleOid::Plugin,
	    [](GenericStruct& mc) {
		    ConfigItemDescriptor configs[] = {{Boolean, dummyRouterParamName, "test that value is read", "false"},
		                                      config_item_end};
		    ModuleRouter::declareConfig(mc);
		    mc.addChildrenValues(configs);
	    },
	    ModuleClass::Production,
	    "Router",
	};
	dummyRouterInfo.declareConfig(rootCfg);

	// Rebuild the module chain with new modules.
	auto sortedModuleInfos = moduleManager->buildModuleChain();

	// Check Dummy modules are present and are placed where the module they are to replace was placed.
	BC_ASSERT_EQUAL(sortedModuleInfos.size(), expectedOrder.size(), int, "%d");
	auto expectedIt = expectedOrder.cbegin();
	for (auto sortedIt = sortedModuleInfos.cbegin(); sortedIt != sortedModuleInfos.cend(); ++sortedIt, ++expectedIt) {
		BC_ASSERT_STRING_EQUAL((*sortedIt)->getModuleName().c_str(), expectedIt->c_str());
	}

	// Check that no crash occurs when creating proxy.
	auto* dummyRouterConf = rootCfg.get<GenericStruct>("module::DummyRouter");
	// Set to true a DummyRouter parameter.
	dummyRouterConf->get<ConfigValue>(dummyRouterParamName)->set("true");
	// Set to true a Router parameter.
	dummyRouterConf->get<ConfigValue>(routerParamName)->set("true");

	// Check the loading of module by creating and starting the agent.
	auto root = std::make_shared<sofiasip::SuRoot>();
	auto authDb = std::make_shared<AuthDb>(cfg);
	auto registrarDb = std::make_shared<RegistrarDb>(root, cfg);
	auto agent = std::make_shared<Agent>(root, cfg, authDb, registrarDb);
	agent->start("", "");
	auto router = dynamic_pointer_cast<DummyRouterModule>(agent->findModuleByRole("Router"));
	BC_HARD_ASSERT_TRUE(router != nullptr);
	BC_ASSERT_CPP_EQUAL(router->testRouterParameterRead, true);
	BC_ASSERT_CPP_EQUAL(router->testDummyRouterParameterRead, true);
}

TestSuite _("ModuleInfo",
            {
                CLASSY_TEST(moduleSorting),
                CLASSY_TEST(moduleReplacement),
            });
} // namespace
} // namespace tester
} // namespace flexisip
