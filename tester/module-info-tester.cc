/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/module.hh"

#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip {
namespace tester {

class DummyModule : public Module {
public:
	using Module::Module;

	void onRequest([[maybe_unused]] std::shared_ptr<RequestSipEvent>& ev) override {
	}
	void onResponse([[maybe_unused]] std::shared_ptr<ResponseSipEvent>& ev) override {
	}
};

class DummyRegistrarModule : public DummyModule {
	using DummyModule::DummyModule;
};

class DummyAuthModule : public DummyModule {
	using DummyModule::DummyModule;
};

class DummyRouterModule : public DummyModule {
	using DummyModule::DummyModule;
};

/**
 * Check that the sorted list of ModuleInfo are in accordance with the 'after'
 * declaration of all the registered modules.
 */
static void moduleSorting() noexcept {
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
static void moduleReplacement() noexcept {
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

	// By instantiating these ModuleInfo in the stack we ensure that they are unregistered
	// from the ModuleInfoManager when the test is completed.
	ModuleInfo<DummyRegistrarModule> dummyRegistrarInfo{
	    "DummyRegistrar", "", {""}, ModuleInfoBase::ModuleOid::Registrar, ModuleClass::Production, "Registrar"};
	ModuleInfo<DummyAuthModule> dummyAuthInfo{
	    "DummyAuthentication", "", {""}, ModuleInfoBase::ModuleOid::Registrar, ModuleClass::Production,
	    "Authentication"};
	ModuleInfo<DummyRouterModule> dummyRouterInfo{
	    "DummyRouter", "", {""}, ModuleInfoBase::ModuleOid::Registrar, ModuleClass::Production, "Router"};

	auto sortedModuleInfos = moduleManager->buildModuleChain();

	// Check Dummy modules are present and are placed where the module they are to replace was placed.
	BC_ASSERT_EQUAL(sortedModuleInfos.size(), expectedOrder.size(), int, "%d");
	auto expectedIt = expectedOrder.cbegin();
	for (auto sortedIt = sortedModuleInfos.cbegin(); sortedIt != sortedModuleInfos.cend(); ++sortedIt, ++expectedIt) {
		BC_ASSERT_STRING_EQUAL((*sortedIt)->getModuleName().c_str(), expectedIt->c_str());
	}
}

namespace {
TestSuite _("ModuleInfo",
            {
                TEST_NO_TAG("Module sorting", moduleSorting),
                TEST_NO_TAG("Module replacement", moduleReplacement),
            });
}
} // namespace tester
} // namespace flexisip
