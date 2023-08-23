/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <optional>

#include "flexisip/module.hh"

namespace flexisip::tester {

// A helper class to register a custom module instance to the Agent's module chain
class InjectedModuleInfo : public ModuleInfoBase {
public:
	InjectedModuleInfo(Module& module)
	    : ModuleInfoBase(typeid(module).name(),
	                     "A module injected as high up in the module chain as possible to mangle requests and "
	                     "responses before they reach other modules",
	                     {""},
	                     static_cast<ModuleInfoBase::ModuleOid>(0xdead),
	                     ModuleClass::Production,
	                     ""),
	      mModule(module) {
		mModule.setInfo(this);
	}

private:
	std::shared_ptr<Module> create(Agent* agent) override {
		mModule.setAgent(agent);
		return {std::make_shared<std::nullopt_t>(std::nullopt), std::addressof(mModule)};
	}

	Module& mModule;
};

} // namespace flexisip::tester
