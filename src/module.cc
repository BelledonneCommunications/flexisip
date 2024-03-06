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

#include <algorithm>
#include <sstream>
#include <string_view>

#include <sofia-sip/nta.h>

#include "flexisip/configmanager.hh"
#include "flexisip/expressionparser.hh"
#include "flexisip/logmanager.hh"
#include "flexisip/module.hh"

#include "agent.hh"
#include "domain-registrations.hh"
#include "entryfilter.hh"
#include "utils/signaling-exception.hh"

using namespace std;
using namespace flexisip;

// -----------------------------------------------------------------------------
// Module.
// -----------------------------------------------------------------------------

Module::Module(Agent* ag, const ModuleInfoBase* moduleInfo)
    : mAgent(ag), mInfo(moduleInfo),
      mModuleConfig(ag->getConfigManager().getRoot()->get<GenericStruct>("module::" + getModuleConfigName())),
      mFilter(new ConfigEntryFilter(*mModuleConfig)) {
	mModuleConfig->setConfigListener(this);
}

Module::~Module() = default;

bool Module::isEnabled() const {
	return mFilter->isEnabled();
}

bool Module::doOnConfigStateChanged(const ConfigValue& conf, ConfigState state) {
	bool dirtyConfig = false;
	LOGD("Configuration of module %s changed for key %s to %s", mInfo->getModuleName().c_str(), conf.getName().c_str(),
	     conf.get().c_str());
	switch (state) {
		case ConfigState::Check:
			return isValidNextConfig(conf);
		case ConfigState::Changed:
			dirtyConfig = true;
			break;
		case ConfigState::Reset:
			dirtyConfig = false;
			break;
		case ConfigState::Committed:
			if (dirtyConfig) {
				LOGI("Reloading config of module %s", mInfo->getModuleName().c_str());
				reload();
				dirtyConfig = false;
			}
			break;
	}
	return true;
}

nta_agent_t* Module::getSofiaAgent() const {
	return mAgent->mAgent;
}

void Module::checkConfig() {
	auto& children = mModuleConfig->getChildren();
	for (auto it = children.begin(); it != children.end(); ++it) {
		auto cv = dynamic_cast<ConfigValue*>(it->get());
		if (cv && !isValidNextConfig(*cv)) {
			LOGF("Invalid config %s:%s=%s", getModuleName().c_str(), cv->getName().c_str(), cv->get().c_str());
		}
	}
}

void Module::load() {
	mFilter->loadConfig(mModuleConfig);
	if (mFilter->isEnabled()) onLoad(mModuleConfig);
}

void Module::unload() {
	if (mFilter->isEnabled()) onUnload();
}

void Module::reload() {
	onUnload();
	load();
}

void Module::processRequest(shared_ptr<RequestSipEvent>& ev) {
	auto errorReply = [&](int code, string_view reason, string_view error_msg) {
		SLOGD << "Exception while onRequest() on module " << getModuleName() << " because " << error_msg;
		SLOGD << "Replying with message " << code << " and reason " << reason.data();
		ev->reply(code, reason.data(), SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	};

	const shared_ptr<MsgSip>& ms = ev->getMsgSip();
	try {
		if (mFilter->canEnter(ms)) {
			SLOGD << "Invoking onRequest() on module " << getModuleName();
			onRequest(ev);
		} else {
			SLOGD << "Skipping onRequest() on module " << getModuleName();
		}
	} catch (SignalingException& se) {
		ostringstream msg;
		msg << se;
		errorReply(se.getStatusCode(), se.getReason(), msg.str());
	} catch (FlexisipException& fe) {
		ostringstream msg;
		msg << fe;
		errorReply(SIP_500_INTERNAL_SERVER_ERROR, msg.str());
	} catch (const GenericSipException& ge) {
		const auto& response = ge.getSipStatus();
		errorReply(response.getCode(), response.getReason(), ge.what());
	} catch (const std::exception& e) {
		errorReply(SIP_500_INTERNAL_SERVER_ERROR, e.what());
	}
}

void Module::processResponse(shared_ptr<ResponseSipEvent>& ev) {
	const shared_ptr<MsgSip>& ms = ev->getMsgSip();

	try {
		if (mFilter->canEnter(ms)) {
			LOGD("Invoking onResponse() on module %s", getModuleName().c_str());
			onResponse(ev);
		} else {
			LOGD("Skipping onResponse() on module %s", getModuleName().c_str());
		}
	} catch (FlexisipException& fe) {
		SLOGD << "Skipping onResponse() on module" << getModuleName() << " because " << fe;
	}
}

void Module::idle() {
	if (mFilter->isEnabled()) {
		onIdle();
	}
}

const string& Module::getModuleName() const {
	return mInfo->getModuleName();
}

const string& Module::getModuleConfigName() const {
	if (!mInfo->getReplace().empty()) {
		return mInfo->getReplace();
	}
	return mInfo->getModuleName();
}

ModuleClass Module::getClass() const {
	return mInfo->getClass();
}

void Module::injectRequestEvent(const shared_ptr<RequestSipEvent>& ev) {
	mAgent->injectRequestEvent(ev);
}

void Module::sendTrap(const std::string& msg) {
	mAgent->sendTrap(mModuleConfig, msg);
}

// -----------------------------------------------------------------------------
// ModuleInfo.
// -----------------------------------------------------------------------------
void ModuleInfoBase::declareConfig(GenericStruct& rootConfig) const {
	auto* moduleConfig = rootConfig.addChild(std::make_unique<GenericStruct>("module::" + mName, mHelp, mOidIndex));
	ConfigEntryFilter::declareConfig(*moduleConfig);
	if (mClass == ModuleClass::Experimental) {
		// Experimental modules are forced to be disabled by default.
		moduleConfig->get<ConfigBoolean>("enabled")->setDefault("false");
	}
	mDeclareConfig(*moduleConfig);
}

ModuleInfoManager* ModuleInfoManager::sInstance = nullptr;

ModuleInfoManager* ModuleInfoManager::get() {
	if (!sInstance) sInstance = new ModuleInfoManager();
	return sInstance;
}

void ModuleInfoManager::registerModuleInfo(ModuleInfoBase* moduleInfo) {
	SLOGI << "Registering module info [" << moduleInfo->getModuleName() << "]...";

	if (moduleInfo->getAfter().empty()) {
		SLOGE << "Cannot register module info [" << moduleInfo->getModuleName() << "] with empty after member.";
		return;
	}

	auto it = find(mRegisteredModuleInfo.cbegin(), mRegisteredModuleInfo.cend(), moduleInfo);
	if (it != mRegisteredModuleInfo.cend()) {
		SLOGE << "Unable to register already registered module [" << moduleInfo->getModuleName() << "].";
	} else {
		mRegisteredModuleInfo.push_back(moduleInfo);
	}
}

void ModuleInfoManager::unregisterModuleInfo(ModuleInfoBase* moduleInfo) {
	SLOGI << "Unregistering module info [" << moduleInfo->getModuleName() << "]...";
	mRegisteredModuleInfo.remove(moduleInfo);
}

bool ModuleInfoManager::moduleDependenciesPresent(const list<ModuleInfoBase*>& sortedList,
                                                  ModuleInfoBase* module) const {
	bool dependenciesOk = false;
	size_t dependencyCount = module->getAfter().size();

	if (dependencyCount == 0) return true; /* no dependency */

	for (const auto& dependency : module->getAfter()) {
		if (dependency.empty() && dependencyCount == 1) {
			dependenciesOk = true;
			break; /*This module has no dependency.*/
		}
		auto it = find_if(sortedList.cbegin(), sortedList.cend(), [dependency](const ModuleInfoBase* moduleInfo) {
			return moduleInfo->getModuleName() == dependency;
		});
		if (it == sortedList.end()) {
			// Not found, check if the dependency ever exists.
			auto registeredListIterator = find_if(
			    mRegisteredModuleInfo.cbegin(), mRegisteredModuleInfo.cend(),
			    [dependency](const ModuleInfoBase* moduleInfo) { return moduleInfo->getModuleName() == dependency; });
			if (registeredListIterator != mRegisteredModuleInfo.cend()) {
				dependenciesOk = false;
				break;
			} // else we can ignore the hint.
		} else {
			dependenciesOk = true;
		}
	}
	return dependenciesOk;
}

void ModuleInfoManager::dumpModuleDependencies(const list<ModuleInfoBase*>& l) const {
	ostringstream ostr;
	for (auto module : l) {
		ostr << "[" << module->getModuleName() << "] depending on ";
		for (auto dep : module->getAfter()) {
			ostr << "[" << dep << "] ";
		}
		ostr << endl;
	}
	SLOGD << ostr.str();
}

void ModuleInfoManager::replaceModules(std::list<ModuleInfoBase*>& sortedList,
                                       const std::list<ModuleInfoBase*>& replacingModules) const {
	for (auto* module : replacingModules) {
		const auto& moduleName = module->getModuleName();
		const auto& replace = module->getReplace();
		auto replacedModule = find_if(sortedList.begin(), sortedList.end(), [&replace](const ModuleInfoBase* module) {
			return module->getModuleName() == replace;
		});
		if (replacedModule == sortedList.end()) {
			SLOGE << "Unable to find module [" << replace << "] to be replaced by module [" << moduleName << "]";
			continue;
		}

		SLOGW << "Module "
		      << "[" << moduleName << "] will replace module [" << replace << "].";
		*replacedModule = module;
	}
}

std::list<ModuleInfoBase*> ModuleInfoManager::buildModuleChain() const {
	// Extract the modules which are to replace other modules from the others.
	decltype(mRegisteredModuleInfo) sortedList{}, pendingModules{}, replacingModules{};
	for (auto* modInfo : mRegisteredModuleInfo) {
		if (modInfo->getReplace().empty()) {
			pendingModules.emplace_back(modInfo);
		} else {
			replacingModules.emplace_back(modInfo);
		}
	}

	// Sort the no-replacing modules according their declared previous module.
	while (!pendingModules.empty()) {
		auto sortProgressing = false;
		for (auto module_it = pendingModules.begin(); module_it != pendingModules.end();) {
			auto* module = *module_it;
			// Make sure the module has already its dependencies in the sortedList
			if (moduleDependenciesPresent(sortedList, module)) {
				/* Good, this module has all its dependencies placed before it in the sorted list.
				 * We can append it to the sorted list, and remove it from the pending list.*/
				sortedList.push_back(module);
				module_it = pendingModules.erase(module_it);
				sortProgressing = true;
			} else {
				/* Some dependencies are not found. Continue iterating on the pending list. */
				++module_it;
			}
		}
		if (!sortProgressing && !pendingModules.empty()) {
			LOGE("Some modules have position references to other modules that could not be found:");
			dumpModuleDependencies(pendingModules);
			LOGF("Somes modules could not be positionned in the module's processing chain. It is usually caused by an "
			     "invalid module declaration Flexisip's source code, or in a loaded plugin.");
		}
	}

	// Replace the modules which are targeted by replacingModules.
	replaceModules(sortedList, replacingModules);
	LOGD("Module chain computed succesfully.");
	return sortedList;
}