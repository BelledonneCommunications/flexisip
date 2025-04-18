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
#include "exceptions/bad-configuration.hh"
#include "utils/signaling-exception.hh"

using namespace std;
using namespace flexisip;

// -----------------------------------------------------------------------------
// Module.
// -----------------------------------------------------------------------------

Module::Module(Agent* ag, const ModuleInfoBase* moduleInfo)
    : mLogPrefix(moduleInfo->getLogPrefix()), mAgent(ag), mInfo(moduleInfo),
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
	LOGI << "Configuration of module " << mInfo->getModuleName() << " changed for key " << conf.getName() << " to "
	     << conf.get();
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
				LOGI << "Reloading configuration of module " << mInfo->getModuleName();
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
			throw BadConfiguration{"invalid configuration " + cv->getCompleteName() + "=" + cv->get()};
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

unique_ptr<RequestSipEvent> Module::processRequest(unique_ptr<RequestSipEvent>&& ev) {
	auto errorReply = [&](int code, string_view reason, string_view error_msg) {
		LOGD_CTX(mLogPrefix, "processRequest")
		    << "Exception while executing onRequest() on module " << getModuleName() << ": " << error_msg;
		LOGI_CTX(mLogPrefix, "processRequest") << "Replying with message " << code << " and reason " << reason.data();
		ev->reply(code, reason.data(), SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	};

	const shared_ptr<MsgSip>& ms = ev->getMsgSip();
	try {
		if (mFilter->isEnabled()) {
			if (mFilter->canEnter(ms)) {
				LOGD_CTX("Module") << "Execute onRequest() on module " << getModuleName();
				return onRequest(std::move(ev));
			} else
				LOGD_CTX("Module") << "Skipped onRequest() on module " << getModuleName()
				                   << ": filter evaluated to 'false'";
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
	return std::move(ev);
}

unique_ptr<ResponseSipEvent> Module::processResponse(unique_ptr<ResponseSipEvent>&& ev) {
	const shared_ptr<MsgSip>& ms = ev->getMsgSip();

	try {
		if (mFilter->isEnabled()) {
			if (mFilter->canEnter(ms)) {
				LOGD_CTX("Module") << "Execute onResponse() on module " << getModuleName();
				return onResponse(std::move(ev));
			} else
				LOGD_CTX("Module") << "Skipped onResponse() on module " << getModuleName()
				                   << ": filter evaluated to 'false'";
		}
	} catch (FlexisipException& fe) {
		LOGD_CTX("Module") << "Skipped onResponse() on module " << getModuleName() << ": " << fe;
	}
	return std::move(ev);
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

void Module::injectRequestEvent(unique_ptr<RequestSipEvent>&& ev) {
	mAgent->injectRequestEvent(std::move(ev));
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

std::unique_ptr<ModuleInfoManager> ModuleInfoManager::sInstance{};

ModuleInfoManager* ModuleInfoManager::get() {
	if (!sInstance) sInstance = std::make_unique<ModuleInfoManager>();
	return sInstance.get();
}

void ModuleInfoManager::registerModuleInfo(ModuleInfoBase* moduleInfo) {
	LOGD << "Registering module info [" << moduleInfo->getModuleName() << "]...";

	if (moduleInfo->getAfter().empty()) {
		LOGE << "Cannot register module info [" << moduleInfo->getModuleName() << "] with empty after member";
		return;
	}

	auto it = find(mRegisteredModuleInfo.cbegin(), mRegisteredModuleInfo.cend(), moduleInfo);
	if (it != mRegisteredModuleInfo.cend()) {
		LOGE << "Unable to register, already registered module [" << moduleInfo->getModuleName() << "]";
	} else {
		mRegisteredModuleInfo.push_back(moduleInfo);
		moduleInfo->setRegistered(true);
	}

	LOGI << "Registered module info [" << moduleInfo->getModuleName() << "]";
}

void ModuleInfoManager::unregisterModuleInfo(ModuleInfoBase* moduleInfo) {
	LOGI << "Unregistered module info [" << moduleInfo->getModuleName() << "]";
	mRegisteredModuleInfo.remove(moduleInfo);
	moduleInfo->setRegistered(false);
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
	LOGD << ostr.str();
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
			LOGE << "Unable to find module [" << replace << "] to be replaced by module [" << moduleName << "]";
			continue;
		}

		LOGD << "Module [" << moduleName << "] will replace module [" << replace << "]";
		*replacedModule = module;
	}
}

ModuleInfoManager::~ModuleInfoManager() {
	// Iterate through a copy of the list because unregisterModuleInfo() removes moduleInfo from mRegisteredModuleInfo.
	// Therefore, we cannot iterate through the list while modifying its content.
	const auto registeredModuleInfo = mRegisteredModuleInfo;
	for (auto* moduleInfo : registeredModuleInfo) {
		unregisterModuleInfo(moduleInfo);
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
			LOGE << "Some modules have position references to other modules that could not be found:";
			dumpModuleDependencies(pendingModules);
			throw FlexisipException{
			    "some modules could not be positioned in the module's processing chain (hint: it is usually caused by "
			    "an invalid module declaration in Flexisip's source code, or in a loaded plugin)"};
		}
	}

	// Replace the modules which are targeted by replacingModules.
	replaceModules(sortedList, replacingModules);
	LOGI << "Module chain computed successfully";
	return sortedList;
}