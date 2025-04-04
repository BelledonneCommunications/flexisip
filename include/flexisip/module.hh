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

#pragma once

#include <sofia-sip/msg_header.h>
#include <sofia-sip/nta_tport.h>
#include <sofia-sip/tport.h>

#include "flexisip/configmanager.hh"
#include "flexisip/event.hh"
#include "flexisip/sofia-wrapper/home.hh"

namespace flexisip {

// =============================================================================

// -----------------------------------------------------------------------------
// Module.
// -----------------------------------------------------------------------------

class ModuleInfoBase;

template <typename T>
class ModuleInfo;

class SharedLibrary;
class EntryFilter;

enum class ModuleClass { Experimental, Production };

/**
 * Abstract base class for all Flexisip module.
 * A module is an object that is able to process sip requests and sip responses.
 * It must implements at least:
 * virtual std::unique_ptr<RequestSipEvent> onRequest(std::unique_ptr<RequestSipEvent>&& ev) = 0;
 * virtual std::unique_ptr<ResponseSipEvent> onResponse(std::unique_ptr<ResponseSipEvent>&& ev) = 0;
 **/
class Module : protected ConfigValueListener {
	template <typename T>
	friend class ModuleInfo;

public:
	Module(Agent* agent, const ModuleInfoBase* moduleInfo);
	virtual ~Module();

	Agent* getAgent() const {
		return mAgent;
	}
	nta_agent_t* getSofiaAgent() const;
	const std::string& getModuleName() const;
	const std::string& getModuleConfigName() const;
	void checkConfig();
	void load();
	void unload();
	void reload();
	StatCounter64& findStat(const std::string& statName) const;
	void idle();
	bool isEnabled() const;
	ModuleClass getClass() const;

	std::unique_ptr<RequestSipEvent> processRequest(std::unique_ptr<RequestSipEvent>&& ev);
	std::unique_ptr<ResponseSipEvent> processResponse(std::unique_ptr<ResponseSipEvent>&& ev);
	std::unique_ptr<RequestSipEvent> process(std::unique_ptr<RequestSipEvent>&& ev) {
		return processRequest(std::move(ev));
	}
	std::unique_ptr<ResponseSipEvent> process(std::unique_ptr<ResponseSipEvent>&& ev) {
		return processResponse(std::move(ev));
	}
	virtual void injectRequestEvent(std::unique_ptr<RequestSipEvent>&& ev);

	const ModuleInfoBase* getInfo() const {
		return mInfo;
	}

protected:
	virtual void onLoad([[maybe_unused]] const GenericStruct* root) {
	}
	virtual void onUnload() {
	}

	virtual std::unique_ptr<RequestSipEvent> onRequest(std::unique_ptr<RequestSipEvent>&& ev) = 0;
	virtual std::unique_ptr<ResponseSipEvent> onResponse(std::unique_ptr<ResponseSipEvent>&& ev) = 0;

	virtual bool doOnConfigStateChanged(const ConfigValue& conf, ConfigState state);
	virtual void onIdle() {
	}

	virtual bool onCheckValidNextConfig() {
		return true;
	}

	virtual bool isValidNextConfig([[maybe_unused]] const ConfigValue& cv) {
		return true;
	}

	void sendTrap(const std::string& msg);

	std::string mLogPrefix;

protected:
	sofiasip::Home mHome;
	Agent* mAgent = nullptr;
	const ModuleInfoBase* mInfo;
	GenericStruct* mModuleConfig = nullptr;
	std::unique_ptr<EntryFilter> mFilter;
};

// -----------------------------------------------------------------------------
// ModuleInfo.
// -----------------------------------------------------------------------------

class ModuleInfoBase;

class ModuleInfoManager {
	friend class ModuleInfoBase;

public:
	~ModuleInfoManager();
	const std::list<ModuleInfoBase*>& getRegisteredModuleInfo() const {
		return mRegisteredModuleInfo;
	}
	std::list<ModuleInfoBase*> buildModuleChain() const;

	static ModuleInfoManager* get();

private:
	static std::unique_ptr<ModuleInfoManager> sInstance;
	static constexpr std::string_view mLogPrefix{"ModuleInfoManager"};

	void registerModuleInfo(ModuleInfoBase* moduleInfo);
	void unregisterModuleInfo(ModuleInfoBase* moduleInfo);
	void dumpModuleDependencies(const std::list<ModuleInfoBase*>& l) const;
	bool moduleDependenciesPresent(const std::list<ModuleInfoBase*>& sortedList, ModuleInfoBase* module) const;
	void replaceModules(std::list<ModuleInfoBase*>& sortedList,
	                    const std::list<ModuleInfoBase*>& replacingModules) const;

	std::list<ModuleInfoBase*> mRegisteredModuleInfo;
};

class ModuleInfoBase {
public:
	enum ModuleOid {
		SanityChecker = 3,
		DoSProtection = 4,
		GarbageIn = 5,
		Capabilities = 10,
		NatHelper = 30,
		Authentication = 60,
		CustomAuthentication = 61,
		OpenIDConnectAuthentication = 62,
		TrustedHostsAuthentication = 63,
		Authorization = 70,
		DateHandler = 75,
		GatewayAdapter = 90,
		Registrar = 120,
		StatisticsCollector = 123,
		Router = 125,
		PushNotification = 130,
		ContactRouteInserter = 150,
		LoadBalancer = 180,
		MediaRelay = 210,
		Transcoder = 240,
		Forward = 270,
		Redirect = 290,
		Presence = 300,
		RegEvent = 305,
		B2bua = 307,
		InterDomainConnections = 310,
		Plugin = 320
	};

	ModuleInfoBase(const std::string& moduleName,
	               const std::string& help,
	               const std::vector<std::string>& after,
	               ModuleOid oid,
	               std::function<void(GenericStruct&)> declareConfig,
	               ModuleClass moduleClass,
	               const std::string& replace)
	    : mName(moduleName), mHelp(help), mAfter(after), mOidIndex(oid), mDeclareConfig(declareConfig),
	      mClass(moduleClass), mReplace(replace) {
		ModuleInfoManager::get()->registerModuleInfo(this);
		mLogPrefix = std::string("module::") + mName;
	}
	virtual ~ModuleInfoBase() {
		if (mRegistered) {
			ModuleInfoManager::get()->unregisterModuleInfo(this);
		}
	}

	const std::string& getModuleName() const {
		return mName;
	}
	const std::string& getLogPrefix() const {
		return mLogPrefix;
	}
	const std::string& getModuleHelp() const {
		return mHelp;
	}
	const std::vector<std::string>& getAfter() const {
		return mAfter;
	}
	unsigned int getOidIndex() const {
		return mOidIndex;
	}
	ModuleClass getClass() const {
		return mClass;
	}
	const std::string& getReplace() const {
		return mReplace;
	}
	const std::string& getFunction() const {
		return mReplace.empty() ? mName : mReplace;
	}
	void setRegistered(bool newState) {
		mRegistered = newState;
	}

	void declareConfig(GenericStruct& rootConfig) const;

	virtual std::shared_ptr<Module> create(Agent* agent) = 0;

private:
	std::string mName;
	std::string mLogPrefix;
	std::string mHelp;
	std::vector<std::string> mAfter;
	ModuleOid mOidIndex;
	std::function<void(GenericStruct&)> mDeclareConfig;
	ModuleClass mClass;
	std::string mReplace;
	bool mRegistered{false};
};

template <typename T>
class ModuleInfo : public ModuleInfoBase {
public:
	using ModuleType = T;

	ModuleInfo(const std::string& moduleName,
	           const std::string& help,
	           const std::vector<std::string>& after,
	           ModuleOid oid,
	           std::function<void(GenericStruct&)> declareConfig,
	           ModuleClass moduleClass = ModuleClass::Production,
	           const std::string& replace = "")
	    : ModuleInfoBase(moduleName, help, after, oid, declareConfig, moduleClass, replace) {
	}

	std::shared_ptr<Module> create(Agent* agent) override {
		std::shared_ptr<Module> module;
		module.reset(new T(agent, this));
		return module;
	}
};

} // namespace flexisip