/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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

#pragma once

#include <sofia-sip/msg_header.h>
#include <sofia-sip/nta_tport.h>
#include <sofia-sip/tport.h>

#include "flexisip/configmanager.hh"
#include "flexisip/event.hh"

#include "entryfilter.hh"

namespace flexisip {

// =============================================================================

// -----------------------------------------------------------------------------
// Module.
// -----------------------------------------------------------------------------

class ModuleInfoBase;

template<typename T>
class ModuleInfo;

class SharedLibrary;

enum class ModuleClass {
	Experimental,
	Production
};

extern "C" Module *__flexisipCreatePlugin(Agent *agent, SharedLibrary *sharedLibrary);

/**
 * Abstract base class for all Flexisip module.
 * A module is an object that is able to process sip requests and sip responses.
 * It must implements at least:
 * virtual void onRequest(SipEvent *ev)=0;
 * virtual void onResponse(SipEvent *ev)=0;
**/
class Module : protected ConfigValueListener {
	template<typename T>
	friend class ModuleInfo;

	friend Module *__flexisipCreatePlugin(Agent *agent, SharedLibrary *sharedLibrary);

public:
	Module(Agent *agent);
	virtual ~Module() = default;

	Agent *getAgent() const {return mAgent;}
	nta_agent_t *getSofiaAgent() const;
	const std::string &getModuleName() const;
	const std::string &getModuleConfigName() const;
	void declare(GenericStruct *root);
	void checkConfig();
	void load();
	void unload();
	void reload();
	StatCounter64 &findStat(const std::string &statName) const;
	void idle();
	bool isEnabled() const;
	ModuleClass getClass() const;

	void processRequest(std::shared_ptr<RequestSipEvent> &ev);
	void processResponse(std::shared_ptr<ResponseSipEvent> &ev);
	void process(std::shared_ptr<RequestSipEvent> &ev) {processRequest(ev);}
	void process(std::shared_ptr<ResponseSipEvent> &ev) {processResponse(ev);}

	void setInfo(ModuleInfoBase *moduleInfo);

protected:
	virtual void onDeclare(GenericStruct *root) {}
	virtual void onLoad(const GenericStruct *root) {}
	virtual void onUnload() {}

	virtual void onRequest(std::shared_ptr<RequestSipEvent> &ev) = 0;
	virtual void onResponse(std::shared_ptr<ResponseSipEvent> &ev) = 0;

	virtual bool doOnConfigStateChanged(const ConfigValue &conf, ConfigState state);
	virtual void onIdle() {}

	virtual bool onCheckValidNextConfig() {return true;}

	virtual bool isValidNextConfig(const ConfigValue &cv) {return true;}

	void sendTrap(const std::string &msg) {GenericManager::get()->sendTrap(mModuleConfig, msg);}

protected:
	SofiaAutoHome mHome;
	Agent *mAgent = nullptr;
	ModuleInfoBase *mInfo = nullptr;
	GenericStruct *mModuleConfig = nullptr;
	std::unique_ptr<EntryFilter> mFilter;
};

// -----------------------------------------------------------------------------
// ModuleInfo.
// -----------------------------------------------------------------------------

class ModuleInfoBase;

class ModuleInfoManager {
	friend class ModuleInfoBase;

public:
	const std::list<ModuleInfoBase *> &getRegisteredModuleInfo() const {
		return mRegisteredModuleInfo;
	}
	std::list<ModuleInfoBase*> buildModuleChain()const;

	static ModuleInfoManager *get();

private:
	void registerModuleInfo(ModuleInfoBase *moduleInfo);
	void unregisterModuleInfo(ModuleInfoBase *moduleInfo);
	void dumpModuleDependencies(const std::list<ModuleInfoBase *> &l) const;
	bool moduleDependenciesPresent(const std::list<ModuleInfoBase *> &sortedList, ModuleInfoBase *module) const;
	void eliminateReplacedModules(std::list<ModuleInfoBase *> &sortedList) const;
	
	std::list<ModuleInfoBase *> mRegisteredModuleInfo;

	static ModuleInfoManager *sInstance;
};

class ModuleInfoBase {
	friend class Agent;

public:
	enum ModuleOid {
		SanityChecker = 3,
		DoSProtection = 4,
		GarbageIn = 5,
		NatHelper = 30,
		Authentication = 60,
		CustomAuthentication = 61,
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
		InterDomainConnections = 310,
		Plugin = 320
	};

	virtual ~ModuleInfoBase() {
		ModuleInfoManager::get()->unregisterModuleInfo(this);
	}

	const std::string &getModuleName() const {
		return mName;
	}

	const std::string &getModuleHelp() const {
		return mHelp;
	}

	const std::vector<std::string> &getAfter() const {
		return mAfter;
	}

	unsigned int getOidIndex() const {
		return mOidIndex;
	}

	ModuleClass getClass() const {
		return mClass;
	}

	const std::string &getReplace() const {
		return mReplace;
	}

protected:
	ModuleInfoBase(
		const std::string &moduleName, const std::string &help, const std::vector<std::string> &after,
		ModuleOid oid, ModuleClass moduleClass, const std::string &replace
	) : mName(moduleName), mHelp(help), mAfter(after), mOidIndex(oid), mClass(moduleClass), mReplace(replace) {
		ModuleInfoManager::get()->registerModuleInfo(this);
	}

	virtual Module *create(Agent *agent) = 0;

private:
	const std::string mName;
	const std::string mHelp;
	const std::vector<std::string> mAfter;
	const oid mOidIndex;
	ModuleClass mClass;
	const std::string mReplace;
};

template<typename T>
class ModuleInfo : public ModuleInfoBase {
public:
	typedef T ModuleType;

	ModuleInfo(
		const std::string &moduleName, const std::string &help, const std::vector<std::string> &after,
		ModuleOid oid, ModuleClass moduleClass = ModuleClass::Production, const std::string &replace = ""
	) : ModuleInfoBase(moduleName, help, after, oid, moduleClass, replace) {}

private:
	Module *create(Agent *agent) override {
		Module *module = new T(agent);
		module->setInfo(this);
		return module;
	}
};

inline std::ostringstream &operator<<(std::ostringstream &os, const Module &module) {
	os << module.getModuleName();
	return os;
}

// -----------------------------------------------------------------------------
// ModuleToolBox.
// -----------------------------------------------------------------------------

/**
 * Some useful routines any module can use by derivating from this class.
**/
class ModuleToolbox {
public:
	static msg_auth_t *findAuthorizationForRealm(su_home_t *home, msg_auth_t *au, const char *realm);
	static const tport_t *getIncomingTport(const std::shared_ptr<RequestSipEvent> &ev, Agent *agent);

	static void addRecordRouteIncoming(Agent *agent, const std::shared_ptr<RequestSipEvent> &ev);
	static void addRecordRoute(Agent *agent, const std::shared_ptr<RequestSipEvent> &ev, const tport_t *tport);

	static void cleanAndPrependRoute(Agent *agent, msg_t *msg, sip_t *sip, sip_route_t *route);

	static bool sipPortEquals(const char *p1, const char *p2, const char *transport = nullptr);
	static int sipPortToInt(const char *port);

	static bool fromMatch(const sip_from_t *from1, const sip_from_t *from2);
	static bool matchesOneOf(const std::string &item, const std::list<std::string> &set);

	static bool fixAuthChallengeForSDP(su_home_t *home, msg_t *msg, sip_t *sip);
	static bool transportEquals(const char *tr1, const char *tr2);
	static bool isNumeric(const char *host);
	static bool isManagedDomain(const Agent *agent, const std::list<std::string> &domains, const url_t *url);
	static void addRoutingParam(
		su_home_t *home, sip_contact_t *contacts, const std::string &routingParam, const char *domain
	);
	static struct sip_route_s *prependNewRoutable(msg_t *msg, sip_t *sip, sip_route_t *&sipr, sip_route_t *value);
	static void addPathHeader(
		Agent *agent, const std::shared_ptr<RequestSipEvent> &ev, tport_t *tport, const char *uniq = nullptr
	);

	// These methods do host comparison taking into account that each one of argument can be an ipv6 address enclosed in
	// brakets.
	static bool urlHostMatch(const char *host1, const char *host2);
	static bool urlHostMatch(const url_t *url, const char *host);

	// Returns the host taking into account that if it is an ipv6 address, then brakets are removed.
	static std::string getHost(const char *host);

	static std::string urlGetHost(url_t *url);
	static void urlSetHost(su_home_t *home, url_t *url, const char *host);
	static bool urlIsResolved(url_t *uri);

	//Returns true if via and url represent the same network address.
	static bool urlViaMatch(const url_t *url, const sip_via_t *via, bool use_received_rport);

	// Returns true if the destination represented by url is present in the via chain.
	static bool viaContainsUrl(const sip_via_t *vias, const url_t *url);
	// Returns true if the destination host contained in 'url' is present in via headers. This helps loop detection.
	static bool viaContainsUrlHost(const sip_via_t *vias, const url_t *url);

	// Returns true if the two url represent the same transport channel (IP, port and protocol).
	static bool urlTransportMatch(const url_t *url1, const url_t *url2);
	static std::string urlGetTransport(const url_t *url);
	static void removeParamsFromContacts(su_home_t *home, sip_contact_t *c, std::list<std::string> &params);
	static void removeParamsFromUrl(su_home_t *home, url_t *u, std::list<std::string> &params);
	static sip_unknown_t *getCustomHeaderByName(const sip_t *sip, const char *name);
	static int getCpuCount();
	static bool getUriParameter(const url_t *url, const char *param, std::string &value);
	static bool getBoolUriParameter(const url_t *url, const char *param, bool defaultValue);
	static sip_via_t *getLastVia(sip_t *sip);
	/* same as url_make() from sofia, but unsure that the url is sip or sips; otherwise return NULL*/
	static url_t *sipUrlMake(su_home_t *home, const char *value);
};

}
