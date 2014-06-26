/*
	Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010  Belledonne Communications SARL.

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

#ifndef module_hh
#define module_hh

#include "sofia-sip/nta_tport.h"
#include "sofia-sip/tport.h"
#include "sofia-sip/msg_header.h"

#include <string>
#include <memory>
#include <list>
#include "configmanager.hh"
#include "event.hh"
#include "transaction.hh"

class ModuleInfoBase;
class Module;
class Agent;
class StatCounter64;

class ModuleFactory{
	public:
		static ModuleFactory *get();
		Module *createModuleInstance(Agent *ag, const std::string &modname);
	private:
		void registerModule(ModuleInfoBase *m);
		std::list<ModuleInfoBase*> mModules;
		static ModuleFactory *sInstance;
		friend class ModuleInfoBase;
};

class ModuleInfoBase {
	const std::string mName;
	const std::string mHelp;
	const oid mOidIndex;
	static oid indexCount;
	public:
		Module *create(Agent *ag);
		virtual Module *_create(Agent *ag)=0;
		const std::string &getModuleName()const{
			return mName;
		}
		const std::string &getModuleHelp()const{
			return mHelp;
		}
		unsigned int getOidIndex () const {return mOidIndex;}
		virtual ~ModuleInfoBase();

		enum ModuleOid {
			SanityChecker=3,
			GarbageIn=5,
			NatHelper=30,
			Authentication=60,
			DateHandler=75,
			GatewayAdapter=90,
			Registrar=120,
			StatisticsCollector=123,
			Router=125,
			PushNotification=130,
			ContactRouteInserter=150,
			LoadBalancer=180,
			MediaRelay=210,
			Transcoder=240,
			Forward=270,
			Redirect=290
		};
	protected:
		ModuleInfoBase(const char *modname, const char *help, enum ModuleOid oid) : mName(modname), mHelp(help),
		mOidIndex(oid){ // Oid::oidFromHashedString(modname)
			ModuleFactory::get()->registerModule(this);
		}
};

template <typename _module_>
class ModuleInfo : public ModuleInfoBase{
	public:
		ModuleInfo(const char *modname, const char *help, ModuleOid oid) : ModuleInfoBase(modname,help,oid){
		}
	protected:
		virtual Module *_create(Agent *ag);
};

class EntryFilter;

/**
 * Abstract base class for all Flexisip module.
 * A module is an object that is able to process sip requests and sip responses.
 * It must implements at least:
 * virtual void onRequest(SipEvent *ev)=0;
 * virtual void onResponse(SipEvent *ev)=0;
**/
class Module : protected ConfigValueListener {
	friend class ModuleInfoBase;
	public:
		Module(Agent *);
		virtual ~Module();
		Agent *getAgent()const;
		nta_agent_t *getSofiaAgent()const;
		const std::string &getModuleName()const;
		void declare(GenericStruct *root);
		void checkConfig();
		void load();
		void reload();
		void processRequest(std::shared_ptr<RequestSipEvent> &ev);
		void processResponse(std::shared_ptr<ResponseSipEvent> &ev);
		StatCounter64 &findStat(const std::string &statName) const;
		void idle();
	public:
		inline void process(std::shared_ptr<RequestSipEvent> &ev) {
			processRequest(ev);
		}
		inline void process(std::shared_ptr<ResponseSipEvent> &ev) {
			processResponse(ev);
		}
	protected:
		virtual void onDeclare(GenericStruct *root){
		}
		virtual void onLoad(const GenericStruct *root){
		}
		virtual void onUnload(){
		}
		virtual void onRequest(std::shared_ptr<RequestSipEvent> &ev)=0;
		virtual void onResponse(std::shared_ptr<ResponseSipEvent> &ev)=0;
		virtual bool doOnConfigStateChanged(const ConfigValue &conf, ConfigState state);
		virtual void onIdle(){
		}
		virtual bool onCheckValidNextConfig() {return true;}
		virtual bool isValidNextConfig(const ConfigValue &cv) {return true;}
		void sendTrap(const std::string &msg) {
			GenericManager::get()->sendTrap(mModuleConfig, msg);
		}
		Agent *mAgent;
	protected:
		static std::list<std::string> sPushNotifParams;
	private:
		void setInfo(ModuleInfoBase *i);
		ModuleInfoBase *mInfo;
		GenericStruct *mModuleConfig;
		EntryFilter *mFilter;
		bool mDirtyConfig;
};


template <typename _modtype>
Module * ModuleInfo<_modtype>::_create(Agent *ag){
	Module *mod=new _modtype(ag);
	return mod;
}

/**
 * Some useful routines any module can use by derivating from this class.
**/
class ModuleToolbox{
	public:
		static msg_auth_t *findAuthorizationForRealm(su_home_t *home, msg_auth_t *au, const char *realm);
		static const tport_t *getIncomingTport(const std::shared_ptr<RequestSipEvent> &ev, Agent *ag);
		static void addRecordRouteIncoming(su_home_t *home, Agent *ag, const std::shared_ptr<RequestSipEvent> &ev);
		static url_t *urlFromTportName(su_home_t *home, const tp_name_t *name);
		static void addRecordRoute(su_home_t *home, Agent *ag, const std::shared_ptr<RequestSipEvent> &ev, const tport_t *tport);
		static void cleanAndPrependRoute(su_home_t *home, Agent *ag, msg_t *msg, sip_t *sip, const char *route);
		static void cleanAndPrependRoutable(su_home_t *home, Agent *ag, msg_t *msg, sip_t *sip, const std::list<std::string> &routes);
		static bool sipPortEquals(const char *p1, const char *p2, const char *transport=NULL);
		static int sipPortToInt(const char *port);
		static bool fromMatch(const sip_from_t *from1, const sip_from_t *from2);
		static bool matchesOneOf(const char *item, const std::list<std::string> &set);
		static bool fixAuthChallengeForSDP(su_home_t *home, msg_t *msg, sip_t *sip);
		static bool transportEquals(const char *tr1, const char *tr2);
		static bool isNumeric(const char *host);
		static bool isManagedDomain(const Agent *agent, const std::list<std::string> &domains, const url_t *url);
		static void addRoutingParam(su_home_t *home, sip_contact_t *contacts, const std::string &routingParam, const char *domain);
		static struct sip_route_s *prependNewRoutable(msg_t *msg, sip_t *sip, struct sip_route_s * &sipr, struct sip_route_s * &value);
		static void addPathHeader(Agent *ag, const std::shared_ptr<RequestSipEvent> &ev, const tport_t *tport, const char *uniq = NULL);
		/**
		* Returns true if via and url represent the same network address.
		**/
		static bool urlViaMatch(url_t *url, sip_via_t *via, bool use_received_rport);
		void removeParamsFromContacts(su_home_t *home, sip_contact_t *c, std::list<std::string> &params);
		void removeParamsFromUrl(su_home_t *home, url_t *u, std::list<std::string> &params);
};

#endif
