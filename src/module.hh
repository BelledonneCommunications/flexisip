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
		const  unsigned int getOidIndex() {return mOidIndex;}
		virtual ~ModuleInfoBase(){
		}
	protected:
		ModuleInfoBase(const char *modname, const char *help) : mName(modname), mHelp(help),
		mOidIndex(Oid::oidFromHashedString(modname)){
			ModuleFactory::get()->registerModule(this);
		}
};

template <typename _module_>
class ModuleInfo : public ModuleInfoBase{
	public:
		ModuleInfo(const char *modname, const char *help) : ModuleInfoBase(modname,help){
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
		void load();
		void reload();
		void processRequest(std::shared_ptr<SipEvent> &ev);
		void processResponse(std::shared_ptr<SipEvent> &ev);
		void processTransactionEvent(const std::shared_ptr<Transaction> &transaction, Transaction::Event event);
		StatCounter64 &findStat(const std::string &statName) const;
		void idle();
	protected:
		virtual void onDeclare(GenericStruct *root){
		}
		virtual void onLoad(const GenericStruct *root){
		}
		virtual void onUnload(){
		}
		virtual void onRequest(std::shared_ptr<SipEvent> &ev)=0;
		virtual void onResponse(std::shared_ptr<SipEvent> &ev)=0;
		virtual void onTransactionEvent(const std::shared_ptr<Transaction> &transaction, Transaction::Event event) {

		}
		virtual void doOnConfigStateChanged(const ConfigValue &conf, ConfigState state);
		virtual void onIdle(){
		}
		Agent *mAgent;
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
		static void addRecordRoute(su_home_t *home, Agent *ag, msg_t *msg, sip_t *sip, const char *transport=NULL);
		static void prependRoute(su_home_t *home, Agent *ag, msg_t *msg, sip_t *sip, const char *route);
		static bool sipPortEquals(const char *p1, const char *p2);
		static int sipPortToInt(const char *port);
		static bool fromMatch(const sip_from_t *from1, const sip_from_t *from2);
		static bool matchesOneOf(const char *item, const std::list<std::string> &set);
		static bool fixAuthChallengeForSDP(su_home_t *home, msg_t *msg, sip_t *sip);
		static bool transportEquals(const char *tr1, const char *tr2);
};

#endif
