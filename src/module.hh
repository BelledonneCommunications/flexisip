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

#include <list>

class ModuleInfoBase;
class Module;
class Agent;

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
	public:
		virtual Module *create(Agent *ag)=0;
		const std::string &getModuleName()const{
			return mName;
		}
		
	protected:
		ModuleInfoBase(const char *modname) : mName(modname){
			ModuleFactory::get()->registerModule(this);
		}
	private:
		const std::string mName;
};

template <typename _module_>
class ModuleInfo : public ModuleInfoBase{
	public:
		ModuleInfo(const char *modname) : ModuleInfoBase(modname){
		}
	protected:
		virtual Module *create(Agent *ag){
			return new _module_(ag);
		}
};

class SipEvent{
	public:
		SipEvent(msg_t *msg, sip_t *sip){
			mMsg=msg;
			mSip=sip;
			mStop=false;
		}
		msg_t *mMsg;
		sip_t *mSip;
		void stopProcessing(){
			mStop=true;
		}
		bool finished()const{
			return mStop;
		}
	private:
		bool mStop;
};

class Module {
	public:
		Module(Agent *);
		virtual ~Module();
		Agent *getAgent()const;
		nta_agent_t *getSofiaAgent()const;
		const std::string &getModuleName();
		void setName(const std::string &name);
		virtual void onLoad(Agent *agent){
		}
		virtual void onRequest(SipEvent *ev)=0;
		virtual void onResponse(SipEvent *ev)=0;
		virtual void onIdle(){
		}
		void enable(bool enabled);
		bool isEnabled() const;
	private:
		std::string mName;
		Agent *mAgent;
		bool mEnabled;
};

#endif
