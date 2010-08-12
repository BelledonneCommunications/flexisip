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

class ModuleInfoBase;

class ModuleFactory{
	public:
		static ModuleFactory *get();
		Module *createModule(const std::string &modname);
	private:
		void registerModule(ModuleFactory *m);
		std::list<ModuleInfoBase*> mModules;
		static ModuleFactory *sInstance;
		friend class ModuleInfoBase;
};

class ModuleInfoBase {
	public:
		virtual Module *create()=0;
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
		virtual Module *create(){
			return new _module_(ag);
		}
		virtual const std::string &getModuleName()const{
			return mName;
		}
	private:
		const std::string mName;
};

class Module {
	public:
		Module();
		Agent *getAgent()const;
		const std::string &getName()const;
		virtual bool onLoad(Agent *agent);
		virtual bool onRequest(msg_t *msg, sip_t *sip)=0;
		virtual bool onResponse(msg_t *msg, sip_t *sip)=0;
		void enable(bool enabled);
		bool isEnabled() const;
	private:
		Agent *mAgent;
		bool mEnabled;
		
};
