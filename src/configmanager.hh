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


#ifndef configmanager_hh
#define configmanager_hh

#include <string>
#include <list>
#include <cstdlib>

enum ConfigValueType{
	Boolean,
	Integer,
	String,
	StringList,
	Struct
};


struct ConfigItemDescriptor {
	ConfigItemType type;
	const char *name;
	const char *help;
	const char *default_value;
};

class ConfigEntry{
	public:
		const std::string & getName()const{
			return mName;
		}
		ConfigValueType getType()const{
			return mType;
		}
		const std::string &getHelp()const{
			return mHelp;
		}
	protected:
		ConfigEntry(const std::string &name, ConfigValueType type, const std::string &help);
	private:
		const std::string mName;
		const std::string mHelp;
		ConfigValueType mType;
};

class ConfigStruct : public ConfigEntry{
	public:
		ConfigStruct(const std::string &name, const std::string &help);
		void addChild(ConfigEntry *c);
		void addChildrenValues(ConfigItemDescriptor *items);
		std::list<ConfigEntry*> &getChildren();
	private:
		std::list<ConfigEntry*> mEntries;
}

class ConfigValue : public ConfigEntry{
	public:
		ConfigValue(const std::string &name, ConfigValueType  vt, const std::string &help, const std::string &default_value);
		void set(const char *value);
		void get(bool *retval)const ;
		void get(int *retval)const;
		void get(std::list<std::string> * retval)const;
	private:
		std::string mValue;
		const std::string mDefaultValue;
};



class ConfigManager{
	friend class ConfigArea;
	public:
		static ConfigManager *get();
		static const char *sGlobalArea;
		void declareArea(const char *area_name, const char *help, ConfigItemDescriptor *items);
		void load(const char* configFile);
		ConfigStruct *getRoot();
	private:
		ConfigManager();
		ConfigStruct mConfigRoot;
		struct _LpConfig *mConf;
		static ConfigManager *sInstance;
};

class FileConfigDumper{
	public:
		FileConfigDumper(ConfigStruct *root){
			mRoot=root;
		}
		std::ostream &dump(std::ostream & ostr);
	private:
		std::ostream &dump2(std::ostream & ostr, ConfigEntry *entry, int level);
		ConfigStruct *mRoot;
};

inline std::ostream & operator<<(std::ostream &ostr, FileConfigDumper &dumper){
	return dumper.dump(ostr);
}

#endif
