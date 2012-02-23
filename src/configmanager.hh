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

#include "common.hh"

enum ConfigValueType{
	Boolean,
	Integer,
	String,
	StringList,
	Struct
};


struct ConfigItemDescriptor {
	ConfigValueType type;
	const char *name;
	const char *help;
	const char *default_value;
};

static const ConfigItemDescriptor config_item_end={Boolean,NULL,NULL,NULL};

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
		ConfigEntry *getParent()const{
			return mParent;
		}
		virtual ~ConfigEntry(){
		}
		void setParent(ConfigEntry *parent);
	protected:
		ConfigEntry(const std::string &name, ConfigValueType type, const std::string &help);
	private:
		const std::string mName;
		const std::string mHelp;
		ConfigValueType mType;
		ConfigEntry *mParent;
};

class ConfigValue;

class ConfigStruct : public ConfigEntry{
	public:
		ConfigStruct(const std::string &name, const std::string &help);
		ConfigEntry * addChild(ConfigEntry *c);
		void addChildrenValues(ConfigItemDescriptor *items);
		std::list<ConfigEntry*> &getChildren();
		template <typename _retType> 
		_retType *get(const char *name)const;
		~ConfigStruct();
		ConfigEntry *find(const char *name)const;
		ConfigEntry *findApproximate(const char *name)const;
	private:
		std::list<ConfigEntry*> mEntries;
};

class ConfigValue : public ConfigEntry{
	public:
		ConfigValue(const std::string &name, ConfigValueType  vt, const std::string &help, const std::string &default_value);
		void set(const std::string &value);
		const std::string &get()const;
		const std::string &getDefault()const;
		void setDefault(const std::string &value);
	private:
		std::string mValue;
		std::string mDefaultValue;
};

class ConfigBoolean : public ConfigValue{
	public:
		ConfigBoolean(const std::string &name, const std::string &help, const std::string &default_value);
		bool read()const;
};

class ConfigInt : public ConfigValue{
	public:
		ConfigInt(const std::string &name, const std::string &help, const std::string &default_value);
		int read()const;
};

class ConfigString : public ConfigValue{
	public:
		ConfigString(const std::string &name, const std::string &help, const std::string &default_value);
		const std::string & read()const;
};

class ConfigStringList : public ConfigValue{
	public:
		ConfigStringList(const std::string &name, const std::string &help, const std::string &default_value);
		std::list<std::string> read()const;
	private:
};

template <typename _retType>
_retType *ConfigStruct::get(const char *name)const{
	ConfigEntry *e=find(name);
	if (e==NULL) {
		LOGA("No ConfigEntry with name %s in struct %s",name,getName().c_str());
		return NULL;
	}
	_retType *ret=dynamic_cast<_retType *>(e);
	if (ret==NULL){
		LOGA("Config entry %s in struct %s does not have the expected type",name,e->getParent()->getName().c_str());
		return NULL;
	}
	return ret;
};


class FileConfigReader{
	public:
		FileConfigReader(ConfigStruct *root) : mRoot(root), mHaveUnreads(false), mCfg(NULL){
		}
		int read(const char *filename);
		int reload();
		void checkUnread();
		~FileConfigReader();
	private:
		int read2(ConfigEntry *entry, int level);
		static void onUnreadItem(void *p, const char *secname, const char *key, int lineno);
		void onUnreadItem(const char *secname, const char *key, int lineno);
		ConfigStruct *mRoot;
		struct _LpConfig *mCfg;
		bool mHaveUnreads;
};

class ConfigManager{
	friend class ConfigArea;
	public:
		static ConfigManager *get();
		void declareArea(const char *area_name, const char *help, ConfigItemDescriptor *items);
		int load(const char* configFile);
		ConfigStruct *getRoot();
		const ConfigStruct *getGlobal();
		void loadStrict();
	private:
		ConfigManager();
		static void atexit(); // Don't call directly!
		ConfigStruct mConfigRoot;
		FileConfigReader mReader;
		static ConfigManager *sInstance;
};

class FileConfigDumper{
	public:
		FileConfigDumper(ConfigStruct *root){
			mRoot=root;
		}
		std::ostream &dump(std::ostream & ostr)const;
	private:
		std::ostream & printHelp(std::ostream &os, const std::string &help, const std::string &comment_prefix)const;
		std::ostream &dump2(std::ostream & ostr, ConfigEntry *entry, int level)const;
		ConfigStruct *mRoot;
};

inline std::ostream & operator<<(std::ostream &ostr, const FileConfigDumper &dumper){
	return dumper.dump(ostr);
}




#endif
