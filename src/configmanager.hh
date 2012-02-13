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

// ids below the root levels
#define GLOBAL_OID_INDEX 1
#define TLS_OID_INDEX 2
#define STUN_OID_INDEX 3
#define FISRT_MODULE_OID_INDEX 10
#define NATHELPER_OID_INDEX FISRT_MODULE_OID_INDEX
#define AUTHENTICATION_OID_INDEX FISRT_MODULE_OID_INDEX+1
#define REGISTRAR_OID_INDEX FISRT_MODULE_OID_INDEX+2
#define CONTACTROUTEINSERTER_OID_INDEX FISRT_MODULE_OID_INDEX+3
#define LOADBALANCER_OID_INDEX FISRT_MODULE_OID_INDEX+4
#define MEDIARELAY_OID_INDEX FISRT_MODULE_OID_INDEX+5
#define TRANSCODER_OID_INDEX FISRT_MODULE_OID_INDEX+6
#define FORWARD_OID_INDEX FISRT_MODULE_OID_INDEX+7


struct ConfigItemDescriptor {
	ConfigValueType type;
	const char *name;
	const char *help;
	const char *default_value;
};



static const ConfigItemDescriptor config_item_end={Boolean,NULL,NULL,NULL};

class Oid {
	friend class ConfigEntry;
	friend class RootConfigStruct;
	protected:
		Oid(unsigned int root[],unsigned int rootLength, unsigned int leaf);
		unsigned int* getValue() {return mOid;}
		unsigned int getLenght() {return mOidLength;}
		virtual ~Oid();
	private:
		unsigned int* mOid;
		unsigned int mOidLength;
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
		ConfigEntry *getParent()const{
			return mParent;
		}
		virtual ~ConfigEntry(){
		}
		void setParent(ConfigEntry *parent);

		/*
		* @returns entry oid built from parent & object oid index
		*/
		Oid& getOid() {return *mOid;};

	protected:
		ConfigEntry(const std::string &name, ConfigValueType type, const std::string &help,unsigned int oid_index=0);
		Oid* mOid;
		private:
		const std::string mName;
		const std::string mHelp;
		ConfigValueType mType;
		ConfigEntry *mParent;

		unsigned int mPartialOid;
};

class ConfigValue;

class ConfigStruct : public ConfigEntry{
	public:
		ConfigStruct(const std::string &name, const std::string &help,unsigned int oid_index);
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

class RootConfigStruct : public ConfigStruct {
public:
	RootConfigStruct(const std::string &name, const std::string &help,unsigned int root_oid[],unsigned int root_oid_length);
};

class ConfigValue : public ConfigEntry{
	public:
		ConfigValue(const std::string &name, ConfigValueType  vt, const std::string &help, const std::string &default_value,unsigned int oid_index);
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
		ConfigBoolean(const std::string &name, const std::string &help, const std::string &default_value,unsigned int oid_index);
		bool read()const;
};

class ConfigInt : public ConfigValue{
	public:
		ConfigInt(const std::string &name, const std::string &help, const std::string &default_value,unsigned int oid_index);
		int read()const;
};

class ConfigString : public ConfigValue{
	public:
		ConfigString(const std::string &name, const std::string &help, const std::string &default_value,unsigned int oid_index);
		const std::string & read()const;
};

class ConfigStringList : public ConfigValue{
	public:
		ConfigStringList(const std::string &name, const std::string &help, const std::string &default_value,unsigned int oid_index);
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
		FileConfigReader(ConfigStruct *root) : mRoot(root), mHaveUnreads(false){
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
		RootConfigStruct mConfigRoot;
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
