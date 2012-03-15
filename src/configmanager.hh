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
#if defined(HAVE_CONFIG_H) && !defined(FLEXISIP_INCLUDED)
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include "flexisip-config.h"
#define FLEXISIP_INCLUDED
#endif
#include <string>
#include <sstream>
#include <list>
#include <cstdlib>
#include <vector>

#include <algorithm>

#include "common.hh"

#ifdef ENABLE_SNMP
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#else
typedef unsigned long oid;
#endif

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


struct ConfigItemDescriptor {
	ConfigValueType type;
	const char *name;
	const char *help;
	const char *default_value;
	unsigned int oid_leaf;
};



static const ConfigItemDescriptor config_item_end={Boolean,NULL,NULL,NULL, 0};

class Oid {
	friend class ConfigEntry;
	friend class ConfigValue;
	friend class ConfigStruct;
	friend class RootConfigStruct;
	protected:
		Oid(Oid &parent, oid leaf);
		Oid(std::vector<oid> path);
		Oid(std::vector<oid> path, oid leaf);
		std::vector<oid> &getValue() {return mOidPath;}
		std::string getValueAsString(){
			std::ostringstream oss (std::ostringstream::out);
			for (oid i=0; i < mOidPath.size(); ++i) {
				if (i != 0) oss << ".";
				oss << mOidPath[i];
			}
			return oss.str();
		}
		virtual ~Oid();
	private:
		std::vector<oid> mOidPath;
	public:
		oid getLeaf() { return mOidPath[mOidPath.size()-1]; }
};

class ConfigEntry {
public:
	static std::string sanitize(const std::string &str);

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
	virtual void setParent(ConfigEntry *parent);
	/*
	 * @returns entry oid built from parent & object oid index
	 */
	Oid& getOid() {return *mOid;};
	virtual void mibFragment(std::ostream &ostr, std::string spacing)const=0;
protected:
	void doMibFragment(std::ostream &ostr, std::string &syntax, std::string spacing) const;
	ConfigEntry(const std::string &name, ConfigValueType type, const std::string &help,oid oid_index=0);
	Oid *mOid;
	const std::string mName;
private:
	const std::string mHelp;
	ConfigValueType mType;
	ConfigEntry *mParent;

	unsigned int mOidLeaf;
};

class ConfigValue;

class ConfigStruct : public ConfigEntry{
	public:
		ConfigStruct(const std::string &name, const std::string &help,oid oid_index);
		ConfigEntry * addChild(ConfigEntry *c);
		void addChildrenValues(ConfigItemDescriptor *items);
		std::list<ConfigEntry*> &getChildren();
		template <typename _retType> 
		_retType *get(const char *name)const;
		~ConfigStruct();
		ConfigEntry *find(const char *name)const;
		ConfigEntry *findApproximate(const char *name)const;
		void mibFragment(std::ostream & ost, std::string spacing) const;
		virtual void setParent(ConfigEntry *parent);
	private:
		std::list<ConfigEntry*> mEntries;
};

class RootConfigStruct : public ConfigStruct {
public:
	RootConfigStruct(const std::string &name, const std::string &help, std::vector<oid> oid_root_prefix);
};

class ConfigValue : public ConfigEntry{
	public:
		ConfigValue(const std::string &name, ConfigValueType  vt, const std::string &help, const std::string &default_value,oid oid_index);
		void set(const std::string &value);
		const std::string &get()const;
		const std::string &getDefault()const;
		void setDefault(const std::string &value);
#ifdef ENABLE_SNMP
		static int sHandleSnmpRequest(netsnmp_mib_handler *handler,
				netsnmp_handler_registration *reginfo,
				netsnmp_agent_request_info   *reqinfo,
				netsnmp_request_info         *requests);
		virtual int handleSnmpRequest(netsnmp_mib_handler *,
				netsnmp_handler_registration *,netsnmp_agent_request_info*,netsnmp_request_info*);
#endif
		virtual void setParent(ConfigEntry *parent);
	private:
		std::string mValue;
		std::string mDefaultValue;

};

class ConfigBoolean : public ConfigValue{
	public:
		ConfigBoolean(const std::string &name, const std::string &help, const std::string &default_value,oid oid_index);
		bool read()const;
#ifdef ENABLE_SNMP
		virtual int handleSnmpRequest(netsnmp_mib_handler *,
				netsnmp_handler_registration *,netsnmp_agent_request_info*,netsnmp_request_info*);
#endif
		void mibFragment(std::ostream & ost, std::string spacing)const;
};

class ConfigInt : public ConfigValue{
	public:
#ifdef ENABLE_SNMP
		virtual int handleSnmpRequest(netsnmp_mib_handler *,
				netsnmp_handler_registration *,netsnmp_agent_request_info*,netsnmp_request_info*);
#endif
		ConfigInt(const std::string &name, const std::string &help, const std::string &default_value,oid oid_index);
		void mibFragment(std::ostream & ost, std::string spacing) const;
		int read()const;
};

class ConfigString : public ConfigValue{
	public:
		ConfigString(const std::string &name, const std::string &help, const std::string &default_value,oid oid_index);
		const std::string & read()const;
		void mibFragment(std::ostream & ost, std::string spacing) const;
};

class ConfigStringList : public ConfigValue{
	public:
		ConfigStringList(const std::string &name, const std::string &help, const std::string &default_value,oid oid_index);
		std::list<std::string> read()const;
		void mibFragment(std::ostream & ost, std::string spacing) const;
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
		FileConfigReader(ConfigStruct *root) : mRoot(root),mCfg(NULL),mHaveUnreads(false){
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

class MibDumper{
public:
	MibDumper(ConfigStruct *root){
		mRoot=root;
	}
	std::ostream &dump(std::ostream & ostr)const;
private:
	std::ostream &dump2(std::ostream & ostr, ConfigEntry *entry, int level)const;
	ConfigStruct *mRoot;
};

inline std::ostream & operator<<(std::ostream &ostr, const MibDumper &dumper){
	return dumper.dump(ostr);
}



#endif
