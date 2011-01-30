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

class ConfigArea;

enum ConfigValueType{
	Boolean,
	Integer,
	String,
	StringList
};

class ConfigEntry{
	std::string mName;
};

class ConfigStruct : public ConfigEntry{
	std::map<std::string, ConfigEntry*> mMap;
}

class ConfigValue : public ConfigEntry{
	std::string mValue;
	ConfigValueType mType;
};

class ConfigArray : public ConfigEntry{
	ConfigValueType mType;
	std::vector<ConfigValue*> mValues;
};

struct ConfigItemDescriptor {
	ConfigItemType type;
	const char *name;
	const char *default_value;
	const char *help;
};

class ConfigManager{
	friend class ConfigArea;
	public:
		static ConfigManager *get();
		static const char *sGlobalArea;
		void declareArea(const char *area_name, const char *help, ConfigItem *items);
		void load(const char* configFile);
		std::ostream &dumpConfig(std::ostream &str);
		ConfigArea getArea(const char *name);
	private:
		ConfigManager();
		bool get(const char *area, const char *key, std::string *result);
		std::map<std::string,ConfigItem *> mConfigMap;
		struct _LpConfig *mConf;
		static ConfigManager *sInstance;
};

class ConfigArea{
	friend class ConfigManager;
	public:
		void get(const char *key, bool *retval)const ;
		void get(const char *key, int *retval)const;
		void get(const char *key, std::list<std::string> * retval)const;
	private:
		ConfigArea(ConfigManager *m, const char *area);
		const std::string mArea;
		ConfigManager *mManager;
};



#endif
