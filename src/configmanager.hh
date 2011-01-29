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

class Property{
	public:
		enum PropertyType{
			Boolean,
			String,
			Integer,
			Float
		};
		Property(){
		}
		const std::string & getName();
		const std::string & getValue();
};

class ConfigArea;

enum ConfigItemType{
	Boolean,
	Integer,
	String,
	StringList
};

struct ConfigItem {
	ConfigItemType type;
	const char *name;
	const char *default_value;
	const char *help;
};

class ConfigManager{
	friend class ConfigArea;
	public:
		static ConfigManager *get();
		void declareArea(const char *area_name, const char *help, ConfigItem *items);
		
		void load(const char* configFile);
		static const char *sGlobalArea;
		
		ConfigArea getArea(const char *name);
		
	private:
		ConfigManager();
		bool get(const char *area, const char *key, std::string *result);
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
