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

class ConfigManager{
	friend class ConfigArea;
	public:
		static ConfigManager *get();
		ConfigArea getArea(const char *name);
		static const char *sGlobalArea;
	private:
		ConfigManager();
		bool get(const char *area, const char *key, std::string *result);
		struct _LpConfig *mConf;
		static ConfigManager *sInstance;
};

class ConfigArea{
	friend class ConfigManager;
	public:
		template< typename _type_>
		_type_ get(const char *key, _type_ default_value)const{
			std::string result;
			if (mManager->get(mArea.c_str(),key,&result)){
				return result;
			}
			return default_value;
		}
		bool get(const char *key, bool default_value)const ;
		int get(const char *key, int default_value)const;
		std::list<std::string> get(const char *key, const std::list<std::string> &default_value)const;
	private:
		ConfigArea(ConfigManager *m, const char *area);
		const std::string mArea;
		ConfigManager *mManager;
};



#endif
