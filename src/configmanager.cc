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

#include "lpconfig.h"
#include <cstring>
#include "configmanager.hh"
#include "common.hh"

ConfigArea::ConfigArea(ConfigManager *m, const char *area) :  mArea(area), mManager(m){
}

bool ConfigArea::get(const char *key, bool default_value){
	std::string result;
	if (mManager->get(mArea.c_str(),key,&result)){
		return atoi(result.c_str());
	}
	return default_value;
}

std::list<std::string> ConfigArea::get(const char *key, const std::list<std::string> & default_value){
	std::string result;
	if (mManager->get(mArea.c_str(),key,&result)){
		std::list<std::string> retlist;
		char *res=strdup(result.c_str());
		char *saveptr=NULL;
		char *ret=strtok_r(res,",",&saveptr);
		while(ret!=NULL){
			retlist.push_back(std::string(ret));
			ret=strtok_r(NULL,",",&saveptr);
		}
		free(res);
		return retlist;
	}
	return default_value;
}


const char *ConfigManager::sGlobalArea="global";
ConfigManager *ConfigManager::sInstance=0;

ConfigManager *ConfigManager::get(){
	if (sInstance==NULL)
		sInstance=new ConfigManager();
	return sInstance;
}

ConfigManager::ConfigManager(){
	mConf=lp_config_new("/etc/flexisip/flexisip.conf");
}

ConfigArea ConfigManager::getArea(const char *name){
	return ConfigArea(this,name);
}

bool ConfigManager::get(const char *area, const char *key, std::string *result){
	const char *res;
	const char *undefined="undefined";
	res=lp_config_get_string(mConf,area,key,undefined);
	if (res==undefined) return false;
	if (res!=NULL) result->assign(res);
	return true;
}

