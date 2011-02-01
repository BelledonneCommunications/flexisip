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

ConfigValue::ConfigValue(const std::string &name, ConfigValueType  vt, const std::string &help, const std::string &default_value) 
	:  ConfigEntry (name,vt,help), mDefaultValue(default_value){
	
}

void ConfigValue::set(const std::string  &value){
	if (getType()==Boolean){
		if (value!="true" && value!="false" && value!="1" && value!="0"){
			LOGF("Not a boolean: \"%s\" for key \"%s\" ", value, getName());
		}
	}
	mValue=value;
}

void ConfigValue::setDefault(const char *value){
	if (getType()==Boolean){
		if (value!="true" && value!="false" && value!="1" && value!="0"){
			LOGF("Not a boolean: \"%s\" for key \"%s\" ", value, getName());
		}
	}
	mDefaultValue=value;
}

void ConfigValue::get(std::string *value)const{
	if (getType()!=String) LOGF("Value %s is not a string !",getName().c_str());
	*value=getValue();
}

void ConfigValue::get(int *value)const{
	if (getType()!=Integer) LOGF("Value %s is not a integer !",getName().c_str());
	*value=atoi(getValue().c_str());
}

void ConfigValue::get(bool *value)const{
	if (getType()!=Boolean) LOGF("Value %s is not a boolean !",getName().c_str());
	if (getValue()=="true" || getValue()=="1") *value=true;
	else *value=false;
}

#define DELIMITERS " \n,"

void ConfigValue::get(std::list<std::string> *retlist)const{
	char *res=strdup(getValue().c_str());
	char *saveptr=NULL;
	char *ret=strtok_r(res,DELIMITERS,&saveptr);
	while(ret!=NULL){
		retlist->push_back(std::string(ret));
		ret=strtok_r(NULL,DELIMITERS,&saveptr);
	}
	free(res);
}


ConfigEntry::ConfigEntry(const std::string &name, ConfigValueType type, const std::string &help) : 
mName(name),mType(type),mHelp(help){
}

ConfigStruct::ConfigStruct(const std::string &name, const std::string &help) : ConfigEntry(name,Struct,help){
	
}

void ConfigStruct::addChild(ConfigEntry *c){
	mEntries.push_back(c);
}

void ConfigStruct::addChildrenValues(ConfigItemDescriptor *items){
	for (;items.name!=NULL;items++){
		mEntries.push_back(new ConfigValue(items->name,items->type,items->help,items->default_value));
	}
}

std::list<ConfigEntry*> &ConfigStruct::getChildren(){
	return mEntries;
}

const char *ConfigManager::sGlobalArea="global";

ConfigManager *ConfigManager::sInstance=0;

ConfigManager *ConfigManager::get(){
	if (sInstance==NULL)
		sInstance=new ConfigManager();
	return sInstance;
}

ConfigManager::ConfigManager() : mConf(NULL){
}

void ConfigManager::load(const char* configfile){
	if (configfile==NULL){
		configfile=CONFIG_DIR "/flexisip.conf";
	}
	mConf=lp_config_new(configfile);
}

ConfigStruct *ConfigStruct::getRoot(){
	return mConfigRoot;
}

std::ostream &FileConfigDumper::dump(std::ostream & ostr){
	return dump2(ostr,0);
}

std::ostream &FileConfigDumper::dump2(std::ostream & ostr, ConfigEntry *entry, int level){
	ConfigStruct *cs=dynamic_cast<ConfigStruct*>(entry);
	ConfigValue *val;
	ostr<<cs->getHelp()<<std::endl;
	if (cs){
		if (level>0){
			ostr<<"["<<cs->getName()<<"]"<<std::endl;
		}else ostr<<std::endl;
		std::list<ConfigEntry*>::iterator it;
		for(it=cs->getChildren().begin();it!=cs->getChildren().end();++it){
			dump2(ostr,*it,level+1);
			ostr<<std::endl;
		}
	}else if ((val=dynamic_cast<ConfigValue*>(entry))!=NULL){
		ostr<<"Default value: "<<entry->getDefault()<<std::endl;
		ostr<<entry->getName()<<"="<<entry->getValue()<<std::endl;
		ostr<<std::endl;
	}
	return ostr;
}

