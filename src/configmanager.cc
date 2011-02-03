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
mName(name),mHelp(help),mType(type),mParent(0){
}

void ConfigEntry::setParent(ConfigEntry *parent){
	mParent=parent;
}

ConfigStruct::ConfigStruct(const std::string &name, const std::string &help) : ConfigEntry(name,Struct,help){
	
}

ConfigEntry * ConfigStruct::addChild(ConfigEntry *c){
	mEntries.push_back(c);
	c->setParent(this);
	return c;
}

void ConfigStruct::addChildrenValues(ConfigItemDescriptor *items){
	for (;items.name!=NULL;items++){
		ConfigValue *val=new ConfigValue(items->name,items->type,items->help,items->default_value);
		val.setParent(this);
		mEntries.push_back(val);
	}
}

ConfigEntry *ConfigStruct::get(const char *child_name)const{
	struct findByName{
		findByName(const char *name) : mName(name){
		}
		bool operator()(ConfigEntry *entry){
			return strcmp(entry->getName().c_str(),name)==0;
		}
	}
	list<ConfigEntry*>::const_terator it=find_if(mEntries.begin(),mEntries.end(),findByName(name));
	if (it!=mEntries.end()) {
		return val;
	}
	return NULL;
}

ConfigValue * ConfigStruct::getValue(const char *name){
	ConfigEntry *e=get(name);	
	if (e!=NULL)
		ConfigValue *val=dynamic_cast<ConfigValue*>(e);
		if (val==NULL) LOGA("%s is not a value.");
		return val;
	}
	return NULL;
}

const ConfigValue * ConfigStruct::getValue(const char *name)const{
	ConfigEntry *e=get(name);	
	if (e!=NULL)
		ConfigValue *val=dynamic_cast<ConfigValue*>(e);
		if (val==NULL) LOGA("%s is not a value.");
		return val;
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
	FileConfigReader reader(&mRoot);
	reader.read(configfile);
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


int FileConfigReader::read(const char *filename){
	mCfg=lp_config_new(NULL);
	if (lp_config_read_file(mCfg,filename)==-1)
		return -1;
	read2(mRoot,0);
}

int FileConfigReader::read2(ConfigEntry *entry, int level){
	ConfigStruct *cs=dynamic_cast<ConfigStruct*>(entry);
	ConfigValue *cv;
	if (cs){
		list<ConfigEntry> & entries=cs->getChildren();
		list<ConfigEntry::iterator it;
		for(it=entries.begin();it!=entries.end();++it){
			read2(*it,level+1);
		}
	}else if ((cv=dynamic_cast<ConfigValue*>(entry))){
		if (level==0){
			LOGF("ConfigValues at root is disallowed.");
		}else if (level==1){
			const char *val=lp_config_get_string(mCfg,cv->getParent()->getName(),cv->getName(),cv->getDefaultValue().c_str());
			cv->setValue(val);
		}else{
			LOGF("The current file format doesn't support recursive subsections.");
		}
	}
}

FileConfigReader::~FileConfigReader(){
	if (mCfg) lp_config_destroy(mCfg);
}
