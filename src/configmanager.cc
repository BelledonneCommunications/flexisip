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


#include <cstring>
#include <algorithm>
#include <iostream>

#include "lpconfig.h"
#include "configmanager.hh"
#include "common.hh"

#include <functional>

#include <ctime>
#include <sstream>

using namespace::std;


static void camelFindAndReplace(const string &needle, string &haystack) {
	size_t pos;
	while ((pos=haystack.find(needle)) != string::npos) {
		haystack.replace(pos, needle.length(), "");
		if (haystack.length() > pos) {
			stringstream ss;
			ss << char(toupper(haystack.at(pos)));
			haystack.replace(pos, 1, ss.str());
		}
	}
}

string ConfigEntry::sanitize(const string &str){
	string strnew=str;
	camelFindAndReplace("::", strnew);
	camelFindAndReplace("-", strnew);
	return strnew;
}

void ConfigEntry::mibFragment(ostream & ost, string spacing) const{
	string s("OCTET STRING");
	doMibFragment(ost, s, spacing);
}

void ConfigBoolean::mibFragment(ostream & ost, string spacing) const{
	string s("INTEGER { true(1),false(0) }");
	doMibFragment(ost, s, spacing);
}
void ConfigInt::mibFragment(ostream & ost, string spacing) const{
	string s("Integer32");
	doMibFragment(ost, s, spacing);
}
void ConfigString::mibFragment(ostream & ost, string spacing) const{
	ConfigValue::mibFragment(ost, spacing);
}
void ConfigStringList::mibFragment(ostream & ost, string spacing) const{
	ConfigValue::mibFragment(ost, spacing);
}
void ConfigStruct::mibFragment(ostream & ost, string spacing) const{
	string parent = getParent() ? getParent()->getName() : "flexisipMIB";
	ost << spacing << sanitize(getName()) << "	"
			<< "OBJECT IDENTIFIER ::= { "
			<< sanitize(parent) << " "
			<< mOid->getLeaf() << " }" << endl;
}



void ConfigEntry::doMibFragment(ostream & ostr, string &syntax, string spacing) const{
	if (!getParent()) LOGA("no parent found for %s", getName().c_str());
	ostr << spacing << sanitize(getName()) << " OBJECT-TYPE" << endl
			<< spacing << "	SYNTAX" << "	" << syntax << endl
			<< spacing << "	MAX-ACCESS	read-only" << endl
			<< spacing << "	STATUS	current" << endl
			<< spacing << "	DESCRIPTION" << endl
			<< spacing << "	\"" << getHelp() << "\"" << endl
			<< spacing << "	::= { " << sanitize(getParent()->getName()) << " " << mOid->getLeaf() << " }" << endl;
}

ConfigValue::ConfigValue(const std::string &name, ConfigValueType  vt, const std::string &help, const std::string &default_value,oid oid_index)
:  ConfigEntry (name,vt,help,oid_index), mDefaultValue(default_value){

}

void ConfigValue::set(const std::string  &value){
	if (getType()==Boolean){
		if (value!="true" && value!="false" && value!="1" && value!="0"){
			LOGF("Not a boolean: \"%s\" for key \"%s\" ", value.c_str(), getName().c_str());
		}
	}
	mValue=value;
}

void ConfigValue::setDefault(const std::string & value){
	if (getType()==Boolean){
		if (value!="true" && value!="false" && value!="1" && value!="0"){
			LOGF("Not a boolean: \"%s\" for key \"%s\" ", value.c_str(), getName().c_str());
		}
	}
	mDefaultValue=value;
}

const std::string & ConfigValue::get()const{
	return mValue;
}

const std::string & ConfigValue::getDefault()const{
	return mDefaultValue;
}

Oid::Oid(Oid &parent, oid leaf) {
	mOidPath=parent.getValue();
	mOidPath.push_back(leaf);
}

Oid::Oid(vector<oid> path, oid leaf) {
	mOidPath=path;
	mOidPath.push_back(leaf);
}

Oid::Oid(vector<oid> path) {
	mOidPath=path;
}

Oid::~Oid() {
}

ConfigEntry::ConfigEntry(const std::string &name, ConfigValueType type, const std::string &help,oid oid_index) :
				mOid(0),mName(name),mHelp(help),mType(type),mParent(0),mOidLeaf(oid_index){
	if (strchr(name.c_str(),'_'))
		LOGA("Underscores not allowed in config items, please use minus sign.");
}


void ConfigEntry::setParent(ConfigEntry *parent){
	mParent=parent;
	if (mOid) delete mOid;
	mOid = new Oid(parent->getOid(),mOidLeaf);
}

void ConfigValue::setParent(ConfigEntry *parent){
	ConfigEntry::setParent(parent);
#ifdef ENABLE_SNMP
	LOGE("SNMP registering %s %s (as %s)",mOid->getValueAsString().c_str(), mName.c_str(), sanitize(mName).c_str());
	netsnmp_handler_registration *reginfo=netsnmp_create_handler_registration(
			sanitize(mName).c_str(), &ConfigValue::sHandleSnmpRequest,
			(oid *) &mOid->getValue()[0], mOid->getValue().size(),
			HANDLER_CAN_RONLY);
	reginfo->my_reg_void=this;
	int res=netsnmp_register_scalar(reginfo);
	if (res != MIB_REGISTERED_OK) {
		if (res == MIB_DUPLICATE_REGISTRATION) {
			LOGE("Duplicate registration of SNMP %s", mName.c_str());
		} else {
			LOGE("Couldn't register SNMP %s", mName.c_str());
		}
	}
#endif
}

ConfigStruct::ConfigStruct(const std::string &name, const std::string &help,oid oid_index) : ConfigEntry(name,Struct,help,oid_index){

}

void ConfigStruct::setParent(ConfigEntry *parent){
	ConfigEntry::setParent(parent);
#ifdef ENABLE_SNMP
	LOGE("SNMP node %s %s",mOid->getValueAsString().c_str(), mName.c_str());
#endif
}

ConfigEntry * ConfigStruct::addChild(ConfigEntry *c){
	mEntries.push_back(c);
	c->setParent(this);
	return c;
}

void ConfigStruct::addChildrenValues(ConfigItemDescriptor *items){
	int oid_index=10;
	int actual_index;
	for (;items->name!=NULL;items++){
		ConfigValue *val=NULL;
		if (items->oid_leaf == 0) {
			++oid_index;
			actual_index=oid_index;
		} else {
			actual_index=items->oid_leaf;
		}
		switch(items->type){
		case Boolean:
			val=new ConfigBoolean(items->name,items->help,items->default_value,actual_index);
			break;
		case Integer:
			val=new ConfigInt(items->name,items->help,items->default_value,actual_index);
			break;
		case String:
			val=new ConfigString(items->name,items->help,items->default_value,actual_index);
			break;
		case StringList:
			val=new ConfigStringList(items->name,items->help,items->default_value,actual_index);
			break;
		default:
			LOGA("Bad ConfigValue type %u for %s!", items->type, items->name);
			if (items->oid_leaf == 0) --oid_index;
			break;
		}
		addChild(val);
	}
}

struct matchEntryName{
	matchEntryName(const char *name) : mName(name){};
	bool operator()(ConfigEntry* e){
		return strcmp(mName,e->getName().c_str())==0;
	}
	const char *mName;
};

ConfigEntry *ConfigStruct::find(const char *name)const{
	std::list<ConfigEntry*>::const_iterator it=find_if(mEntries.begin(),mEntries.end(),matchEntryName(name));
	if (it!=mEntries.end()) return *it;
	return NULL;
}

struct matchEntryNameApprox{
	matchEntryNameApprox(const char *name) : mName(name){};
	bool operator()(ConfigEntry* e){
		unsigned int i;
		int count=0;
		int min_required=mName.size()-2;
		if (min_required<1) return false;

		for(i=0;i<mName.size();++i){
			if (e->getName().find(mName[i])!=std::string::npos){
				count++;
			}
		}
		if (count>=min_required){
			return true;
		}
		return false;
	}
	const std::string mName;
};

ConfigEntry * ConfigStruct::findApproximate(const char *name)const{
	std::list<ConfigEntry*>::const_iterator it=find_if(mEntries.begin(),mEntries.end(),matchEntryNameApprox(name));
	if (it!=mEntries.end()) return *it;
	return NULL;
}

std::list<ConfigEntry*> &ConfigStruct::getChildren(){
	return mEntries;
}

struct destroy{
	void operator()(ConfigEntry *e){
		delete e;
	}
};

ConfigStruct::~ConfigStruct(){
	for_each(mEntries.begin(),mEntries.end(),destroy());
}


ConfigBoolean::ConfigBoolean(const std::string &name, const std::string &help, const std::string &default_value,oid oid_index)
: ConfigValue(name, Boolean, help, default_value,oid_index){
}

bool ConfigBoolean::read()const{
	if (get()=="true" || get()=="1") return true;
	else if (get()=="false" || get()=="0") return false;
	LOGA("Bad boolean value %s",get().c_str());
	return false;
}


ConfigInt::ConfigInt(const std::string &name, const std::string &help, const std::string &default_value,oid oid_index)
:	ConfigValue(name,Integer,help,default_value,oid_index){
}

int ConfigInt::read()const{
	return atoi(get().c_str());
}

ConfigString::ConfigString(const std::string &name, const std::string &help, const std::string &default_value,oid oid_index)
:	ConfigValue(name,String,help,default_value,oid_index){
}

const std::string & ConfigString::read()const{
	return get();
}


ConfigStringList::ConfigStringList(const std::string &name, const std::string &help, const std::string &default_value,oid oid_index)
:	ConfigValue(name,StringList,help,default_value,oid_index){
}

#define DELIMITERS " \n,"

std::list<std::string>  ConfigStringList::read()const{
	std::list<std::string> retlist;
	char *res=strdup(get().c_str());
	char *saveptr=NULL;
	char *ret=strtok_r(res,DELIMITERS,&saveptr);
	while(ret!=NULL){
		retlist.push_back(std::string(ret));
		ret=strtok_r(NULL,DELIMITERS,&saveptr);
	}
	free(res);
	return retlist;
}


ConfigManager *ConfigManager::sInstance=0;

static void init_flexisip_snmp() {
#ifdef ENABLE_SNMP
	LOGE("Initializing snmp");

	int syslog = 0; /* change this if you want to use syslog */

	//snmp_set_do_debugging(1);
	/* print log errors to syslog or stderr */
	if (syslog)
		snmp_enable_calllog();
	else
		snmp_enable_stderrlog();

	/* make us a agentx client. */
	netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1);
	//netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,NETSNMP_DS_AGENT_X_SOCKET,"udp:localhost:161");
	netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID,NETSNMP_DS_AGENT_VERBOSE,0);

	/* initialize tcpip, if necessary */
	SOCK_STARTUP;

	/* initialize the agent library */
	int err=init_agent("flexisip");
	if (err !=0 ) {
		LOGF("error init snmp agent %d", errno);
	}
#endif
}

ConfigManager *ConfigManager::get(){
	if (sInstance==NULL) {
		init_flexisip_snmp();
		sInstance=new ConfigManager();
	}
	return sInstance;
}

static ConfigItemDescriptor global_conf[]={
		{	Boolean	,	"debug"	,	"Outputs very detailed logs",	"false"	},
		{	Boolean	,	"auto-respawn",	"Automatically respawn flexisip in case of abnormal termination (crashes)",	"true"},
		{	StringList	,	"aliases"	,	"List of white space separated host names pointing to this machine. This is to prevent loops while routing SIP messages.", "localhost"},
		{	String	,	"ip-address",	"The public ip address of the proxy.",	"guess"},
		{	String	,	"bind-address",	"The local interface's ip address where to listen. The wildcard (*) means all interfaces.",	"*"},
		{	Integer	,	"port"		,	"UDP/TCP port number to listen for sip messages.",	"5060"},
		config_item_end
};

static ConfigItemDescriptor tls_conf[]={
		{	Boolean	,	"enabled"	,	"Enable SIP/TLS (sips)",	"true"	},
		{	Integer	,	"port",	"The port used for SIP/TLS",	"5061"},
		{	String	,	"certificates-dir", "An absolute path of a directory where TLS certificate can be found. "
				"The private key for TLS server must be in a agent.pem file within this directory" , "/etc/flexisip/tls"	},
				config_item_end
};

RootConfigStruct::RootConfigStruct(const std::string &name, const std::string &help,vector<oid> oid_root_path)
: ConfigStruct(name,help,1) {
	mOid = new Oid(oid_root_path,1);
}
static oid company_id = SNMP_COMPANY_OID;
ConfigManager::ConfigManager() : mConfigRoot("flexisip","This is the default Flexisip configuration file",{1,3,6,1,4,1,company_id}), mReader(&mConfigRoot){
	ConfigStruct *global=new ConfigStruct("global","Some global settings of the flexisip proxy.",GLOBAL_OID_INDEX);
	mConfigRoot.addChild(global);
	global->addChildrenValues(global_conf);
	ConfigStruct *tls=new ConfigStruct("tls","TLS specific parameters.",TLS_OID_INDEX);
	mConfigRoot.addChild(tls);
	tls->addChildrenValues(tls_conf);
}

int ConfigManager::load(const char* configfile){
	return mReader.read(configfile);
}

void ConfigManager::loadStrict(){
	mReader.reload();
	mReader.checkUnread();
}

ConfigStruct *ConfigManager::getRoot(){
	return &mConfigRoot;
}

const ConfigStruct *ConfigManager::getGlobal(){
	return mConfigRoot.get<ConfigStruct>("global");
}

std::ostream &FileConfigDumper::dump(std::ostream & ostr)const {
	return dump2(ostr,mRoot,0);
}

std::ostream & FileConfigDumper::printHelp(std::ostream &os, const std::string &help, const std::string &comment_prefix)const{
	const char *p=help.c_str();
	const char *begin=p;
	const char *origin=help.c_str();
	for(;*p!=0;++p){
		if (p-begin>60 && *p==' '){
			os<<comment_prefix<<" "<<help.substr(begin-origin,p-begin)<<endl;
			p++;
			begin=p;
		}
	}
	os<<comment_prefix<<" "<<help.substr(begin-origin,p-origin)<<endl;
	return os;
}

std::ostream &FileConfigDumper::dump2(std::ostream & ostr, ConfigEntry *entry, int level)const{
	ConfigStruct *cs=dynamic_cast<ConfigStruct*>(entry);
	ConfigValue *val;

	if (cs){
		ostr<<"##"<<endl;
		printHelp(ostr,cs->getHelp(),"##");
		ostr<<"##"<<endl;
		if (level>0){
			ostr<<"["<<cs->getName()<<"]"<<std::endl;
		}else ostr<<std::endl;
		std::list<ConfigEntry*>::iterator it;
		for(it=cs->getChildren().begin();it!=cs->getChildren().end();++it){
			dump2(ostr,*it,level+1);
			ostr<<std::endl;
		}
	}else if ((val=dynamic_cast<ConfigValue*>(entry))!=NULL){
		printHelp(ostr,entry->getHelp(),"#");
		ostr<<"#  Default value: "<<val->getDefault()<<std::endl;
		ostr<<entry->getName()<<"="<<val->getDefault()<<std::endl;
	}
	return ostr;
}

std::ostream &MibDumper::dump(std::ostream & ostr)const {
	const std::time_t t = std::time(NULL);
	char mbstr[100];
	strftime(mbstr, sizeof(mbstr), "%Y%m%d0000Z", std::localtime(&t));

	ostr << "FLEXISIP-MIB DEFINITIONS ::= BEGIN" << endl
			<< "IMPORTS" << endl
			<< "	OBJECT-TYPE, Integer32, MODULE-IDENTITY, enterprises,Counter64  	FROM SNMPv2-SMI" << endl
			<< "	MODULE-COMPLIANCE, OBJECT-GROUP       					FROM SNMPv2-CONF;" << endl
			<< endl

			<< "flexisipMIB MODULE-IDENTITY" << endl
			<< "	LAST-UPDATED \"" << mbstr <<"\"" << endl
			<< "	ORGANIZATION \"belledonne-communications\"" << endl
			<< "	CONTACT-INFO \"postal:   34 Avenue de L'europe 38 100 Grenoble France" << endl
			<< "		email:    contact@belledonne-communications.com\"" << endl
			<< "DESCRIPTION  \"A Flexisip management tree.\"" << endl
			<< "::={ enterprises "<< company_id << " }" << endl
			<< endl;

	dump2(ostr,mRoot,0);
	ostr << "END";
	return ostr;
}

std::ostream &MibDumper::dump2(std::ostream & ostr, ConfigEntry *entry, int level)const{
	ConfigStruct *cs=dynamic_cast<ConfigStruct*>(entry);
	ConfigValue *val;
	string spacing="";
	while (level > 0) {
		spacing += "	";
		--level;
	}
	if (cs){
		std::list<ConfigEntry*>::iterator it;
		cs->mibFragment(ostr, spacing);
		for(it=cs->getChildren().begin();it!=cs->getChildren().end();++it){
			dump2(ostr,*it,level+1);
			ostr<<std::endl;
		}
	}else if ((val=dynamic_cast<ConfigValue*>(entry))!=NULL){
		val->mibFragment(ostr, spacing);
	}
	return ostr;
}

int FileConfigReader::read(const char *filename){
	int err;
	mCfg=lp_config_new(NULL);
	err=lp_config_read_file(mCfg,filename);
	read2(mRoot,0);
	return err;
}

int FileConfigReader::reload(){
	read2(mRoot,0);
	return 0;
}

void FileConfigReader::onUnreadItem(void *p, const char *secname, const char *key, int lineno){
	FileConfigReader *zis=(FileConfigReader*)p;
	zis->onUnreadItem(secname,key,lineno);
}

void FileConfigReader::onUnreadItem(const char *secname, const char *key, int lineno){
	LOGE("Unsupported parameter '%s' in section [%s] at line %i", key, secname, lineno);
	mHaveUnreads=true;
	ConfigEntry *sec=mRoot->find(secname);
	if (sec==NULL){
		sec=mRoot->findApproximate(secname);
		if (sec!=NULL){
			LOGE("Did you meant '[%s]' ?",sec->getName().c_str());
		}
		return;
	}
	ConfigStruct *st=dynamic_cast<ConfigStruct*>(sec);
	if (st){
		ConfigEntry *val=st->find(key);
		if (val==NULL){
			val=st->findApproximate(key);
			if (val!=NULL){
				LOGE("Did you meant '%s' ?",val->getName().c_str());
			}
		}
	}
}

void FileConfigReader::checkUnread(){
	lp_config_for_each_unread (mCfg,onUnreadItem,this);
	if (mHaveUnreads)
		LOGE("Please fix your configuration file.");
}

int FileConfigReader::read2(ConfigEntry *entry, int level){
	ConfigStruct *cs=dynamic_cast<ConfigStruct*>(entry);
	ConfigValue *cv;
	if (cs){
		list<ConfigEntry*> & entries=cs->getChildren();
		list<ConfigEntry*>::iterator it;
		for(it=entries.begin();it!=entries.end();++it){
			read2(*it,level+1);
		}
	}else if ((cv=dynamic_cast<ConfigValue*>(entry))){
		if (level<2){
			LOGF("ConfigValues at root is disallowed.");
		}else if (level==2){
			const char *val=lp_config_get_string(mCfg,cv->getParent()->getName().c_str(),cv->getName().c_str(),cv->getDefault().c_str());
			cv->set(val);
		}else{
			LOGF("The current file format doesn't support recursive subsections.");
		}
	}
	return 0;
}

FileConfigReader::~FileConfigReader(){
	if (mCfg) lp_config_destroy(mCfg);
}



#ifdef ENABLE_SNMP
int ConfigValue::sHandleSnmpRequest(netsnmp_mib_handler *handler,
		netsnmp_handler_registration *reginfo,
		netsnmp_agent_request_info   *reqinfo,
		netsnmp_request_info         *requests)
{
	if (!reginfo->my_reg_void) {
		LOGE("no reg");
		return SNMP_ERR_GENERR;
	}
	else {
		LOGE("got something for %s", reginfo->handlerName);
		ConfigValue *cv=static_cast<ConfigValue*>(reginfo->my_reg_void);
		return cv->handleSnmpRequest(handler, reginfo, reqinfo, requests);
	}
}

int ConfigValue::handleSnmpRequest(netsnmp_mib_handler *handler,
		netsnmp_handler_registration *reginfo,
		netsnmp_agent_request_info   *reqinfo,
		netsnmp_request_info         *requests)
{
	LOGE("str handleSnmpRequest %s -> %s", reginfo->handlerName, get().c_str());

	switch(reqinfo->mode) {
	case MODE_GET:
		return snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
				(const u_char*) get().c_str(), get().size());
		break;

	default:
		/* we should never get here, so this is a really bad error */
		snmp_log(LOG_ERR, "unknown mode (%d) in handle_bindAddress\n", reqinfo->mode );
		return SNMP_ERR_GENERR;
	}

	return SNMP_ERR_NOERROR;
}


int ConfigBoolean::handleSnmpRequest(netsnmp_mib_handler *handler,
		netsnmp_handler_registration *reginfo,
		netsnmp_agent_request_info   *reqinfo,
		netsnmp_request_info         *requests)
{
	LOGE("bool handleSnmpRequest %s -> %d", reginfo->handlerName, read()?1:0);

	switch(reqinfo->mode) {
	case MODE_GET:
		snmp_set_var_typed_integer(requests->requestvb, ASN_INTEGER, read()?1:0);
		break;
	default:
		/* we should never get here, so this is a really bad error */
		snmp_log(LOG_ERR, "unknown mode (%d)\n", reqinfo->mode );
		return SNMP_ERR_GENERR;
	}

	return SNMP_ERR_NOERROR;
}

int ConfigInt::handleSnmpRequest(netsnmp_mib_handler *handler,
		netsnmp_handler_registration *reginfo,
		netsnmp_agent_request_info   *reqinfo,
		netsnmp_request_info         *requests)
{
	LOGE("hint andleSnmpRequest %s -> %d", reginfo->handlerName, read());

	switch(reqinfo->mode) {
	case MODE_GET:
		snmp_set_var_typed_integer(requests->requestvb, ASN_INTEGER, read());
		break;
	default:
		/* we should never get here, so this is a really bad error */
		snmp_log(LOG_ERR, "unknown mode (%d)\n", reqinfo->mode );
		return SNMP_ERR_GENERR;
	}

	return SNMP_ERR_NOERROR;
}
#endif
