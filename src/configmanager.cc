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

#include <sofia-sip/su_md5.h>

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

string GenericEntry::sanitize(const string &str){
	string strnew=str;
	camelFindAndReplace("::", strnew);
	camelFindAndReplace("-", strnew);
	return strnew;
}

void GenericEntry::mibFragment(ostream & ost, string spacing) const{
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
void StatCounter64::mibFragment(ostream & ost, string spacing) const{
	string s("Counter64");
	doMibFragment(ost, s, spacing);
}
void ConfigString::mibFragment(ostream & ost, string spacing) const{
	ConfigValue::mibFragment(ost, spacing);
}
void ConfigStringList::mibFragment(ostream & ost, string spacing) const{
	ConfigValue::mibFragment(ost, spacing);
}
void GenericStruct::mibFragment(ostream & ost, string spacing) const{
	string parent = getParent() ? getParent()->getName() : "flexisipMIB";
	ost << spacing << sanitize(getName()) << "	"
			<< "OBJECT IDENTIFIER ::= { "
			<< sanitize(parent) << " "
			<< mOid->getLeaf() << " }" << endl;
}



void GenericEntry::doMibFragment(ostream & ostr, string &syntax, string spacing) const{
	if (!getParent()) LOGA("no parent found for %s", getName().c_str());
	ostr << spacing << sanitize(getName()) << " OBJECT-TYPE" << endl
			<< spacing << "	SYNTAX" << "	" << syntax << endl
			<< spacing << "	MAX-ACCESS	read-only" << endl
			<< spacing << "	STATUS	current" << endl
			<< spacing << "	DESCRIPTION" << endl
			<< spacing << "	\"" << getHelp() << "\"" << endl
			<< spacing << "	::= { " << sanitize(getParent()->getName()) << " " << mOid->getLeaf() << " }" << endl;
}

ConfigValue::ConfigValue(const std::string &name, GenericValueType  vt, const std::string &help, const std::string &default_value,oid oid_index)
:  GenericEntry (name,vt,help,oid_index), mDefaultValue(default_value){

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

oid Oid::oidFromHashedString(const string &str) {
	  su_md5_t md5[1];
	  su_md5_init(md5);
	  su_md5_update(md5, str.c_str(), str.size());
	  uint8_t  digest[SU_MD5_DIGEST_SIZE];
	  su_md5_digest(md5, digest);
	  oid oidValue=0;
	  for (int i=0; i < 4; ++i) { // limit to half 32 bits [1]
		  oidValue <<= 8;
		  oidValue += digest[i];
	  }
	  return oidValue /2; // takes only half the 32 bit size [1]
	  // 1: snmpwalk cannot associate oid to name otherwise
}

GenericEntry::GenericEntry(const std::string &name, GenericValueType type, const std::string &help,oid oid_index) :
				mOid(0),mName(name),mHelp(help),mType(type),mParent(0),mOidLeaf(oid_index){
	if (strchr(name.c_str(),'_'))
		LOGA("Underscores not allowed in config items, please use minus sign.");
	if (oid_index == 0) {
		mOidLeaf = Oid::oidFromHashedString(name);
	}
}


void GenericEntry::setParent(GenericEntry *parent){
	mParent=parent;
	if (mOid) delete mOid;
	mOid = new Oid(parent->getOid(),mOidLeaf);

	string key=parent->getName() + "::" + mName;
	registerWithKey(key);
}

void ConfigValue::setParent(GenericEntry *parent){
	GenericEntry::setParent(parent);
#ifdef ENABLE_SNMP
	LOGD("SNMP registering %s %s (as %s)",mOid->getValueAsString().c_str(), mName.c_str(), sanitize(mName).c_str());
	netsnmp_handler_registration *reginfo=netsnmp_create_handler_registration(
			sanitize(mName).c_str(), &GenericEntry::sHandleSnmpRequest,
			(oid *) mOid->getValue().data(), mOid->getValue().size(),
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

void StatCounter64::setParent(GenericEntry *parent){
	GenericEntry::setParent(parent);

#ifdef ENABLE_SNMP
	LOGD("SNMP registering %s %s (as %s)",mOid->getValueAsString().c_str(), mName.c_str(), sanitize(mName).c_str());
	netsnmp_handler_registration *reginfo=netsnmp_create_handler_registration(
			sanitize(mName).c_str(), &GenericEntry::sHandleSnmpRequest,
			(oid *) mOid->getValue().data(), mOid->getValue().size(),
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

GenericStruct::GenericStruct(const std::string &name, const std::string &help,oid oid_index) : GenericEntry(name,Struct,help,oid_index){
}

void GenericStruct::setParent(GenericEntry *parent){
	GenericEntry::setParent(parent);
#ifdef ENABLE_SNMP
	LOGD("SNMP node %s %s",mOid->getValueAsString().c_str(), mName.c_str());
#endif
}

GenericEntry * GenericStruct::addChild(GenericEntry *c){
	mEntries.push_back(c);
	c->setParent(this);
	return c;
}


void GenericStruct::addChildrenValues(ConfigItemDescriptor *items){
	for (;items->name!=NULL;items++){
		ConfigValue *val=NULL;
		oid cOid=Oid::oidFromHashedString(items->name);
		switch(items->type){
		case Boolean:
			val=new ConfigBoolean(items->name,items->help,items->default_value,cOid);
			break;
		case Integer:
			val=new ConfigInt(items->name,items->help,items->default_value,cOid);
			break;
		case String:
			val=new ConfigString(items->name,items->help,items->default_value,cOid);
			break;
		case StringList:
			val=new ConfigStringList(items->name,items->help,items->default_value,cOid);
			break;
		default:
			LOGA("Bad ConfigValue type %u for %s!", items->type, items->name);
			break;
		}
		addChild(val);
	}
}


void GenericStruct::addChildrenValues(StatItemDescriptor *items){
	for (;items->name!=NULL;items++){
		GenericEntry *val=NULL;
		oid cOid=Oid::oidFromHashedString(items->name);
		switch(items->type){
		case Counter64:
			LOGD("StatItemDescriptor: %s %lu", items->name, cOid);
			val=new StatCounter64(items->name,items->help,cOid);
			break;
		default:
			LOGA("Bad ConfigValue type %u for %s!", items->type, items->name);
			break;
		}
		addChild(val);
	}
}

struct matchEntryName{
	matchEntryName(const char *name) : mName(name){};
	bool operator()(GenericEntry* e){
		return strcmp(mName,e->getName().c_str())==0;
	}
	const char *mName;
};

GenericEntry *GenericStruct::find(const char *name)const{
	std::list<GenericEntry*>::const_iterator it=find_if(mEntries.begin(),mEntries.end(),matchEntryName(name));
	if (it!=mEntries.end()) return *it;
	return NULL;
}

struct matchEntryNameApprox{
	matchEntryNameApprox(const char *name) : mName(name){};
	bool operator()(GenericEntry* e){
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

GenericEntry * GenericStruct::findApproximate(const char *name)const{
	std::list<GenericEntry*>::const_iterator it=find_if(mEntries.begin(),mEntries.end(),matchEntryNameApprox(name));
	if (it!=mEntries.end()) return *it;
	return NULL;
}

std::list<GenericEntry*> &GenericStruct::getChildren(){
	return mEntries;
}

struct destroy{
	void operator()(GenericEntry *e){
		delete e;
	}
};

GenericStruct::~GenericStruct(){
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

StatCounter64::StatCounter64(const std::string &name, const std::string &help, oid oid_index)
:	GenericEntry(name,Counter64,help,oid_index){
	mValue=0;
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


GenericManager *GenericManager::sInstance=0;

static void init_flexisip_snmp() {
#ifdef ENABLE_SNMP
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
		LOGA("error init snmp agent %d", errno);
	}
#endif
}

void GenericManager::atexit() {
	if (sInstance!=NULL) {
		delete sInstance;
		sInstance = NULL;
	}
}

GenericManager *GenericManager::get(){
	if (sInstance==NULL) {
		init_flexisip_snmp();
		sInstance=new GenericManager();
		::atexit(GenericManager::atexit);
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

static StatItemDescriptor global_stat[]={
		{	Counter64	,	"count-snmp-request"		,	"Count number of received snmp requests"},
		{	Counter64	,	"count-snmp-request-error"		,	"Count number of received snmp requests which are errors"},
		stat_item_end
};

static ConfigItemDescriptor tls_conf[]={
		{	Boolean	,	"enabled"	,	"Enable SIP/TLS (sips)",	"true"	},
		{	Integer	,	"port",	"The port used for SIP/TLS",	"5061"},
		{	String	,	"certificates-dir", "An absolute path of a directory where TLS certificate can be found. "
				"The private key for TLS server must be in a agent.pem file within this directory" , "/etc/flexisip/tls"	},
		config_item_end
};


RootConfigStruct::RootConfigStruct(const std::string &name, const std::string &help,vector<oid> oid_root_path)
: GenericStruct(name,help,1) {
	mOid = new Oid(oid_root_path,1);
}
static oid company_id = SNMP_COMPANY_OID;
GenericManager::GenericManager() : mConfigRoot("flexisip","This is the default Flexisip configuration file",{1,3,6,1,4,1,company_id}), mReader(&mConfigRoot){
	GenericStruct *global=new GenericStruct("global","Some global settings of the flexisip proxy.",0);
	mConfigRoot.addChild(global);
	global->addChildrenValues(global_conf);
	global->addChildrenValues(global_stat);
	GenericStruct *tls=new GenericStruct("tls","TLS specific parameters.",0);
	mConfigRoot.addChild(tls);
	tls->addChildrenValues(tls_conf);
}

int GenericManager::load(const char* configfile){
	return mReader.read(configfile);
}

void GenericManager::loadStrict(){
	mReader.reload();
	mReader.checkUnread();
}

GenericStruct *GenericManager::getRoot(){
	return &mConfigRoot;
}

const GenericStruct *GenericManager::getGlobal(){
	return mConfigRoot.get<GenericStruct>("global");
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

std::ostream &FileConfigDumper::dump2(std::ostream & ostr, GenericEntry *entry, int level)const{
	GenericStruct *cs=dynamic_cast<GenericStruct*>(entry);
	ConfigValue *val;

	if (cs){
		ostr<<"##"<<endl;
		printHelp(ostr,cs->getHelp(),"##");
		ostr<<"##"<<endl;
		if (level>0){
			ostr<<"["<<cs->getName()<<"]"<<std::endl;
		}else ostr<<std::endl;
		std::list<GenericEntry*>::iterator it;
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

std::ostream &MibDumper::dump2(std::ostream & ostr, GenericEntry *entry, int level)const{
	GenericStruct *cs=dynamic_cast<GenericStruct*>(entry);
	ConfigValue *cVal;
	StatCounter64 *sVal;
	string spacing="";
	while (level > 0) {
		spacing += "	";
		--level;
	}
	if (cs){
		std::list<GenericEntry*>::iterator it;
		cs->mibFragment(ostr, spacing);
		for(it=cs->getChildren().begin();it!=cs->getChildren().end();++it){
			dump2(ostr,*it,level+1);
			ostr<<std::endl;
		}
	}else if ((cVal=dynamic_cast<ConfigValue*>(entry))!=NULL){
		cVal->mibFragment(ostr, spacing);
	}else if ((sVal=dynamic_cast<StatCounter64*>(entry))!=NULL){
		sVal->mibFragment(ostr, spacing);
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
	GenericEntry *sec=mRoot->find(secname);
	if (sec==NULL){
		sec=mRoot->findApproximate(secname);
		if (sec!=NULL){
			LOGE("Did you meant '[%s]' ?",sec->getName().c_str());
		}
		return;
	}
	GenericStruct *st=dynamic_cast<GenericStruct*>(sec);
	if (st){
		GenericEntry *val=st->find(key);
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
		LOGF("Please fix your configuration file.");
}

int FileConfigReader::read2(GenericEntry *entry, int level){
	GenericStruct *cs=dynamic_cast<GenericStruct*>(entry);
	ConfigValue *cv;
	if (cs){
		list<GenericEntry*> & entries=cs->getChildren();
		list<GenericEntry*>::iterator it;
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


GenericEntriesGetter *GenericEntriesGetter::sInstance=NULL;

#ifdef ENABLE_SNMP
int GenericEntry::sHandleSnmpRequest(netsnmp_mib_handler *handler,
		netsnmp_handler_registration *reginfo,
		netsnmp_agent_request_info   *reqinfo,
		netsnmp_request_info         *requests)
{
	++StatCounter64::find("global::count-snmp-request");
	if (!reginfo->my_reg_void) {
		LOGE("no reg");
		++StatCounter64::find("global::count-snmp-request-error");
		return SNMP_ERR_GENERR;
	}
	else {
		GenericEntry *cv=static_cast<GenericEntry*>(reginfo->my_reg_void);
		return cv->handleSnmpRequest(handler, reginfo, reqinfo, requests);
	}
}

int ConfigValue::handleSnmpRequest(netsnmp_mib_handler *handler,
		netsnmp_handler_registration *reginfo,
		netsnmp_agent_request_info   *reqinfo,
		netsnmp_request_info         *requests)
{
	LOGD("str handleSnmpRequest %s -> %s", reginfo->handlerName, get().c_str());

	switch(reqinfo->mode) {
	case MODE_GET:
		return snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
				(const u_char*) get().c_str(), get().size());
		break;

	default:
		/* we should never get here, so this is a really bad error */
		snmp_log(LOG_ERR, "unknown mode (%d) in handleSnmpRequest\n", reqinfo->mode );
		return SNMP_ERR_GENERR;
	}

	return SNMP_ERR_NOERROR;
}


int ConfigBoolean::handleSnmpRequest(netsnmp_mib_handler *handler,
		netsnmp_handler_registration *reginfo,
		netsnmp_agent_request_info   *reqinfo,
		netsnmp_request_info         *requests)
{
	LOGD("bool handleSnmpRequest %s -> %d", reginfo->handlerName, read()?1:0);

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
	LOGD("int handleSnmpRequest %s -> %d", reginfo->handlerName, read());

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
int StatCounter64::handleSnmpRequest(netsnmp_mib_handler *handler,
		netsnmp_handler_registration *reginfo,
		netsnmp_agent_request_info   *reqinfo,
		netsnmp_request_info         *requests)
{
	LOGD("counter64 handleSnmpRequest %s -> %lu", reginfo->handlerName, read());

	switch(reqinfo->mode) {
	case MODE_GET:
		struct counter64 counter;
		counter.high=read()>>32;
		counter.low=read()&0x00000000FFFFFFFF;
		snmp_set_var_typed_value(requests->requestvb, ASN_COUNTER64, (const u_char*)&counter, sizeof(counter));
		break;
	default:
		/* we should never get here, so this is a really bad error */
		snmp_log(LOG_ERR, "unknown mode (%d)\n", reqinfo->mode );
		return SNMP_ERR_GENERR;
	}

	return SNMP_ERR_NOERROR;
}
#endif
