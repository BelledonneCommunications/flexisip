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
#include <fstream>

#include <sofia-sip/su_md5.h>

using namespace::std;

bool ConfigValueListener::sDirty=false;
bool ConfigValueListener::onConfigStateChanged(const ConfigValue &conf, ConfigState state) {
	switch (state) {
	case ConfigState::Commited:
		if (sDirty) {
			// Write to disk
			GenericStruct *rootStruct=GenericManager::get()->getRoot();
			ofstream cfgfile;
			cfgfile.open(GenericManager::get()->getConfigFile());
			FileConfigDumper dumper(rootStruct);
			dumper.setDumpDefaultValues(false);
			cfgfile << dumper;
			cfgfile.close();
			LOGI("New configuration wrote to %s .", GenericManager::get()->getConfigFile().c_str());
			sDirty=false;
		}
		break;
	case ConfigState::Changed:
		sDirty=true;
		break;
	case ConfigState::Reset:
		sDirty=false;
		break;
	default:
		break;
	}
	return doOnConfigStateChanged(conf, state);
}

static void camelFindAndReplace(string &haystack, const string &needle) {
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
	camelFindAndReplace(strnew, "::");
	camelFindAndReplace(strnew, "-");
	return strnew;
}

string GenericEntry::getPrettyName()const{
	string pn(mName);
	char upper=char(toupper(::toupper(pn.at(0))));
	pn.erase(0, 1);
	pn.insert(0, 1, upper);
	size_t i=pn.find_first_of("::");
	if (string::npos != i) {
		pn.replace(i, 1, " ");
		pn.erase(i+1, 1);
	}

	i=0;
	while(string::npos != (i=pn.find_first_of('-', i))) {
		pn.replace(i, 1, " ");
	}
	return pn;
}

void GenericEntry::mibFragment(ostream & ost, string spacing) const{
	string s("OCTET STRING");
	doMibFragment(ost, "", "read-write", s, spacing);
}

void ConfigValue::mibFragment(ostream & ost, string spacing) const{
	string s("OCTET STRING");
	doMibFragment(ost, s, spacing);
}

void ConfigValue::doMibFragment(ostream &ostr, const string &syntax, const string &spacing) const {
	string access(mNotifPayload?"accessible-for-notify":mReadOnly ? "read-only":"read-write");
	GenericEntry::doMibFragment(ostr,getDefault(),access,syntax,spacing);
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
	doMibFragment(ost, "", "read-only", s, spacing);
}
void GenericStruct::mibFragment(ostream & ost, string spacing) const{
	string parent = getParent() ? getParent()->getName() : "flexisipMIB";
	ost << spacing << sanitize(getName()) << "	"
			<< "OBJECT IDENTIFIER ::= { "
			<< sanitize(parent) << " "
			<< mOid->getLeaf() << " }" << endl;
}

void NotificationEntry::mibFragment(ostream & ost, string spacing) const{
	if (!getParent()) LOGA("no parent found for %s", getName().c_str());
	ost << spacing << sanitize(getName()) << " NOTIFICATION-TYPE" << endl
			<< spacing << "	OBJECTS	{	flNotifString	} "<< endl
			<< spacing << "	STATUS	current" << endl
			<< spacing << "	DESCRIPTION" << endl
			<< spacing << "	\"" << getHelp() << endl
			<< spacing << "	" << " PN:" << getPrettyName() << "\"" << endl
			<< spacing << "	::= { " << sanitize(getParent()->getName()) << " " << mOid->getLeaf() << " }" << endl;
}

NotificationEntry::NotificationEntry(const std::string &name, const std::string &help, oid oid_index):
		GenericEntry(name,Notification,help,oid_index), mInitialized(false){
}

void NotificationEntry::setInitialized(bool status) {
	mInitialized=status;
	if (status) {
		const GenericEntry *source;
		string msg;
		if (!mPendingTraps.empty()) {
			LOGD("Sending %zd pending notifications", mPendingTraps.size());
		}
		while(!mPendingTraps.empty()) {
			tie(source,msg)=mPendingTraps.front();
			mPendingTraps.pop();
			send(source,msg);
		}
	}
}

void NotificationEntry::send(const string &msg){
	send(NULL,msg);
}
void NotificationEntry::send(const GenericEntry *source, const string &msg){
	LOGD("Sending trap %s: %s", source? source->getName().c_str():"", msg.c_str());

#ifdef ENABLE_SNMP
	if (!mInitialized) {
		mPendingTraps.push(make_tuple(source,msg));
		LOGD("Pending trap: SNMP not initialized");
		return;
	}

	static Oid &sMsgTemplateOid=GenericManager::get()->getRoot()
			->getDeep<GenericEntry>("notif/msg", true)->getOid();
	static Oid &sSourceTemplateOid=GenericManager::get()->getRoot()
			->getDeep<GenericEntry>("notif/source", true)->getOid();

	/*
	 * See:
	 * http://net-snmp.sourceforge.net/dev/agent/notification_8c-example.html
	 * In the notification, we have to assign our notification OID to
	 * the snmpTrapOID.0 object. Here is it's definition.
	 */
	oid objid_snmptrap[] = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };
	size_t objid_snmptrap_len = OID_LENGTH(objid_snmptrap);

	netsnmp_variable_list *notification_vars = NULL;

	snmp_varlist_add_variable(&notification_vars,
			objid_snmptrap, objid_snmptrap_len,
			ASN_OBJECT_ID,
			(u_char *) mOid->mOidPath.data(),
			mOid->mOidPath.size() * sizeof(oid));

	snmp_varlist_add_variable(&notification_vars,
			(const oid*)sMsgTemplateOid.getValue().data(),
			sMsgTemplateOid.getValue().size(),
			ASN_OCTET_STR,
			(u_char *)msg.data(),msg.length());

	if (source) {
		string oidstr(source->getOidAsString());
		snmp_varlist_add_variable(&notification_vars,
				(const oid*)sSourceTemplateOid.getValue().data(),
				sSourceTemplateOid.getValue().size(),
				ASN_OCTET_STR,
				(u_char *)oidstr.data(),oidstr.length());
	}

	send_v2trap(notification_vars);
	snmp_free_varbind(notification_vars);
#endif
}

void GenericEntry::doMibFragment(ostream & ostr, const string &def, const string &access, const string &syntax, const string &spacing) const{
	if (!getParent()) LOGA("no parent found for %s", getName().c_str());
	ostr << spacing << sanitize(getName()) << " OBJECT-TYPE" << endl
			<< spacing << "	SYNTAX" << "	" << syntax << endl
			<< spacing << "	MAX-ACCESS	" << access << endl
			<< spacing << "	STATUS	current" << endl
			<< spacing << "	DESCRIPTION" << endl
			<< spacing << "	\"" << getHelp() << endl
			<< spacing << "	"<< " Default:" << def << endl
			<< spacing << "	" << " PN:" << getPrettyName() << "\"" << endl
			<< spacing << "	::= { " << sanitize(getParent()->getName()) << " " << mOid->getLeaf() << " }" << endl;
}

ConfigValue::ConfigValue(const string &name, GenericValueType  vt, const string &help, const string &default_value,oid oid_index)
:  GenericEntry (name,vt,help,oid_index), mDefaultValue(default_value){
	mExportToConfigFile=true;
}

void ConfigValue::set(const string  &value){
	if (getType()==Boolean){
		if (value!="true" && value!="false" && value!="1" && value!="0"){
			LOGF("Not a boolean: \"%s\" for key \"%s\" ", value.c_str(), getName().c_str());
		}
	}
	mValue=value;
}

void ConfigValue::setNextValue(const string  &value){
	if (getType()==Boolean){
		if (value!="true" && value!="false" && value!="1" && value!="0"){
			LOGF("Not a boolean: \"%s\" for key \"%s\" ", value.c_str(), getName().c_str());
		}
	}
	mNextValue=value;
}

void ConfigValue::setDefault(const string & value){
	if (getType()==Boolean){
		if (value!="true" && value!="false" && value!="1" && value!="0"){
			LOGF("Not a boolean: \"%s\" for key \"%s\" ", value.c_str(), getName().c_str());
		}
	}
	mDefaultValue=value;
}

const string & ConfigValue::get()const{
	return mValue;
}

const string & ConfigValue::getDefault()const{
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

GenericEntry::GenericEntry(const string &name, GenericValueType type, const string &help,oid oid_index) :
				mOid(0),mName(name),mReadOnly(false),mExportToConfigFile(true),mHelp(help),mType(type),mParent(0),mOidLeaf(oid_index){
	mConfigListener=NULL;
	size_t idx;
	for(idx=0;idx<name.size();idx++){
		if (name[idx]=='_')
			LOGA("Underscores not allowed in config items, please use minus sign (while checking generic entry name '%s').",name.c_str());
		if (type!= Struct && isupper(name[idx])){
			LOGA("Uppercase characters not allowed in config items, please use lowercase characters only (while checking generic entry name '%s').",name.c_str());
		}
	}
		
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
//	LOGD("SNMP registering %s %s (as %s)",mOid->getValueAsString().c_str(), mName.c_str(), sanitize(mName).c_str());
	netsnmp_handler_registration *reginfo=netsnmp_create_handler_registration(
			sanitize(mName).c_str(), &GenericEntry::sHandleSnmpRequest,
			(oid *) mOid->getValue().data(), mOid->getValue().size(),
			HANDLER_CAN_RWRITE);
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
//	LOGD("SNMP registering %s %s (as %s)",mOid->getValueAsString().c_str(), mName.c_str(), sanitize(mName).c_str());
	netsnmp_handler_registration *reginfo=netsnmp_create_handler_registration(
			sanitize(mName).c_str(), &GenericEntry::sHandleSnmpRequest,
			(oid *) mOid->getValue().data(), mOid->getValue().size(),
			HANDLER_CAN_RONLY);
	reginfo->my_reg_void=this;
	int res=netsnmp_register_read_only_scalar(reginfo);
	if (res != MIB_REGISTERED_OK) {
		if (res == MIB_DUPLICATE_REGISTRATION) {
			LOGE("Duplicate registration of SNMP %s", mName.c_str());
		} else {
			LOGE("Couldn't register SNMP %s", mName.c_str());
		}
	}
#endif
}

GenericStruct::GenericStruct(const string &name, const string &help,oid oid_index) : GenericEntry(name,Struct,help,oid_index){
}

void GenericStruct::setParent(GenericEntry *parent){
	GenericEntry::setParent(parent);
#ifdef ENABLE_SNMP
//	LOGD("SNMP node %s %s",mOid->getValueAsString().c_str(), mName.c_str());
#endif
}

GenericEntry * GenericStruct::addChild(GenericEntry *c){
	mEntries.push_back(c);
	c->setParent(this);
	return c;
}

void GenericStruct::deprecateChild(const char *name){
	GenericEntry *e=find(name);
	if (e) e->setDeprecated(true);
}

void GenericStruct::addChildrenValues(ConfigItemDescriptor *items){
	addChildrenValues(items,true);
}
void GenericStruct::addChildrenValues(ConfigItemDescriptor *items, bool hashed){
	oid cOid=1;
	for (;items->name!=NULL;items++){
		ConfigValue *val=NULL;
		if (hashed) cOid=Oid::oidFromHashedString(items->name);
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
		if (!hashed) ++cOid;
	}
}

StatCounter64 *GenericStruct::createStat(const string &name, const string &help){
	oid cOid=Oid::oidFromHashedString(name);
	StatCounter64 *val=new StatCounter64(name,help,cOid);
	addChild(val);
	return val;
}
pair<StatCounter64 *, StatCounter64*> GenericStruct::createStatPair(const string &name, const string &help){
	return make_pair(createStat(name, help), createStat(name+"-finished", help + " Finished."));
}
/*
void GenericStruct::addChildrenValues(StatItemDescriptor *items){
	for (;items->name!=NULL;items++){
		GenericEntry *val=NULL;
		oid cOid=Oid::oidFromHashedString(items->name);
		switch(items->type){
		case Counter64:
			//LOGD("StatItemDescriptor: %s %lu", items->name, cOid);
			val=new StatCounter64(items->name,items->help,cOid);
			break;
		default:
			LOGA("Bad ConfigValue type %u for %s!", items->type, items->name);
			break;
		}
		addChild(val);
	}
}
*/
struct matchEntryName{
	matchEntryName(const char *name) : mName(name){};
	bool operator()(GenericEntry* e){
		return strcmp(mName,e->getName().c_str())==0;
	}
	const char *mName;
};

GenericEntry *GenericStruct::find(const char *name)const{
	list<GenericEntry*>::const_iterator it=find_if(mEntries.begin(),mEntries.end(),matchEntryName(name));
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
			if (e->getName().find(mName[i])!=string::npos){
				count++;
			}
		}
		if (count>=min_required){
			return true;
		}
		return false;
	}
	const string mName;
};

GenericEntry * GenericStruct::findApproximate(const char *name)const{
	list<GenericEntry*>::const_iterator it=find_if(mEntries.begin(),mEntries.end(),matchEntryNameApprox(name));
	if (it!=mEntries.end()) return *it;
	return NULL;
}

list<GenericEntry*> &GenericStruct::getChildren(){
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


ConfigBoolean::ConfigBoolean(const string &name, const string &help, const string &default_value,oid oid_index)
: ConfigValue(name, Boolean, help, default_value,oid_index){
}


bool ConfigBoolean::read()const{
	if (get()=="true" || get()=="1") return true;
	else if (get()=="false" || get()=="0") return false;
	LOGA("Bad boolean value %s",get().c_str());
	return false;
}
bool ConfigBoolean::readNext()const{
	if (getNextValue()=="true" || getNextValue()=="1") return true;
	else if (getNextValue()=="false" || getNextValue()=="0") return false;
	LOGA("Bad boolean value %s",getNextValue().c_str());
	return false;
}

void ConfigBoolean::write(bool value){
	set(value?"1":"0");
}


ConfigInt::ConfigInt(const string &name, const string &help, const string &default_value,oid oid_index)
:	ConfigValue(name,Integer,help,default_value,oid_index){
}

int ConfigInt::read()const{
	return atoi(get().c_str());
}
int ConfigInt::readNext()const{
	return atoi(getNextValue().c_str());
}
void ConfigInt::write(int value){
	std::ostringstream oss;
	oss << value;
	set(oss.str());
}

StatCounter64::StatCounter64(const string &name, const string &help, oid oid_index)
:	GenericEntry(name,Counter64,help,oid_index){
	mValue=0;
}

ConfigString::ConfigString(const string &name, const string &help, const string &default_value,oid oid_index)
:	ConfigValue(name,String,help,default_value,oid_index){
}

ConfigRuntimeError::ConfigRuntimeError(const string &name, const string &help,oid oid_index)
:	ConfigValue(name,RuntimeError,help,"",oid_index){
	this->setReadOnly(true);
	this->mExportToConfigFile=false;
}

const string & ConfigString::read()const{
	return get();
}

const void ConfigRuntimeError::writeErrors(GenericEntry *entry, ostringstream &oss) const{
	GenericStruct *cs=dynamic_cast<GenericStruct*>(entry);
	if (cs) {
		const auto &children=cs->getChildren();
		for (auto it=children.begin(); it != children.end(); ++it) {
			writeErrors(*it, oss);
		}
	}

	if (!entry->getErrorMessage().empty()) {
		if (oss.tellp() > 0) oss << "|";
		oss << entry->getOidAsString() << ":" << entry->getErrorMessage();
	}
}

string ConfigRuntimeError::generateErrors()const{
	ostringstream oss;
	writeErrors(GenericManager::get()->getRoot(), oss);
	return oss.str();
}



ConfigStringList::ConfigStringList(const string &name, const string &help, const string &default_value,oid oid_index)
:	ConfigValue(name,StringList,help,default_value,oid_index){
}

#define DELIMITERS " \n,"

list<string> ConfigStringList::parse(const char *input){
	list<string> retlist;
	char *res=strdup(input);
	char *saveptr=NULL;
	char *ret=strtok_r(res,DELIMITERS,&saveptr);
	while(ret!=NULL){
		retlist.push_back(string(ret));
		ret=strtok_r(NULL,DELIMITERS,&saveptr);
	}
	free(res);
	return retlist;
}

list<string>  ConfigStringList::read()const{
	return parse(get().c_str());
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
		{	Boolean	,	"debug"	        ,	"Outputs very detailed logs",	"false"	},
		{	Boolean	,	"dump-corefiles",	"Generate a corefile when crashing", "true"},
		{	Boolean	,	"auto-respawn"  ,	"Automatically respawn flexisip in case of abnormal termination (crashes)",	"true"},
		{	StringList	,"aliases"	,	"List of white space separated host names pointing to this machine. This is to prevent loops while routing SIP messages.", "localhost"},
		{	StringList	,"transports"	,	"List of white space separated SIP uris where the proxy must listen."
								"Wildcard (*) can be used to mean 'all local ip addresses'. If 'transport' prameter is unspecified, it will listen "
								"to both udp and tcp. An local address to bind can be indicated in the 'maddr' parameter, while the domain part of the uris "
								"are used as public domain or ip address. Here some examples to understand:\n"
								"* listen on all local interfaces for udp and tcp, on standart port:\n"
								"\ttransports=sip:*\n"
								"* listen on all local interfaces for udp,tcp and tls, on standart ports:\n"
								"\ttransports=sip:* sips:*\n" 
								"* listen on 192.168.0.29:6060 with tls, but public hostname is 'sip.linphone.org' used in SIP messages. Bind address won't appear:\n"
								"\ttransports=sips:sip.linphone.org:6060;maddr=192.168.0.29"
		,	"sip:*" },
		{	String		,"tls-certificates-dir", "An absolute path of a directory where TLS server certificate and private key can be found, concatenated inside an 'agent.pem' file. Any chain certificates must be put into a file named 'cafile.pem'.", "/etc/flexisip/tls"},
		{	Integer		,"idle-timeout",	"Time interval in seconds after which inactive connections are closed.", "3600"},
		{	Boolean		,"enable-event-logs",	"Enable event logs. Event logs contain per domain and user information about processed registrations, calls and messages.", "false"},
		{	String		,"event-logs-dir",	"Directory where event logs are written.",	"/var/log/flexisip"},
		config_item_end
};


RootConfigStruct::RootConfigStruct(const string &name, const string &help,vector<oid> oid_root_path)
: GenericStruct(name,help,1) {
	mOid = new Oid(oid_root_path,1);
}
static oid company_id = SNMP_COMPANY_OID;
GenericManager::GenericManager() : mNeedRestart(false), mDirtyConfig(false),
		mConfigRoot("flexisip","This is the default Flexisip configuration file",{1,3,6,1,4,1,company_id}),
		mReader(&mConfigRoot), mNotifier(NULL){
	GenericStruct *notifObjs=new GenericStruct("notif","Templates for notifications.",1);
	notifObjs->setExportToConfigFile(false);
	mConfigRoot.addChild(notifObjs);
	mNotifier=new NotificationEntry("sender","Send notifications",1);
	notifObjs->addChild(mNotifier);
	ConfigString *nmsg=new ConfigString("msg", "Notification message payload.", "", 10);
	nmsg->setNotifPayload(true);
	notifObjs->addChild(nmsg);
	ConfigString *nsoid=new ConfigString("source", "Notification source payload.", "", 11);
	nsoid->setNotifPayload(true);
	notifObjs->addChild(nsoid);



	GenericStruct *global=new GenericStruct("global","Some global settings of the flexisip proxy.",2);
	mConfigRoot.addChild(global);
	global->addChildrenValues(global_conf);
	global->setConfigListener(this);

	ConfigString *version=new ConfigString("version-number", "Flexisip version.", PACKAGE_VERSION, 999);
	version->setReadOnly(true);
	version->setExportToConfigFile(false);
	global->addChild(version);

	ConfigValue *runtimeError=new ConfigRuntimeError("runtime-error", "Retrieve current runtime error state", 998);
	runtimeError->setExportToConfigFile(false);
	runtimeError->setReadOnly(true);
	global->addChild(runtimeError);

}

bool GenericManager::doIsValidNextConfig(const ConfigValue &cv) {
	return true;
}

bool GenericManager::doOnConfigStateChanged(const ConfigValue &conf, ConfigState state){
	switch (state) {
		case ConfigState::Check:
			return doIsValidNextConfig(conf);
			break;
		case ConfigState::Changed:
			mDirtyConfig=true;
			break;
		case ConfigState::Reset:
			mDirtyConfig=false;
			break;
		case ConfigState::Commited:
			if (mDirtyConfig) {
				LOGI("Scheduling server restart to apply new config.");
				mDirtyConfig=false;
				mNeedRestart=true;
			}
			break;
		default:
			break;
	}
	return true;
}

int GenericManager::load(const char* configfile){
	mConfigFile = configfile;
	int res=mReader.read(configfile);
	applyOverrides(&mConfigRoot, false);
	return res;
}

void GenericManager::loadStrict(){
	mReader.reload();
	mReader.checkUnread();
	applyOverrides(&mConfigRoot, true);
}

GenericStruct *GenericManager::getRoot(){
	return &mConfigRoot;
}

const GenericStruct *GenericManager::getGlobal(){
	return mConfigRoot.get<GenericStruct>("global");
}

ostream &FileConfigDumper::dump(ostream & ostr)const {
	return dump2(ostr,mRoot,0);
}

ostream & FileConfigDumper::printHelp(ostream &os, const string &help, const string &comment_prefix)const{
	const char *p=help.c_str();
	const char *begin=p;
	const char *origin=help.c_str();
	for(;*p!=0;++p){
		if ((p-begin>60 && *p==' ') || *p=='\n'){
			os<<comment_prefix<<" "<<help.substr(begin-origin,p-begin)<<endl;
			p++;
			begin=p;
		}
	}
	os<<comment_prefix<<" "<<help.substr(begin-origin,p-origin)<<endl;
	return os;
}

ostream &FileConfigDumper::dump2(ostream & ostr, GenericEntry *entry, int level)const{
	if (entry && !entry->getExportToConfigFile()) return ostr;

	GenericStruct *cs=dynamic_cast<GenericStruct*>(entry);
	ConfigValue *val;

	if (cs){
		ostr<<"##"<<endl;
		printHelp(ostr,cs->getHelp(),"##");
		ostr<<"##"<<endl;
		if (level>0){
			ostr<<"["<<cs->getName()<<"]"<<endl;
		}else ostr<<endl;
		list<GenericEntry*>::iterator it;
		for(it=cs->getChildren().begin();it!=cs->getChildren().end();++it){
			dump2(ostr,*it,level+1);
		}
	}else if ((val=dynamic_cast<ConfigValue*>(entry))!=NULL && !val->isDeprecated()){
		printHelp(ostr,entry->getHelp(),"#");
		ostr<<"#  Default value: "<<val->getDefault()<<endl;
		if (mDumpDefault) {
			ostr<<entry->getName()<<"="<<val->getDefault()<<endl;
		} else {
			ostr<<entry->getName()<<"="<<val->get()<<endl;
		}
		ostr<<endl;
	}
	return ostr;
}


ostream &TexFileConfigDumper::dump(ostream & ostr)const {
	return dump2(ostr,mRoot,0);
}



static void escaper(string &str, char c, const string &replaced) {
	size_t i=0;
	while(string::npos != (i=str.find_first_of(c, i))) {
		str.erase(i, 1);
		str.insert(i, replaced);
		i+=replaced.length();
	}
}
string TexFileConfigDumper::escape(const string &strc) const{
	std::string str(strc);
	escaper(str, '_', "\\_");
	escaper(str, '<', "\\textless{}");
	escaper(str, '>', "\\textgreater{}");

	return str;
}

ostream &TexFileConfigDumper::dump2(ostream & ostr, GenericEntry *entry, int level)const{
	GenericStruct *cs=dynamic_cast<GenericStruct*>(entry);
	ConfigValue *val;

	if (cs){
		if (cs->getParent()) {
			string pn=escape(cs->getPrettyName());
			ostr<<"\\section{"<< pn << "}" << endl << endl;
			ostr<<"\\label{" << cs->getName() << "}" << endl;
			ostr<<"\\subsection{Description}"<< endl <<endl;
			ostr<<escape(cs->getHelp())<< endl <<endl;
			ostr<<"\\subsection{Parameters}"<< endl <<endl;
		}
		list<GenericEntry*>::iterator it;
		for(it=cs->getChildren().begin();it!=cs->getChildren().end();++it){
			dump2(ostr,*it,level+1);
		}
	}else if ((val=dynamic_cast<ConfigValue*>(entry))!=NULL && !val->isDeprecated()){
		ostr<<"\\subsubsection{"<<escape(entry->getName())<<"}"<<endl;
		ostr<<escape(entry->getHelp())<<endl;
		ostr<<"The default value is ``"<<escape(val->getDefault())<<"''."<<endl;
		ostr<<endl;
	}
	return ostr;
}

ostream &MibDumper::dump(ostream & ostr)const {
	const time_t t = getCurrentTime();
	char mbstr[100];
	strftime(mbstr, sizeof(mbstr), "%Y%m%d0000Z", localtime(&t));

	ostr << "FLEXISIP-MIB DEFINITIONS ::= BEGIN" << endl
			<< "IMPORTS" << endl
			<< "	OBJECT-TYPE, Integer32, MODULE-IDENTITY, enterprises," << endl
			<< "	Counter64,NOTIFICATION-TYPE							  	FROM SNMPv2-SMI" << endl
			<< "	MODULE-COMPLIANCE, OBJECT-GROUP       					FROM SNMPv2-CONF;" << endl
			<< endl

			<< "flexisipMIB MODULE-IDENTITY" << endl
			<< "	LAST-UPDATED \"" << mbstr <<"\"" << endl
			<< "	ORGANIZATION \"belledonne-communications\"" << endl
			<< "	CONTACT-INFO \"postal:   34 Avenue de L'europe 38 100 Grenoble France" << endl
			<< "		email:    contact@belledonne-communications.com\"" << endl
			<< "	DESCRIPTION  \"A Flexisip management tree.\"" << endl
			<< "	REVISION     \"" <<mbstr <<"\""<<endl
			<< "    DESCRIPTION  \"" PACKAGE_VERSION << "\"" << endl
			<< "::={ enterprises "<< company_id << " }" << endl
			<< endl;

	dump2(ostr,mRoot,0);
	ostr << "END";
	return ostr;
}

ostream &MibDumper::dump2(ostream & ostr, GenericEntry *entry, int level)const{
	GenericStruct *cs=dynamic_cast<GenericStruct*>(entry);
	ConfigValue *cVal;
	StatCounter64 *sVal;
	NotificationEntry *ne;
	string spacing="";
	while (level > 0) {
		spacing += "	";
		--level;
	}
	if (cs){
		list<GenericEntry*>::iterator it;
		cs->mibFragment(ostr, spacing);
		for(it=cs->getChildren().begin();it!=cs->getChildren().end();++it){
			if (!cs->isDeprecated()){
				dump2(ostr,*it,level+1);
				ostr<<endl;
			}
		}
	}else if ((cVal=dynamic_cast<ConfigValue*>(entry))!=NULL){
		cVal->mibFragment(ostr, spacing);
	}else if ((sVal=dynamic_cast<StatCounter64*>(entry))!=NULL){
		sVal->mibFragment(ostr, spacing);
	}else if ((ne=dynamic_cast<NotificationEntry*>(entry))!=NULL){
		ne->mibFragment(ostr,spacing);
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

static bool checkTranscoder(const std::map<std::string,std::string> &override) {
#ifdef ENABLE_TRANSCODER
	if (override.find("notrans") != override.end()) {
		return true;
	}
#else
	return true;
#endif
	return false;
}
void FileConfigReader::onUnreadItem(const char *secname, const char *key, int lineno){
	static bool dontCheckTranscoder=checkTranscoder(GenericManager::get()->getOverrideMap());
	if (dontCheckTranscoder && 0==strcmp(secname,"module::Transcoder")) return;
	LOGE("Unsupported parameter '%s' in section [%s] at line %i", key, secname, lineno);
	mHaveUnreads=true;
	GenericEntry *sec=mRoot->find(secname);
	if (sec==NULL){
		sec=mRoot->findApproximate(secname);
		if (sec!=NULL){
			LOGE("Did you mean '[%s]' ?",sec->getName().c_str());
		}
		return;
	}
	GenericStruct *st=dynamic_cast<GenericStruct*>(sec);
	if (st){
		GenericEntry *val=st->find(key);
		if (val==NULL){
			val=st->findApproximate(key);
			if (val!=NULL){
				LOGE("Did you mean '%s' ?",val->getName().c_str());
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
			cv->setNextValue(val);
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
	if (!reginfo->my_reg_void) {
		LOGE("no reg");
		return SNMP_ERR_GENERR;
	}
	else {
		GenericEntry *cv=static_cast<GenericEntry*>(reginfo->my_reg_void);
		return cv->handleSnmpRequest(handler, reginfo, reqinfo, requests);
	}
}


int ConfigRuntimeError::handleSnmpRequest(netsnmp_mib_handler *handler,
		netsnmp_handler_registration *reginfo,
		netsnmp_agent_request_info   *reqinfo,
		netsnmp_request_info         *requests)
{
	if (reqinfo->mode != MODE_GET) return SNMP_ERR_GENERR;

	const string errors=generateErrors();
//	LOGD("runtime error handleSnmpRequest %s -> %s", reginfo->handlerName, errors.c_str());
	return snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
			(const u_char*) errors.c_str(), errors.size());
}

int ConfigValue::handleSnmpRequest(netsnmp_mib_handler *handler,
		netsnmp_handler_registration *reginfo,
		netsnmp_agent_request_info   *reqinfo,
		netsnmp_request_info         *requests)
{
	char *old_value;
	int ret;
	string newValue;

	switch(reqinfo->mode) {
	case MODE_GET:
//		LOGD("str handleSnmpRequest %s -> %s", reginfo->handlerName, get().c_str());
		return snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
				(const u_char*) get().c_str(), get().size());
		break;
	case MODE_SET_RESERVE1:
		ret = netsnmp_check_vb_type(requests->requestvb, ASN_OCTET_STR);
		if ( ret != SNMP_ERR_NOERROR ) {
			netsnmp_set_request_error(reqinfo, requests, ret );
		}

		mNextValue.assign((char*)requests->requestvb->val.string,
						requests->requestvb->val_len);
		if (!invokeConfigStateChanged(ConfigState::Check)) {
			netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGVALUE);
		}
		break;
	case MODE_SET_RESERVE2:
		old_value=netsnmp_strdup_and_null((const u_char*) get().c_str() , get().size());
		if (!old_value) {
			netsnmp_set_request_error(reqinfo, requests,
					SNMP_ERR_RESOURCEUNAVAILABLE);
			return SNMP_ERR_NOERROR;
		}
		netsnmp_request_add_list_data(requests,
				netsnmp_create_data_list("old_value", old_value, free));
		break;
	case MODE_SET_ACTION:
		newValue.assign((char*)requests->requestvb->val.string,
				requests->requestvb->val_len);
		set(newValue);
		invokeConfigStateChanged(ConfigState::Changed);
		break;
	case MODE_SET_COMMIT:
//		LOGD("str handleSnmpRequest %s <- %s", reginfo->handlerName, get().c_str());
		invokeConfigStateChanged(ConfigState::Commited);
		break;
	case MODE_SET_FREE:
		// Nothing to do
		break;
	case MODE_SET_UNDO:
		old_value=(char *) netsnmp_request_get_list_data(requests, "old_value");
		set(old_value);
		invokeConfigStateChanged(ConfigState::Reset);
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
	int ret;
	u_short *old_value;
	switch(reqinfo->mode) {
	case MODE_GET:
//		LOGD("bool handleSnmpRequest %s -> %d", reginfo->handlerName, read()?1:0);
		snmp_set_var_typed_integer(requests->requestvb, ASN_INTEGER, read()?1:0);
		break;
	case MODE_SET_RESERVE1:
		ret = netsnmp_check_vb_int_range(requests->requestvb, 0, 1);
		if ( ret != SNMP_ERR_NOERROR ) {
			netsnmp_set_request_error(reqinfo, requests, ret );
		}
		mNextValue= requests->requestvb->val.integer == 0 ? "0":"1";
		if (!invokeConfigStateChanged(ConfigState::Check)) {
			netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGVALUE);
		}
		break;
	case MODE_SET_RESERVE2:
		old_value=(u_short*)malloc(sizeof(u_short));
		if (!old_value) {
			netsnmp_set_request_error(reqinfo, requests,
					SNMP_ERR_RESOURCEUNAVAILABLE);
			return SNMP_ERR_NOERROR;
		}
		*old_value=read()?1:0;
		netsnmp_request_add_list_data(requests,
				netsnmp_create_data_list("old_value", old_value, free));
		break;
	case MODE_SET_ACTION:
		write(*requests->requestvb->val.integer == 1);
		invokeConfigStateChanged(ConfigState::Changed);
		break;
	case MODE_SET_COMMIT:
//		LOGD("bool handleSnmpRequest %s <- %d", reginfo->handlerName, read()?1:0);
		invokeConfigStateChanged(ConfigState::Commited);
		break;
	case MODE_SET_FREE:
		// Nothing to do
		break;
	case MODE_SET_UNDO:
		old_value=(u_short *) netsnmp_request_get_list_data(requests, "old_value");
		write(*old_value);
		invokeConfigStateChanged(ConfigState::Reset);
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
	int *old_value;
	int ret;
	std::ostringstream oss;

	switch(reqinfo->mode) {
	case MODE_GET:
//		LOGD("int handleSnmpRequest %s -> %d", reginfo->handlerName, read());
		snmp_set_var_typed_integer(requests->requestvb, ASN_INTEGER, read());
		break;
	case MODE_SET_RESERVE1:
		ret = netsnmp_check_vb_type(requests->requestvb, ASN_INTEGER);
		if ( ret != SNMP_ERR_NOERROR ) {
			netsnmp_set_request_error(reqinfo, requests, ret );
		}
		oss << *requests->requestvb->val.integer;
		mNextValue=oss.str();
		if (!invokeConfigStateChanged(ConfigState::Check)) {
			netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGVALUE);
		}
		break;
	case MODE_SET_RESERVE2:
		old_value=(int*)malloc(sizeof(int));
		if (!old_value) {
			netsnmp_set_request_error(reqinfo, requests,
					SNMP_ERR_RESOURCEUNAVAILABLE);
			return SNMP_ERR_NOERROR;
		}
		*old_value=read();
		netsnmp_request_add_list_data(requests,
				netsnmp_create_data_list("old_value", old_value, free));
		break;
	case MODE_SET_ACTION:
		write(*requests->requestvb->val.integer);
		invokeConfigStateChanged(ConfigState::Changed);
		break;
	case MODE_SET_COMMIT:
//		LOGD("int handleSnmpRequest %s <- %d", reginfo->handlerName, read());
		invokeConfigStateChanged(ConfigState::Commited);
		break;
	case MODE_SET_FREE:
		// Nothing to do
		break;
	case MODE_SET_UNDO:
		old_value=(int *) netsnmp_request_get_list_data(requests, "old_value");
		write(*old_value);
		invokeConfigStateChanged(ConfigState::Reset);
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
//	LOGD("counter64 handleSnmpRequest %s -> %lu", reginfo->handlerName, read());

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
