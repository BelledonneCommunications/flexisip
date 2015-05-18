/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include "eventlogs.hh"
#include "configmanager.hh"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <typeinfo>

#ifdef HAVE_ODB
#include <odb/mysql/database.hxx>
#include <odb/transaction.hxx>
#include <odb/schema-catalog.hxx>

#include <thread>

#include "eventlogsdb.hh"
#include "eventlogsdb-odb.hxx"

using namespace odb::core;

#define NB_REQ_MAX 1000

#endif

using namespace ::std;

EventLog::Init EventLog::evStaticInit;

EventLog::Init::Init(){
	ConfigItemDescriptor items[]={
		{	Boolean		,	"enabled"		,	"Enable event logs.", "false"},
		{	String		,	"dir"		,	"Directory where event logs are written as a filesystem (case where odb output is not active).",	"/var/log/flexisip"},
		{	Boolean     ,	"use-odb"	,	"Use odb for storing logs in database. The list of arguments below are used for the connection to the database.  ",	"false"	},
		{	String		,	"odb-database"			,	"Name of the database", "" },
		{	String		,	"odb-user"				,	"User", "" },
		{	String		,	"odb-password"			,	"Password", "" },
		{	String		,	"odb-host"				,	"Host", "" },
		{	Integer		,	"odb-port"				,	"Port", "" },
		{	Integer		,	"nb-thread-max"			,	"Number of thread max for writing in database", "500" },
		config_item_end
	};
	GenericStruct *ev=new GenericStruct("event-logs","Event logs contain per domain and user information about processed registrations, calls and messages.",0);
	GenericManager::get()->getRoot()->addChild(ev);
	ev->addChildrenValues(items);
}


EventLog::EventLog() {
	su_home_init(&mHome);
	mFrom=NULL;
	mTo=NULL;
	mDate=time(NULL);
	mUA=NULL;
	mCompleted=false;
}

EventLog::~EventLog(){
	su_home_deinit(&mHome);
}

void EventLog::setFrom(const sip_from_t *from){
	mFrom=sip_from_dup(&mHome,from);
}

void EventLog::setTo(const sip_to_t *to){
	mTo=sip_to_dup(&mHome,to);
}

void EventLog::setUserAgent(const sip_user_agent_t *ag){
	mUA=sip_user_agent_dup(&mHome,ag);
}

void EventLog::setStatusCode(int sip_status, const char *reason){
	mStatusCode=sip_status;
	mReason=reason;
}

void EventLog::setCompleted(){
	mCompleted=true;
}

RegistrationLog::RegistrationLog(Type type, const sip_from_t *from, const std::string &instance_id, const sip_contact_t *contacts){
	mType=type;
	setFrom(from);
	mInstanceId=instance_id;
	mContacts=sip_contact_dup(&mHome,contacts);
	mStatusCode=200;
}


CallLog::CallLog(const sip_from_t *from, const sip_to_t *to){
	setFrom(from);
	setTo(to);
	mStatusCode=0;
	mCancelled=false;
}

void CallLog::setCancelled(){
	mCancelled=true;
}

MessageLog::MessageLog ( MessageLog::ReportType report, const sip_from_t* from, const sip_to_t* to, const sip_call_id_t * id ) {
	setFrom(from);
	setTo(to);
	mId=id->i_hash;
	mUri=NULL;
	mReportType=report;
	mCallId=id->i_id;
}

void MessageLog::setDestination(const url_t *dest){
	mUri=url_hdup(&mHome,dest);
}

CallQualityStatisticsLog::CallQualityStatisticsLog(const sip_from_t *from, const sip_to_t *to, const char *report){
	setFrom(from);
	setTo(to);

	if (report != NULL) {
		mReport = strdup(report);
	}
}

CallQualityStatisticsLog::~CallQualityStatisticsLog() {
	if (mReport != NULL) {
		free(mReport);
	}
}

AuthLog::AuthLog(const char *method, const sip_from_t *from, const sip_to_t *to, bool userExists){
	setFrom(from);
	setTo(to);
	mOrigin=NULL;
	mUserExists=userExists;
	mMethod=method;
}

void AuthLog::setOrigin( const sip_via_t* via ) {
	const char *protocol=strchr(via->v_protocol,'/')+1;
	const char *scheme="sip";
	const char *port=via->v_rport ? via->v_rport : via->v_port;
	const char *ip=via->v_received ? via->v_received : via->v_host;

	protocol=strchr(protocol,'/')+1;

	if (strcasecmp(protocol,"UDP")==0) protocol=NULL;
	else if (strcasecmp(protocol,"UDP")==0) {
		protocol=NULL;
		scheme="sips";
	}
	if (port)
		mOrigin=url_format(&mHome,"%s:%s:%s",scheme,ip,port);
	else
		mOrigin=url_format(&mHome,"%s:%s",scheme,ip);
	if (protocol)
		mOrigin->url_params=su_sprintf(&mHome,"transport=%s",protocol);
}


static bool createDirectoryIfNotExist(const char *path){
	if (access(path,R_OK|W_OK)==-1){
		if (mkdir(path,S_IRUSR|S_IWUSR|S_IXUSR)==-1){
			LOGE("Cannot create directory %s: %s",path,strerror(errno));
			return false;
		}
	}
	return true;
}


inline ostream & operator<<(ostream & ostr, const sip_user_agent_t *ua){
	char tmp[500]={0};
	sip_user_agent_e(tmp,sizeof(tmp)-1,(msg_header_t*)ua,0);
	ostr<<tmp;
	return ostr;
}

inline ostream & operator<<(ostream & ostr, const url_t *url){
	char tmp[500]={0};
	url_e(tmp,sizeof(tmp)-1,url);
	ostr<<tmp;
	return ostr;
}

inline ostream & operator<<(ostream & ostr, const sip_from_t *from){
	if (from->a_display && *from->a_display!='\0') ostr<<from->a_display;
	ostr<<" <"<<from->a_url<<">";
	return ostr;
}


struct PrettyTime{
	PrettyTime(time_t t) : _t(t){}
	time_t _t;
};

inline ostream & operator<<(ostream & ostr, const PrettyTime &t){
	char tmp[128]={0};
	int len;
	ctime_r(&t._t,tmp);
	len=strlen(tmp);
	if (tmp[len-1]=='\n') tmp[len-1]='\0'; //because ctime_r adds a '\n'
	ostr<<tmp;
	return ostr;
}

inline ostream & operator<<(ostream & ostr, RegistrationLog::Type type){
	switch(type){
		case RegistrationLog::Register:
			ostr<<"Registered";
			break;
		case RegistrationLog::Unregister:
			ostr<<"Unregistered";
			break;
		case RegistrationLog::Expired:
			ostr<<"Registration expired";
			break;
	}
	return ostr;
}

inline ostream &operator<<(ostream & ostr, MessageLog::ReportType type){
	switch(type){
		case MessageLog::Reception:
			ostr<<"Reception";
		break;
		case MessageLog::Delivery:
			ostr<<"Delivery";
		break;
	}
	return ostr;
}

EventLogWriter::~EventLogWriter(){}

FilesystemEventLogWriter::FilesystemEventLogWriter(const std::string &rootpath) : mRootPath(rootpath), mIsReady(false){
	if (rootpath.c_str()[0]!='/'){
		LOGE("Path for event log writer must be absolute.");
		return;
	}
	if (!createDirectoryIfNotExist(rootpath.c_str()))
		return;

	mIsReady=true;
}

bool FilesystemEventLogWriter::isReady()const{
	return mIsReady;
}

int FilesystemEventLogWriter::openPath(const url_t *uri, const char *kind, time_t curtime, int errorcode){
	ostringstream path;

	if (errorcode==0){
		const char *username=uri->url_user;
		const char *domain=uri->url_host;


		path<<mRootPath<<"/users";

		if (!createDirectoryIfNotExist(path.str().c_str()))
			return -1;

		path<<"/"<<domain;

		if (!createDirectoryIfNotExist(path.str().c_str()))
			return -1;

		if (!username)
			username="anonymous";

		path<<"/"<<username;

		if (!createDirectoryIfNotExist(path.str().c_str()))
			return -1;
		path<<"/"<<kind;

		if (!createDirectoryIfNotExist(path.str().c_str()))
			return -1;
	}else{
		path<<mRootPath<<"/"<<"errors/";
		if (!createDirectoryIfNotExist(path.str().c_str()))
			return -1;
		path<<kind;
		if (!createDirectoryIfNotExist(path.str().c_str()))
			return -1;
		path<<"/"<<errorcode;
		if (!createDirectoryIfNotExist(path.str().c_str()))
			return -1;
	}


	struct tm tm;
	localtime_r(&curtime,&tm);
	path<<"/"<<1900+tm.tm_year<<"-"<<std::setfill('0')<<std::setw(2)<<tm.tm_mon+1<<"-"<<std::setfill('0')<<std::setw(2)<<tm.tm_mday<<".log";

	int fd=open(path.str().c_str(),O_WRONLY|O_CREAT|O_APPEND,S_IRUSR|S_IWUSR);
	if (fd==-1){
		LOGE("Cannot open %s: %s",path.str().c_str(),strerror(errno));
		return -1;
	}
	return fd;
}

void FilesystemEventLogWriter::writeRegistrationLog(const std::shared_ptr<RegistrationLog> & rlog){
	const char *label="registers";
	int fd=openPath(rlog->mFrom->a_url,label,rlog->mDate);
	if (fd==-1) return;

	ostringstream msg;
	msg<<PrettyTime(rlog->mDate)<<": "<<rlog->mType<<" "<<rlog->mFrom;
	if (rlog->mContacts && rlog->mContacts->m_url) msg<<" ("<<rlog->mContacts->m_url<<") ";
	if (rlog->mUA) msg<<rlog->mUA<<endl;

	if (::write(fd,msg.str().c_str(),msg.str().size())==-1){
		LOGE("Fail to write registration log: %s",strerror(errno));
	}
	close(fd);
	if (rlog->mStatusCode>=300){
		writeErrorLog(rlog,label,msg.str());
	}
}

void FilesystemEventLogWriter::writeCallLog(const std::shared_ptr<CallLog> &calllog){
	const char *label="calls";
	int fd1=openPath(calllog->mFrom->a_url,label,calllog->mDate);
	int fd2=openPath(calllog->mTo->a_url,label,calllog->mDate);

	ostringstream msg;

	msg<<PrettyTime(calllog->mDate)<<": "<<calllog->mFrom<<" --> "<<calllog->mTo<<" ";
	if (calllog->mCancelled) msg<<"Cancelled";
	else msg<<calllog->mStatusCode<<" "<<calllog->mReason;
	msg<<endl;

	if (fd1==-1 || ::write(fd1,msg.str().c_str(),msg.str().size())==-1){
		LOGE("Fail to write registration log: %s",strerror(errno));
	}
	// Avoid to write logs for users that possibly do not exist.
	// However the error will be reported in the errors directory.
	if (calllog->mStatusCode!=404){
		if (fd2==-1 || ::write(fd2,msg.str().c_str(),msg.str().size())==-1){
			LOGE("Fail to write registration log: %s",strerror(errno));
		}
	}
	if (fd1!=-1) close(fd1);
	if (fd2!=-1) close(fd2);
	if (calllog->mStatusCode>=300){
		writeErrorLog(calllog,label,msg.str());
	}
}

void FilesystemEventLogWriter::writeMessageLog(const std::shared_ptr<MessageLog> &mlog){
	const char *label="messages";
	int fd=openPath(mlog->mReportType==MessageLog::Reception ? mlog->mFrom->a_url : mlog->mTo->a_url
			,label,mlog->mDate);
	if (fd==-1) return;
	ostringstream msg;

	msg<<PrettyTime(mlog->mDate)<<": "<<mlog->mReportType<<" id:"<<std::hex<<mlog->mCallId<<" "<<std::dec;
	msg<<mlog->mFrom<<" --> "<<mlog->mTo;
	if (mlog->mUri) msg<<" ("<<mlog->mUri<<") ";
	msg<<mlog->mStatusCode<<" "<<mlog->mReason<<endl;
	// Avoid to write logs for users that possibly do not exist.
	// However the error will be reported in the errors directory.
	if (!(mlog->mReportType==MessageLog::Delivery && mlog->mStatusCode==404)){
		if (::write(fd,msg.str().c_str(),msg.str().size())==-1){
			LOGE("Fail to write message log: %s",strerror(errno));
		}
	}
	close(fd);
	if (mlog->mStatusCode>=300){
		writeErrorLog(mlog,label,msg.str());
	}
}

void FilesystemEventLogWriter::writeCallQualityStatisticsLog(const std::shared_ptr<CallQualityStatisticsLog> &mlog){
	const char *label="statistics_reports";
	int fd=openPath(mlog->mFrom->a_url,label,mlog->mDate);
	if (fd==-1) return;
	ostringstream msg;

	msg<<PrettyTime(mlog->mDate)<<" ";
	msg<<mlog->mFrom<<" --> "<<mlog->mTo<<" ";
	msg<<mlog->mStatusCode<<" "<<mlog->mReason <<": ";
	if (mlog->mReport != NULL) msg<<mlog->mReport<<endl;

	if (::write(fd,msg.str().c_str(),msg.str().size())==-1){
		LOGE("Fail to write registration log: %s",strerror(errno));
	}

	close(fd);
	if (mlog->mStatusCode>=300){
		writeErrorLog(mlog,label,msg.str());
	}
}

void FilesystemEventLogWriter::writeAuthLog(const std::shared_ptr<AuthLog> &alog){
	const char *label="auth";
	ostringstream msg;
	msg<<PrettyTime(alog->mDate)<<" "<<alog->mMethod<<" "<<alog->mFrom;
	if (alog->mOrigin) msg<<" ("<<alog->mOrigin<<") ";
	if (alog->mUA) msg<<" ("<<alog->mUA<<") ";
	msg<<" --> "<<alog->mTo<<" ";
	msg<<alog->mStatusCode<<" "<<alog->mReason<<endl;

	if (alog->mUserExists){
		int fd=openPath(alog->mFrom->a_url,label,alog->mDate);
		if (fd!=-1){
			if (::write(fd,msg.str().c_str(),msg.str().size())==-1){
				LOGE("Fail to write auth log: %s",strerror(errno));
			}
			close(fd);
		}
	}
	writeErrorLog(alog,"auth",msg.str());
}

void FilesystemEventLogWriter::writeErrorLog(const std::shared_ptr<EventLog> &log, const char *kind, const std::string &logstr){
	int fd=openPath(NULL,kind,log->mDate,log->mStatusCode);
	if (fd==-1) return;
	if (::write(fd,logstr.c_str(),logstr.size())==-1){
		LOGE("Fail to write error log: %s",strerror(errno));
	}
	close(fd);
}

void FilesystemEventLogWriter::write(const std::shared_ptr<EventLog> &evlog){
	if (typeid(*evlog.get())==typeid(RegistrationLog)){
		writeRegistrationLog(static_pointer_cast<RegistrationLog>(evlog));
	}else if (typeid(*evlog.get())==typeid(CallLog)){
		writeCallLog(static_pointer_cast<CallLog>(evlog));
	}else if (typeid(*evlog.get())==typeid(MessageLog)){
		writeMessageLog(static_pointer_cast<MessageLog>(evlog));
	}else if (typeid(*evlog.get())==typeid(AuthLog)){
		writeAuthLog(static_pointer_cast<AuthLog>(evlog));
	}else if (typeid(*evlog.get())==typeid(CallQualityStatisticsLog)){
		writeCallQualityStatisticsLog(static_pointer_cast<CallQualityStatisticsLog>(evlog));
	}
}

#ifdef HAVE_ODB
// Data Base EventLog Writer

DataBaseEventLogWriter::DataBaseEventLogWriter(const std::string &db_name,const std::string &db_user, const std::string &db_password, const std::string &db_host, int db_port) : mIsReady(false){
	try {
		mDatabase = unique_ptr<odb::database>(new odb::mysql::database (db_user, db_password, db_name, db_host, db_port));

		mIsReady=true;

		schema_version v (mDatabase->schema_version ());
		schema_version bv (schema_catalog::base_version (*mDatabase));
		schema_version cv (schema_catalog::current_version (*mDatabase));

		if (v == 0){
			SLOGD << "No database found... creating it.";
			transaction t (mDatabase->begin ());
			schema_catalog::create_schema (*mDatabase);
			t.commit ();
		} else if (v < cv){
			SLOGD << "Database is outdated (current="<<v<<", latest="<<cv<<").";
			if (v < bv){
				LOGE("Error: migration from this version is no longer supported.");
			}
			for (v=schema_catalog::next_version (*mDatabase, v); v<=cv; v=schema_catalog::next_version (*mDatabase, v)){
				transaction t (mDatabase->begin ());

				SLOGD << "Updating database to version "<<v<<".";
				schema_catalog::migrate_schema_pre (*mDatabase, v);

				schema_catalog::migrate(*mDatabase, v);

				schema_catalog::migrate_schema_post (*mDatabase, v);
				t.commit ();
			}
		}
		else if (v > cv){
			LOGE("Error: old application trying to access new database.");
		}
	} catch (const odb::exception& e){
		LOGE("Fail to connect to the database: %s.", e.what());
	}
}

bool DataBaseEventLogWriter::isReady()const{
	return mIsReady;
}

void DataBaseEventLogWriter::writeLogs(){
	mMutex.lock();
	shared_ptr<EventLog> evlog = mListLogs.front();
	mListLogs.pop();
	mMutex.unlock();

	EventLogDb * ev = NULL;
	if (typeid(*evlog.get())==typeid(RegistrationLog)){
		ev = new RegistrationLogDb(static_pointer_cast<RegistrationLog>(evlog));
	}else if (typeid(*evlog.get())==typeid(CallLog)){
		ev = new CallLogDb(static_pointer_cast<CallLog>(evlog));
	}else if (typeid(*evlog.get())==typeid(MessageLog)){
		ev = new MessageLogDb(static_pointer_cast<MessageLog>(evlog));
	}else if (typeid(*evlog.get())==typeid(AuthLog)){
		ev = new AuthLogDb(static_pointer_cast<AuthLog>(evlog));
	}else if (typeid(*evlog.get())==typeid(CallQualityStatisticsLog)){
		ev = new CallQualityStatisticsLogDb(static_pointer_cast<CallQualityStatisticsLog>(evlog));
	}

	if (ev){
		if(mIsReady){
			try {
				transaction t (mDatabase->begin ());
				mDatabase->persist (*ev);
				t.commit ();
			} catch (const odb::exception & e){
				LOGE("DataBaseEventLogWriter: could not write log in database: %s", e.what());
			}
		}
		delete ev;
	}
}

void *DataBaseEventLogWriter::threadFunc(void *arg) {
	DataBaseEventLogWriter *dbLW = (DataBaseEventLogWriter*) arg;
	dbLW->writeLogs();
	return NULL;
}

void DataBaseEventLogWriter::write(const std::shared_ptr<EventLog> &evlog){
	unsigned int nb_thread_max = GenericManager::get()->getRoot()->get<GenericStruct>("event-logs")->get<ConfigInt>("nb-thread-max")->read();
	mMutex.lock();
	if(mListLogs.size() < nb_thread_max){
		mListLogs.push(evlog);
		mMutex.unlock();
		thread t=thread(DataBaseEventLogWriter::threadFunc, this);
		t.detach();
	} else {
		mMutex.unlock();
	}
}

#endif

