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

#ifndef eventlogs_hh
#define eventlogs_hh

#include <sofia-sip/sip.h>
#include <sofia-sip/sip_protos.h>

#include "../common.hh"
#include <string>
#include <memory>
#include <queue>

#ifdef HAVE_ODB
#include <odb/database.hxx>
#endif

class FilesystemEventLogWriter;

class EventLog {
friend class FilesystemEventLogWriter;
friend class EventLogDb;
public:
	EventLog();
	virtual ~EventLog();
	void setFrom(const sip_from_t *from);
	void setTo(const sip_to_t *to);
	void setUserAgent(const sip_user_agent_t *ag);
	void setCompleted();
	void setStatusCode(int sip_status, const char *reason);
	bool isCompleted()const{
		return mCompleted;
	}
protected:
	su_home_t mHome;
	sip_from_t *mFrom;
	sip_to_t *mTo;
	sip_user_agent_t *mUA;
	time_t mDate;
	int mStatusCode;
	std::string mReason;
	bool mCompleted;
	class Init{
		public:
			Init();
	};
	static Init evStaticInit;
};

class RegistrationLog : public EventLog{
friend class FilesystemEventLogWriter;
friend class RegistrationLogDb;
public:
	enum Type {Register, Unregister, Expired};
	RegistrationLog(Type type, const sip_from_t *from, const std::string &instance_id, const sip_contact_t *contacts);
private:
	Type mType;
	sip_contact_t *mContacts;
	std::string mInstanceId;
};

class CallLog : public EventLog{
friend class FilesystemEventLogWriter;
friend class CallLogDb;
public:
	CallLog(const sip_from_t *from, const sip_to_t *to);
	void setCancelled();
private:
	bool mCancelled;
};

class MessageLog : public EventLog{
friend class FilesystemEventLogWriter;
friend class MessageLogDb;
public:
	enum ReportType{ Reception, Delivery};
	MessageLog(ReportType report, const sip_from_t *from, const sip_to_t *to, unsigned long id);
	void setDestination(const url_t *dest);
private:
	ReportType mReportType;
	url_t *mUri; //destination uri of message
	unsigned long mId;
};

class AuthLog : public EventLog{
friend class FilesystemEventLogWriter;
friend class AuthLogDb;
	public:
		AuthLog(const char *method, const sip_from_t *from, const sip_to_t *to, bool userExists);
		void setOrigin(const sip_via_t *via);
private:
	url_t *mOrigin;
	std::string mMethod;
	bool mUserExists;
};

class CallQualityStatisticsLog : public EventLog{
friend class FilesystemEventLogWriter;
friend class CallQualityStatisticsLogDb;
public:
	CallQualityStatisticsLog(const sip_from_t *from, const sip_to_t *to, const char *report);
	~CallQualityStatisticsLog();
private:
	char *mReport;
};

class EventLogWriter{
public:
	virtual void write(const std::shared_ptr<EventLog> &evlog)=0;
	virtual ~EventLogWriter();
};

class FilesystemEventLogWriter : public EventLogWriter{
public:
	FilesystemEventLogWriter(const std::string &rootpath);
	virtual void write(const std::shared_ptr<EventLog> &evlog);
	bool isReady()const;
private:
	int openPath(const url_t *uri, const char *kind, time_t curtime, int errorcode=0);
	void writeRegistrationLog(const std::shared_ptr<RegistrationLog> &evlog);
	void writeCallLog(const std::shared_ptr<CallLog> &clog);
	void writeCallQualityStatisticsLog(const std::shared_ptr<CallQualityStatisticsLog> &mlog);
	void writeMessageLog(const std::shared_ptr<MessageLog> & mlog);
	void writeAuthLog(const std::shared_ptr<AuthLog> & alog);
	void writeErrorLog(const std::shared_ptr<EventLog> &log, const char *kind, const std::string &logstr);
	std::string mRootPath;
	bool mIsReady;
};

#if HAVE_ODB
class DataBaseEventLogWriter : public EventLogWriter{
public:
	DataBaseEventLogWriter(const std::string &db_name,const std::string &db_user, const std::string &db_password, const std::string &db_host, int db_port);
	virtual void write(const std::shared_ptr<EventLog> &evlog);
	void static *threadFunc(void *arg) ;
	bool isReady()const;
private:
	bool mIsReady;
	void writeLogs();
	std::mutex mMutex;
	std::unique_ptr<odb::database> mDatabase;
	std::queue<std::shared_ptr<EventLog>> mListLogs;

};
#endif

#endif
