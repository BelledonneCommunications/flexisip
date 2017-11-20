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

#ifndef eventlogs_hh
#define eventlogs_hh

#include <sofia-sip/sip.h>
#include <sofia-sip/sip_protos.h>

#include "../common.hh"
#include <string>
#include <memory>
#include <queue>
#include <mutex>

class EventLog {
	friend class FilesystemEventLogWriter;
	friend class DataBaseEventLogWriter;
	friend class EventLogDb;

public:

	EventLog(const sip_t *sip);
	virtual ~EventLog();
	void setCompleted();
	void setStatusCode(int sip_status, const char *reason);
	bool isCompleted() const {
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
	std::string mCallId;
	class Init {
	public:
		Init();
	};
	static Init evStaticInit;
};

class RegistrationLog : public EventLog {
	friend class FilesystemEventLogWriter;
	friend class DataBaseEventLogWriter;
	friend class RegistrationLogDb;

public:

	// Explicit values are necessary for soci. Do not change this.
	enum Type {
		Register = 0,
		Unregister = 1,
		Expired = 2
	};

	RegistrationLog(const sip_t *sip, const sip_contact_t *contacts);

private:
	Type mType;
	sip_contact_t *mContacts;
};

class CallLog : public EventLog {
	friend class FilesystemEventLogWriter;
	friend class DataBaseEventLogWriter;
	friend class CallLogDb;

public:
	CallLog(const sip_t *sip);
	void setCancelled();

private:
	bool mCancelled;
};

class MessageLog : public EventLog {
	friend class FilesystemEventLogWriter;
	friend class DataBaseEventLogWriter;
	friend class MessageLogDb;

public:

	// Explicit values is necessary for soci. Do not change this.
	enum ReportType {
		ReceivedFromUser = 0,
		DeliveredToUser = 1
	};

	MessageLog(const sip_t *sip, ReportType report);
	void setDestination(const url_t *dest);

private:

	ReportType mReportType;
	url_t *mUri; // destination uri of message
};

class AuthLog: public EventLog {
	friend class FilesystemEventLogWriter;
	friend class DataBaseEventLogWriter;
	friend class AuthLogDb;

public:

	AuthLog(const sip_t *sip, bool userExists);

private:

	void setOrigin(const sip_via_t *via);

	url_t *mOrigin;
	std::string mMethod;
	bool mUserExists;
};

class CallQualityStatisticsLog: public EventLog {
	friend class FilesystemEventLogWriter;
	friend class DataBaseEventLogWriter;
	friend class CallQualityStatisticsLogDb;

public:

	CallQualityStatisticsLog(const sip_t *sip);

private:

	// Note on `soci`: The `char *` support is dead since 2008...
	// See: https://github.com/SOCI/soci/commit/25c704ac4cb7bb0135dabc2421a1281fb868a511
	// It's necessary to create a hard copy with a `string`.
	std::string mReport;
};

class EventLogWriter {
public:

	virtual void write(const std::shared_ptr<EventLog> &evlog) = 0;
	virtual ~EventLogWriter();
};

class FilesystemEventLogWriter: public EventLogWriter {
public:

	FilesystemEventLogWriter(const std::string &rootpath);
	virtual void write(const std::shared_ptr<EventLog> &evlog);
	bool isReady() const;

private:

	int openPath(const url_t *uri, const char *kind, time_t curtime, int errorcode = 0);
	void writeRegistrationLog(const std::shared_ptr<RegistrationLog> &evlog);
	void writeCallLog(const std::shared_ptr<CallLog> &clog);
	void writeCallQualityStatisticsLog(const std::shared_ptr<CallQualityStatisticsLog> &mlog);
	void writeMessageLog(const std::shared_ptr<MessageLog> &mlog);
	void writeAuthLog(const std::shared_ptr<AuthLog> &alog);
	void writeErrorLog(const std::shared_ptr<EventLog> &log, const char *kind, const std::string &logstr);
	std::string mRootPath;
	bool mIsReady;
};

#if ENABLE_SOCI

#ifdef __GNUG__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#include <soci.h>
#ifdef __GNUG__
#pragma GCC diagnostic pop
#endif

#include "utils/threadpool.hh"

class DataBaseEventLogWriter: public EventLogWriter {
public:

	enum Backend {
		Mysql = 0,
		Sqlite3 = 1,
		Postgresql = 2
	};

	DataBaseEventLogWriter(
		const std::string &backendString, const std::string &connectionString,
		int maxQueueSize, int nbThreadsMax
	);
	~DataBaseEventLogWriter();

	virtual void write(const std::shared_ptr<EventLog> &evlog);
	bool isReady() const;

private:

	void initTables(Backend backend);

	static void writeEventLog(const std::shared_ptr<EventLog> &evlog, int typeId, soci::session &sql);

	void writeRegistrationLog(const std::shared_ptr<RegistrationLog> &evlog);
	void writeCallLog(const std::shared_ptr<CallLog> &evlog);
	void writeMessageLog(const std::shared_ptr<MessageLog> &evlog);
	void writeAuthLog(const std::shared_ptr<AuthLog> &evlog);
	void writeCallQualityStatisticsLog(const std::shared_ptr<CallQualityStatisticsLog> &evlog);

	void writeEventFromQueue();

	bool mIsReady;
	std::mutex mMutex;
	std::queue<std::shared_ptr<EventLog>> mListLogs;

	soci::connection_pool *mConnectionPool;
	ThreadPool *mThreadPool;

	size_t mMaxQueueSize;

	std::string mInsertReq[5];
};

#endif

#endif
