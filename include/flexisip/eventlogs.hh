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

#pragma once

#include <memory>
#include <mutex>
#include <queue>
#include <string>

#include <sofia-sip/sip.h>
#include <sofia-sip/sip_protos.h>

#include <flexisip/common.hh>
#include <flexisip/sofia-wrapper/home.hh>

namespace flexisip {

class EventLog {
public:

	EventLog(const sip_t *sip);
	EventLog(const EventLog &) = delete;
	virtual ~EventLog() = default;

	const sip_from_t *getFrom() const {return mFrom;}
	const sip_from_t *getTo() const {return mTo;}
	sip_user_agent_t *getUserAgent() const {return mUA;}
	const std::string &getCallId() const {return mCallId;}
	const time_t &getDate() const {return mDate;}
	const std::string &getReason() const {return mReason;}

	bool isCompleted() const {return mCompleted;}
	void setCompleted() {mCompleted = true;}

	int getStatusCode() const {return mStatusCode;}
	template <typename T>
	void setStatusCode(int sip_status, T &&reason) {
		mStatusCode = sip_status;
		mReason = std::forward<T>(reason);
	}

	const std::string &getPriority() const {return mPriority;}
	template <typename T>
	void setPriority(T &&priority) {mPriority = std::forward<T>(priority);}

protected:

	sofiasip::Home mHome{};
	sip_from_t *mFrom{nullptr};
	sip_to_t *mTo{nullptr};
	sip_user_agent_t *mUA{nullptr};
	time_t mDate{0};
	int mStatusCode{0};
	std::string mReason{};
	bool mCompleted{false};
	std::string mCallId{};
	std::string mPriority{"normal"};

	class Init {
	public:
		Init();
	};
	static Init evStaticInit;
};

class RegistrationLog : public EventLog {
public:

	// Explicit values are necessary for soci. Do not change this.
	enum class Type {
		Register = 0,
		Unregister = 1,
		Expired = 2
	};

	RegistrationLog(const sip_t *sip, const sip_contact_t *contacts);

	Type getType() const {return mType;}
	sip_contact_t *getContacts() const {return mContacts;}

private:
	Type mType{Type::Register};
	sip_contact_t *mContacts{nullptr};
};

class CallLog : public EventLog {
public:
	CallLog(const sip_t *sip) : EventLog(sip) {}

	bool isCancelled() const {return mCancelled;}
	void setCancelled() {mCancelled = true;}

private:
	bool mCancelled{false};
};

class MessageLog : public EventLog {
public:

	// Explicit values is necessary for soci. Do not change this.
	enum class ReportType {
		ReceivedFromUser = 0,
		DeliveredToUser = 1
	};

	MessageLog(const sip_t *sip, ReportType report): EventLog(sip), mReportType{report} {}

	ReportType getReportType() const {return mReportType;}
	const url_t *getUri() const {return mUri;}

	void setDestination(const url_t *dest) {mUri = url_hdup(mHome.home(), dest);}

private:

	ReportType mReportType{ReportType::ReceivedFromUser};
	url_t *mUri{nullptr}; // destination uri of message
};

class AuthLog: public EventLog {
public:

	AuthLog(const sip_t *sip, bool userExists);

	const url_t *getOrigin() const {return mOrigin;}
	const std::string &getMethod() const {return mMethod;}

	bool userExists() const {return mUserExists;}

private:

	void setOrigin(const sip_via_t *via);

	url_t *mOrigin{nullptr};
	std::string mMethod{};
	bool mUserExists{false};
};

class CallQualityStatisticsLog: public EventLog {
public:

	CallQualityStatisticsLog(const sip_t *sip);

	const std::string &getReport() const {return mReport;}

private:

	// Note on `soci`: The `char *` support is dead since 2008...
	// See: https://github.com/SOCI/soci/commit/25c704ac4cb7bb0135dabc2421a1281fb868a511
	// It's necessary to create a hard copy with a `string`.
	std::string mReport{};
};

class EventLogWriter {
public:
	EventLogWriter() = default;
	EventLogWriter(const EventLogWriter &) = delete;
	virtual ~EventLogWriter() = default;

	virtual void write(std::shared_ptr<const EventLog> evlog) = 0;
};

class FilesystemEventLogWriter: public EventLogWriter {
public:

	FilesystemEventLogWriter(const std::string &rootpath);
	void write(std::shared_ptr<const EventLog> evlog) override;
	bool isReady() const {return mIsReady;}

private:

	int openPath(const url_t *uri, const char *kind, time_t curtime, int errorcode = 0);
	void writeRegistrationLog(const RegistrationLog *evlog);
	void writeCallLog(const CallLog *clog);
	void writeCallQualityStatisticsLog(const CallQualityStatisticsLog *mlog);
	void writeMessageLog(const MessageLog *mlog);
	void writeAuthLog(const AuthLog *alog);
	void writeErrorLog(const EventLog *log, const char *kind, const std::string &logstr);

	std::string mRootPath{};
	bool mIsReady{false};
};

}

#if ENABLE_SOCI

#include <soci/soci.h>

#include "utils/threadpool.hh"

namespace flexisip {

class DataBaseEventLogWriter: public EventLogWriter {
public:
	enum class Backend {
		Mysql,
		Sqlite3,
		Postgresql
	};

	DataBaseEventLogWriter(
		const std::string &backendString, const std::string &connectionString,
		unsigned int maxQueueSize, unsigned int nbThreadsMax
	);

	void write(std::shared_ptr<const EventLog> evlog) override;
	bool isReady() const {return mIsReady;}

private:
	void initTables(soci::session *session, Backend backend);

	static void writeEventLog(soci::session *session, const EventLog *evlog, int typeId);

	void writeRegistrationLog(soci::session *session, const RegistrationLog *evlog);
	void writeCallLog(soci::session *session, const CallLog *evlog);
	void writeMessageLog(soci::session *session, const MessageLog *evlog);
	void writeAuthLog(soci::session *session, const AuthLog *evlog);
	void writeCallQualityStatisticsLog(soci::session *session, const CallQualityStatisticsLog *evlog);

	void writeEventFromQueue();

	bool mIsReady{false};
	std::mutex mMutex{};
	std::queue<std::shared_ptr<const EventLog>> mListLogs{};

	std::unique_ptr<soci::connection_pool> mConnectionPool{};
	std::unique_ptr<ThreadPool> mThreadPool{};

	unsigned int mMaxQueueSize{0};

	std::array<std::string, 5> mInsertReq{};
};

}

#endif
