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

using namespace std;

EventLog::Init EventLog::evStaticInit;

EventLog::Init::Init() {
	ConfigItemDescriptor items[] = {
		{Boolean, "enabled", "Enable event logs.", "false"},
		{String, "dir", "Directory where event logs are written as a filesystem (case when database output is not active).",
		 "/var/log/flexisip"},
		{String, "logger", "Define logger for storing logs. It supports \"filesystem\" and \"database\".",
		 "database"},
		{String, "database-backend", "Choose the type of backend that Soci will use for the connection.\n"
		 "Depending on your Soci package and the modules you installed, the supported databases are:",
		 "`mysql` and `sqlite3`"
		 "mysql"},
		{String, "database-connection-string", "The configuration parameters of the backend.\n"
		 "The basic format is \"key=value key2=value2\". For a mysql backend, this "
		 "is a valid config: \"db=mydb user=user password='pass' host=myhost.com\".\n"
		 "Please refer to the Soci documentation of your backend, for instance: "
		 "http://soci.sourceforge.net/doc/3.2/backends/mysql.html"
		 "http://soci.sourceforge.net/doc/3.2/backends/sqlite3.html",
		 "db='mydb' user='myuser' password='mypass' host='myhost.com'"},
		{Integer, "database-max-queue-size",
		 "Amount of queries that will be allowed to be queued before bailing password "
		 "requests.\n This value should be chosen accordingly with 'database-nb-threads-max', so "
		 "that you have a coherent behavior.\n This limit is here mainly as a safeguard "
		 "against out-of-control growth of the queue in the event of a flood or big "
		 "delays in the database backend.",
		 "100"},
		{Integer, "database-nb-threads-max", "Maximum number of threads for writing in database.\n"
		 "If you get a `database is locked` error with sqlite3, you must set this variable to 1.",
		 "10"},
		config_item_end};
	GenericStruct *ev = new GenericStruct(
		"event-logs",
		"Event logs contain per domain and user information about processed registrations, calls and messages.", 0);
	GenericManager::get()->getRoot()->addChild(ev);
	ev->addChildrenValues(items);
}

EventLog::EventLog(const sip_t *sip) {
	su_home_init(&mHome);
	mFrom = sip_from_dup(&mHome, sip->sip_from);
	mTo = sip_to_dup(&mHome, sip->sip_to);
	mDate = time(NULL);

	mUA = sip->sip_user_agent ? sip_user_agent_dup(&mHome, sip->sip_user_agent) : NULL;
	mCallId = sip->sip_call_id->i_id;
	mStatusCode = 0;

	mCompleted = false;
}

EventLog::~EventLog() {
	su_home_deinit(&mHome);
}

void EventLog::setStatusCode(int sip_status, const char *reason) {
	mStatusCode = sip_status;
	mReason = reason;
}

void EventLog::setCompleted() {
	mCompleted = true;
}

RegistrationLog::RegistrationLog(const sip_t *sip, const sip_contact_t *contacts): EventLog(sip) {
	mType = (sip->sip_expires && sip->sip_expires->ex_delta == 0)
		? RegistrationLog::Unregister // REVISIT not 100% exact.
		: RegistrationLog::Register;

	mContacts = sip_contact_dup(&mHome, contacts);
}

CallLog::CallLog(const sip_t *sip): EventLog(sip) {
	mCancelled = false;
}

void CallLog::setCancelled() {
	mCancelled = true;
}

MessageLog::MessageLog(const sip_t *sip, ReportType report): EventLog(sip) {
	mUri = NULL;
	mReportType = report;
}

void MessageLog::setDestination(const url_t *dest) {
	mUri = url_hdup(&mHome, dest);
}

CallQualityStatisticsLog::CallQualityStatisticsLog(const sip_t *sip): EventLog(sip) {
	const char *report = sip->sip_payload ? sip->sip_payload->pl_data : NULL;
	if (report != NULL) {
		mReport = report;
	}
}

AuthLog::AuthLog(const sip_t *sip, bool userExists): EventLog(sip) {
	mOrigin = NULL;
	mUserExists = userExists;
	mMethod = sip->sip_request->rq_method_name;

	setOrigin(sip->sip_via);
}

void AuthLog::setOrigin(const sip_via_t *via) {
	const char *protocol = strchr(via->v_protocol, '/') + 1;
	const char *port = via->v_rport ? via->v_rport : via->v_port;
	const char *ip = via->v_received ? via->v_received : via->v_host;

	protocol = strchr(protocol, '/') + 1;

	mOrigin = url_format(&mHome, "sip:%s", ip);
	if (!mOrigin){
		LOGE("AuthLog: invalid via with host %s", ip);
		mOrigin = url_format(&mHome, "sip:invalid.host");
	}
	if (port){
		mOrigin->url_port = su_strdup(&mHome, port);
	}
	if (protocol){
		mOrigin->url_params = su_sprintf(&mHome, "transport=%s", protocol);
	}
}

static bool createDirectoryIfNotExist(const char *path) {
	if (access(path, R_OK | W_OK) == -1) {
		if (mkdir(path, S_IRUSR | S_IWUSR | S_IXUSR) == -1) {
			LOGE("Cannot create directory %s: %s", path, strerror(errno));
			return false;
		}
	}
	return true;
}

inline ostream &operator<<(ostream &ostr, const sip_user_agent_t *ua) {
	char tmp[500] = {0};
	sip_user_agent_e(tmp, sizeof(tmp) - 1, (msg_header_t *)ua, 0);
	ostr << tmp;
	return ostr;
}

inline ostream &operator<<(ostream &ostr, const url_t *url) {
	char tmp[500] = {0};
	url_e(tmp, sizeof(tmp) - 1, url);
	ostr << tmp;
	return ostr;
}

inline ostream &operator<<(ostream &ostr, const sip_from_t *from) {
	if (from->a_display && *from->a_display != '\0')
		ostr << from->a_display;
	ostr << " <" << from->a_url << ">";
	return ostr;
}

struct PrettyTime {
	PrettyTime(time_t t) : _t(t) {
	}
	time_t _t;
};

inline ostream &operator<<(ostream &ostr, const PrettyTime &t) {
	char tmp[128] = {0};
	int len;
	ctime_r(&t._t, tmp);
	len = strlen(tmp);
	if (tmp[len - 1] == '\n')
		tmp[len - 1] = '\0'; // because ctime_r adds a '\n'
	ostr << tmp;
	return ostr;
}

inline ostream &operator<<(ostream &ostr, RegistrationLog::Type type) {
	switch (type) {
		case RegistrationLog::Register:
			ostr << "Registered";
			break;
		case RegistrationLog::Unregister:
			ostr << "Unregistered";
			break;
		case RegistrationLog::Expired:
			ostr << "Registration expired";
			break;
	}
	return ostr;
}

inline ostream &operator<<(ostream &ostr, MessageLog::ReportType type) {
	switch (type) {
		case MessageLog::ReceivedFromUser:
			ostr << "Received from user";
			break;
		case MessageLog::DeliveredToUser:
			ostr << "Delivered to user";
			break;
	}
	return ostr;
}

EventLogWriter::~EventLogWriter() {
}

FilesystemEventLogWriter::FilesystemEventLogWriter(const std::string &rootpath) : mRootPath(rootpath), mIsReady(false) {
	if (rootpath.c_str()[0] != '/') {
		LOGE("Path for event log writer must be absolute.");
		return;
	}
	if (!createDirectoryIfNotExist(rootpath.c_str()))
		return;

	mIsReady = true;
}

bool FilesystemEventLogWriter::isReady() const {
	return mIsReady;
}

int FilesystemEventLogWriter::openPath(const url_t *uri, const char *kind, time_t curtime, int errorcode) {
	ostringstream path;

	if (errorcode == 0) {
		const char *username = uri->url_user;
		const char *domain = uri->url_host;

		path << mRootPath << "/users";

		if (!createDirectoryIfNotExist(path.str().c_str()))
			return -1;

		path << "/" << domain;

		if (!createDirectoryIfNotExist(path.str().c_str()))
			return -1;

		if (!username)
			username = "anonymous";

		path << "/" << username;

		if (!createDirectoryIfNotExist(path.str().c_str()))
			return -1;
		path << "/" << kind;

		if (!createDirectoryIfNotExist(path.str().c_str()))
			return -1;
	} else {
		path << mRootPath << "/" << "errors/";
		if (!createDirectoryIfNotExist(path.str().c_str()))
			return -1;
		path << kind;
		if (!createDirectoryIfNotExist(path.str().c_str()))
			return -1;
		path << "/" << errorcode;
		if (!createDirectoryIfNotExist(path.str().c_str()))
			return -1;
	}

	struct tm tm;
	localtime_r(&curtime, &tm);
	path << "/" << 1900 + tm.tm_year << "-" << std::setfill('0') << std::setw(2) << tm.tm_mon + 1 << "-" <<
		std::setfill('0') << std::setw(2) << tm.tm_mday << ".log";

	int fd = open(path.str().c_str(), O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		LOGE("Cannot open %s: %s", path.str().c_str(), strerror(errno));
		return -1;
	}
	return fd;
}

void FilesystemEventLogWriter::writeRegistrationLog(const std::shared_ptr<RegistrationLog> &rlog) {
	const char *label = "registers";
	int fd = openPath(rlog->mFrom->a_url, label, rlog->mDate);
	if (fd == -1)
		return;

	ostringstream msg;
	msg << PrettyTime(rlog->mDate) << ": " << rlog->mType << " " << rlog->mFrom;
	if (rlog->mContacts)
		msg << " (" << rlog->mContacts->m_url << ") ";
	if (rlog->mUA)
		msg << rlog->mUA << endl;

	if (::write(fd, msg.str().c_str(), msg.str().size()) == -1) {
		LOGE("Fail to write registration log: %s", strerror(errno));
	}
	close(fd);
	if (rlog->mStatusCode >= 300) {
		writeErrorLog(rlog, label, msg.str());
	}
}

void FilesystemEventLogWriter::writeCallLog(const std::shared_ptr<CallLog> &calllog) {
	const char *label = "calls";
	int fd1 = openPath(calllog->mFrom->a_url, label, calllog->mDate);
	int fd2 = openPath(calllog->mTo->a_url, label, calllog->mDate);

	ostringstream msg;

	msg << PrettyTime(calllog->mDate) << ": " << calllog->mFrom << " --> " << calllog->mTo << " ";
	if (calllog->mCancelled)
		msg << "Cancelled";
	else
		msg << calllog->mStatusCode << " " << calllog->mReason;
	msg << endl;

	if (fd1 == -1 || ::write(fd1, msg.str().c_str(), msg.str().size()) == -1) {
		LOGE("Fail to write registration log: %s", strerror(errno));
	}
	// Avoid to write logs for users that possibly do not exist.
	// However the error will be reported in the errors directory.
	if (calllog->mStatusCode != 404) {
		if (fd2 == -1 || ::write(fd2, msg.str().c_str(), msg.str().size()) == -1) {
			LOGE("Fail to write registration log: %s", strerror(errno));
		}
	}
	if (fd1 != -1)
		close(fd1);
	if (fd2 != -1)
		close(fd2);
	if (calllog->mStatusCode >= 300) {
		writeErrorLog(calllog, label, msg.str());
	}
}

void FilesystemEventLogWriter::writeMessageLog(const std::shared_ptr<MessageLog> &mlog) {
	const char *label = "messages";
	ostringstream msg;

	msg << PrettyTime(mlog->mDate) << ": " << mlog->mReportType << " id:" << std::hex << mlog->mCallId << " " <<
		std::dec;
	msg << mlog->mFrom << " --> " << mlog->mTo;
	if (mlog->mUri)
		msg << " (" << mlog->mUri << ") ";
	msg << mlog->mStatusCode << " " << mlog->mReason << endl;

	if (mlog->mReportType == MessageLog::ReceivedFromUser){
		int fd = openPath(mlog->mFrom->a_url, label, mlog->mDate);
		if (fd != -1){
			if (::write(fd, msg.str().c_str(), msg.str().size()) == -1) {
				LOGE("Fail to write message log: %s", strerror(errno));
			}
			close(fd);
		}
	}else { //MessageLog::DeliveredToUser
		/*the event is added into the sender's log file and the receiver's log file, for convenience*/
		int fd = openPath(mlog->mFrom->a_url, label, mlog->mDate);
		if (fd != -1){
			if (::write(fd, msg.str().c_str(), msg.str().size()) == -1) {
				LOGE("Fail to write message log: %s", strerror(errno));
			}
			close(fd);
		}
		// Avoid to write logs for users that possibly do not exist.
		// However the error will be reported in the errors directory.
		if (mlog->mStatusCode != 404){
			fd = openPath(mlog->mTo->a_url, label, mlog->mDate);
			if (fd != -1){
				if (::write(fd, msg.str().c_str(), msg.str().size()) == -1) {
					LOGE("Fail to write message log: %s", strerror(errno));
				}
				close(fd);
			}
		}
	}
	if (mlog->mStatusCode >= 300) {
		writeErrorLog(mlog, label, msg.str());
	}
}

void FilesystemEventLogWriter::writeCallQualityStatisticsLog(const std::shared_ptr<CallQualityStatisticsLog> &mlog) {
	const char *label = "statistics_reports";
	int fd = openPath(mlog->mFrom->a_url, label, mlog->mDate);
	if (fd == -1)
		return;
	ostringstream msg;

	msg << PrettyTime(mlog->mDate) << " ";
	msg << mlog->mFrom << " --> " << mlog->mTo << " ";
	msg << mlog->mStatusCode << " " << mlog->mReason << ": ";
	msg << mlog->mReport << endl;

	if (::write(fd, msg.str().c_str(), msg.str().size()) == -1) {
		LOGE("Fail to write registration log: %s", strerror(errno));
	}

	close(fd);
	if (mlog->mStatusCode >= 300) {
		writeErrorLog(mlog, label, msg.str());
	}
}

void FilesystemEventLogWriter::writeAuthLog(const std::shared_ptr<AuthLog> &alog) {
	const char *label = "auth";
	ostringstream msg;
	msg << PrettyTime(alog->mDate) << " " << alog->mMethod << " " << alog->mFrom;
	if (alog->mOrigin)
		msg << " (" << alog->mOrigin << ") ";
	if (alog->mUA)
		msg << " (" << alog->mUA << ") ";
	msg << " --> " << alog->mTo << " ";
	msg << alog->mStatusCode << " " << alog->mReason << endl;

	if (alog->mUserExists) {
		int fd = openPath(alog->mFrom->a_url, label, alog->mDate);
		if (fd != -1) {
			if (::write(fd, msg.str().c_str(), msg.str().size()) == -1) {
				LOGE("Fail to write auth log: %s", strerror(errno));
			}
			close(fd);
		}
	}
	writeErrorLog(alog, "auth", msg.str());
}

void FilesystemEventLogWriter::writeErrorLog(
	const std::shared_ptr<EventLog> &log, const char *kind,
	const std::string &logstr
) {
	int fd = openPath(NULL, kind, log->mDate, log->mStatusCode);
	if (fd == -1)
		return;
	if (::write(fd, logstr.c_str(), logstr.size()) == -1) {
		LOGE("Fail to write error log: %s", strerror(errno));
	}
	close(fd);
}

void FilesystemEventLogWriter::write(const std::shared_ptr<EventLog> &evlog) {
	EventLog *ev = evlog.get(); // to fix compilation issue with Apple LLVM version 7.0.0
	if (typeid(*ev) == typeid(RegistrationLog)) {
		writeRegistrationLog(static_pointer_cast<RegistrationLog>(evlog));
	} else if (typeid(*ev) == typeid(CallLog)) {
		writeCallLog(static_pointer_cast<CallLog>(evlog));
	} else if (typeid(*ev) == typeid(MessageLog)) {
		writeMessageLog(static_pointer_cast<MessageLog>(evlog));
	} else if (typeid(*ev) == typeid(AuthLog)) {
		writeAuthLog(static_pointer_cast<AuthLog>(evlog));
	} else if (typeid(*ev) == typeid(CallQualityStatisticsLog)) {
		writeCallQualityStatisticsLog(static_pointer_cast<CallQualityStatisticsLog>(evlog));
	}
}

#if ENABLE_SOCI

#define BUFFER_SIZE 256

#define SQL_REGISTRATION_EVENT_LOG_ID 0
#define SQL_CALL_EVENT_LOG_ID 1
#define SQL_MESSAGE_EVENT_LOG_ID 2
#define SQL_AUTH_EVENT_LOG_ID 3
#define SQL_CALL_QUALITY_EVENT_LOG_ID 4

#define SQL_MYSQL_LAST_ID_FUN "LAST_INSERT_ID()"
#define SQL_SQLITE3_LAST_ID_FUN "last_insert_rowid()"

using namespace soci;

inline string sipDataToString(const url_t *url) {
	if (!url) {
		return string();
	}

	char tmp[BUFFER_SIZE] = {0};
	url_e(tmp, sizeof(tmp) - 1, url);
	return string(tmp);
}

inline string sipDataToString(const sip_from_t *from) {
	string str;

	if (!from) {
		return str;
	}

	if (from->a_display && *from->a_display != '\0') {
		str = from->a_display;
		str += " ";
	}

	str += "<" + sipDataToString(from->a_url) + ">";

	return str;
}

inline string sipDataToString(const sip_user_agent_t *ua) {
	if (!ua) {
		return string();
	}

	char tmp[BUFFER_SIZE] = {0};
	sip_user_agent_e(tmp, sizeof(tmp) - 1, (msg_header_t *)ua, 0);
	return string(tmp);
}

inline string sipDataToString(const sip_contact_t *contact) {
	if (!contact) {
		return string();
	}

	return sipDataToString(contact->m_url);
}

// `bool` type is not supported by `soci`.
// Also, for future uses, no sql column is a bool type in this code.
// A Oracle database doesn't support this type. It's better to use
// a `CHAR(1)` instead with a `Y`/`N` value.
inline string boolToSqlString(bool value) {
	return string(value ? "Y" : "N");
}

inline string createEventsTable(DataBaseEventLogWriter::Backend backend) {
	string str = "CREATE TABLE IF NOT EXISTS event_log (";

	// Damn it... This function exists only because `AUTOINCREMENT`
	// has one `_` in MySQL and none in SQlite3...
	//
	// Also in SQlite3, AUTOINCREMENT is only allowed on an INTEGER PRIMARY KEY.
	str += (backend == DataBaseEventLogWriter::Backend::Mysql)
		? "  id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,"
		: "  id INTEGER PRIMARY KEY AUTOINCREMENT,";

	str +=
		"  type_id TINYINT UNSIGNED NOT NULL,"
		"  sip_from VARCHAR(255) NOT NULL,"
		"  sip_to VARCHAR(255) NOT NULL,"
		"  user_agent VARCHAR(255) NOT NULL,"
		"  date DATETIME NOT NULL,"
		"  status_code TINYINT UNSIGNED NOT NULL,"
		"  reason VARCHAR(255) NOT NULL,"
		"  completed CHAR(1) NOT NULL,"
		"  call_id VARCHAR(255) NOT NULL,"

		"  FOREIGN KEY (type_id)"
		"    REFERENCES event_type(id)"
		")";

	return str;
}

inline string createEventTypesTable(DataBaseEventLogWriter::Backend backend) {
	string str = (backend == DataBaseEventLogWriter::Backend::Mysql)
		? "INSERT INTO event_type (id, type)"
		: "INSERT OR IGNORE INTO event_type (id, type)";

	str +=
		"VALUES"
		"(0, \"Registration\"),"
		"(1, \"Call\"),"
		"(2, \"Message\"),"
		"(3, \"Auth\"),"
		"(4, \"QualityStatistics\")";

	if (backend == DataBaseEventLogWriter::Backend::Mysql) {
		str += "ON DUPLICATE KEY UPDATE type = VALUES(type)";
	}

	return str;
}

inline string createRegistrationTypesTable(DataBaseEventLogWriter::Backend backend) {
	string str = (backend == DataBaseEventLogWriter::Backend::Mysql)
		? "INSERT INTO registration_type (id, type)"
		: "INSERT OR IGNORE INTO registration_type (id, type)";

	str +=
		"VALUES"
		"(0, \"Register\"),"
		"(1, \"Unregister\"),"
		"(2, \"Expired\")";

	if (backend == DataBaseEventLogWriter::Backend::Mysql) {
		str += "ON DUPLICATE KEY UPDATE type = VALUES(type)";
	}

	return str;
}

inline string createMessageTypesTable(DataBaseEventLogWriter::Backend backend) {
	string str = (backend == DataBaseEventLogWriter::Backend::Mysql)
		? "INSERT INTO message_type (id, type)"
		: "INSERT OR IGNORE INTO message_type (id, type)";

	str +=
		"VALUES"
		"(0, \"Received\"),"
		"(1, \"Delivered\")";

	if (backend == DataBaseEventLogWriter::Backend::Mysql) {
		str += "ON DUPLICATE KEY UPDATE type = VALUES(type)";
	}

	return str;
}

DataBaseEventLogWriter::DataBaseEventLogWriter(
	const std::string &backendString, const std::string &connectionString,
	int maxQueueSize, int nbThreadsMax){
	mConnectionPool = nullptr;
	mThreadPool = nullptr;
	mIsReady = false;
	mMaxQueueSize = maxQueueSize;
	try {
		if (backendString != "mysql" && backendString != "sqlite3") {
			LOGE("DataBaseEventLogWriter: backend must be equals to `mysql` or `sqlite3`.");
			return;
		}

		mConnectionPool = new connection_pool(nbThreadsMax);
		mThreadPool = new ThreadPool(nbThreadsMax, maxQueueSize);

		for (int i = 0; i < nbThreadsMax; i++) {
			mConnectionPool->at(i).open(backendString, connectionString);
		}

		// Init tables.
		Backend backend = backendString == "mysql" ? Backend::Mysql : Backend::Sqlite3;
		initTables(backend);

		// Build insert requests.
		string lastIdFun =
			(backend == Backend::Mysql) ? SQL_MYSQL_LAST_ID_FUN : SQL_SQLITE3_LAST_ID_FUN;

		mInsertReq[SQL_REGISTRATION_EVENT_LOG_ID] =
			"INSERT INTO event_registration_log VALUES (" + lastIdFun + ", :typeId, :contacts)";

		mInsertReq[SQL_CALL_EVENT_LOG_ID] =
			"INSERT INTO event_call_log VALUES (" + lastIdFun + ", :cancelled)";

		mInsertReq[SQL_MESSAGE_EVENT_LOG_ID] =
			"INSERT INTO event_message_log VALUES (" + lastIdFun + ", :typeId, :uri)";

		mInsertReq[SQL_AUTH_EVENT_LOG_ID] =
			"INSERT INTO event_auth_log VALUES (" +	lastIdFun + ", :method, :origin, :userExists)";

		mInsertReq[SQL_CALL_QUALITY_EVENT_LOG_ID] =
			"INSERT INTO event_call_quality_log VALUES (" + lastIdFun + ", :report)";

		mIsReady = true;
	} catch (exception const &e) {
		LOGE("DataBaseEventLogWriter: could not create logger: %s", e.what());
	}
}

DataBaseEventLogWriter::~DataBaseEventLogWriter() {
	delete mThreadPool;
	delete mConnectionPool;
}

bool DataBaseEventLogWriter::DataBaseEventLogWriter::isReady() const {
	return mIsReady;
}

void DataBaseEventLogWriter::initTables(Backend backend) {
	// Get a connection from pool.
	// It's free at end of the function.
	session sql(*mConnectionPool);

	// Create types (event, registration, message).
	sql <<
		"CREATE TABLE IF NOT EXISTS event_type ("
		"  id TINYINT UNSIGNED PRIMARY KEY,"
		"  type VARCHAR(255) NOT NULL UNIQUE"
		")";

	sql <<
		"CREATE TABLE IF NOT EXISTS registration_type ("
		"  id TINYINT UNSIGNED PRIMARY KEY,"
		"  type VARCHAR(255) NOT NULL UNIQUE"
		")";

	sql <<
		"CREATE TABLE IF NOT EXISTS message_type ("
		"  id TINYINT UNSIGNED PRIMARY KEY,"
		"  type VARCHAR(255) NOT NULL UNIQUE"
		")";

	// Main events table.
	sql << createEventsTable(backend);

	// Specialized events table.
	sql <<
		"CREATE TABLE IF NOT EXISTS event_registration_log ("
		"  id BIGINT UNSIGNED PRIMARY KEY,"
		"  type_id TINYINT UNSIGNED NOT NULL,"
		"  contacts VARCHAR(255) NOT NULL,"

		"  FOREIGN KEY (id)"
		"    REFERENCES event_log(id)"
		"    ON DELETE CASCADE,"

		"  FOREIGN KEY (type_id)"
		"    REFERENCES registration_type(id)"
		")";

	sql <<
		"CREATE TABLE IF NOT EXISTS event_call_log ("
		"  id BIGINT UNSIGNED PRIMARY KEY,"
		"  cancelled CHAR(1) NOT NULL,"

		"  FOREIGN KEY (id)"
		"    REFERENCES event_log(id)"
		"    ON DELETE CASCADE"
		")";

	sql <<
		"CREATE TABLE IF NOT EXISTS event_message_log ("
		"  id BIGINT UNSIGNED PRIMARY KEY,"
		"  type_id TINYINT UNSIGNED NOT NULL,"
		"  uri VARCHAR(255) NOT NULL,"

		"  FOREIGN KEY (id)"
		"    REFERENCES event_log(id)"
		"    ON DELETE CASCADE,"

		"  FOREIGN KEY (type_id)"
		"    REFERENCES message_type(id)"
		"    ON DELETE CASCADE"
		")";

	sql <<
		"CREATE TABLE IF NOT EXISTS event_auth_log ("
		"  id BIGINT UNSIGNED PRIMARY KEY,"
		"  method VARCHAR(255) NOT NULL,"
		"  origin VARCHAR(255) NOT NULL,"
		"  user_exists CHAR(1) NOT NULL,"

		"  FOREIGN KEY (id)"
		"    REFERENCES event_log(id)"
		"    ON DELETE CASCADE"
		")";

	sql <<
		"CREATE TABLE IF NOT EXISTS event_call_quality_statistics_log ("
		"  id BIGINT UNSIGNED PRIMARY KEY,"
		"  report TEXT NOT NULL,"

		"  FOREIGN KEY (id)"
		"    REFERENCES event_log(id)"
		"    ON DELETE CASCADE"
		")";

	// Set types values if necessary.
	sql << createEventTypesTable(backend);
	sql << createRegistrationTypesTable(backend);
	sql << createMessageTypesTable(backend);
}

void DataBaseEventLogWriter::writeEventLog(const std::shared_ptr<EventLog> &evlog, int typeId, soci::session &sql) {
	tm date;

	sql << "INSERT INTO event_log "
		"(type_id, sip_from, sip_to, user_agent, date, status_code, reason, completed, call_id)"
		"VALUES (:typeId, :sipFrom, :sipTo, :userAgent, :date, :statusCode, :reason, :completed, :callId)",
		use(typeId), use(sipDataToString(evlog->mFrom)), use(sipDataToString(evlog->mTo)),
		use(sipDataToString(evlog->mUA)), use(*gmtime_r(&evlog->mDate, &date)), use(evlog->mStatusCode),
		use(evlog->mReason), use(boolToSqlString(evlog->mCompleted)), use(evlog->mCallId);
}

// IMPORTANT
//
// See: https://github.com/SOCI/soci/blob/master/include/soci/session.h#L115
// It's possible to get the last inserted id in a table with a soci method:
// `get_last_insert_id`.
//
// But the returned value is a long. It's not sufficient for us.
// If 100 events are generated in one second, in 6 years we won't be able to use this value.
// So the choice here is to use the `LAST_INSERT_ID()` and `last_insert_rowid()`
// from MySQL and SQlite3 directly in SQL.

void DataBaseEventLogWriter::writeRegistrationLog(const std::shared_ptr<RegistrationLog> &evlog) {
	session sql(*mConnectionPool);
	transaction tr(sql);

	writeEventLog(evlog, SQL_REGISTRATION_EVENT_LOG_ID, sql);
	sql << mInsertReq[SQL_REGISTRATION_EVENT_LOG_ID],
		use(static_cast<int>(evlog->mType)), use(sipDataToString(evlog->mContacts));

	tr.commit();
}

void DataBaseEventLogWriter::writeCallLog(const std::shared_ptr<CallLog> &evlog) {
	session sql(*mConnectionPool);
	transaction tr(sql);

	writeEventLog(evlog, SQL_CALL_EVENT_LOG_ID, sql);
	sql << mInsertReq[SQL_CALL_EVENT_LOG_ID],
		use(boolToSqlString(evlog->mCancelled));

	tr.commit();
}

void DataBaseEventLogWriter::writeMessageLog(const std::shared_ptr<MessageLog> &evlog) {
	session sql(*mConnectionPool);
	transaction tr(sql);

	writeEventLog(evlog, SQL_MESSAGE_EVENT_LOG_ID, sql);
	sql << mInsertReq[SQL_MESSAGE_EVENT_LOG_ID],
		use(static_cast<int>(evlog->mReportType)), use(sipDataToString(evlog->mUri));

	tr.commit();
}

void DataBaseEventLogWriter::writeAuthLog(const std::shared_ptr<AuthLog> &evlog) {
	session sql(*mConnectionPool);
	transaction tr(sql);

	writeEventLog(evlog, SQL_AUTH_EVENT_LOG_ID, sql);
	sql << mInsertReq[SQL_AUTH_EVENT_LOG_ID],
		use(evlog->mMethod), use(sipDataToString(evlog->mOrigin)), use(boolToSqlString(evlog->mUserExists));

	tr.commit();
}

void DataBaseEventLogWriter::writeCallQualityStatisticsLog(const std::shared_ptr<CallQualityStatisticsLog> &evlog) {
	session sql(*mConnectionPool);
	transaction tr(sql);

	writeEventLog(evlog, SQL_CALL_QUALITY_EVENT_LOG_ID, sql);
	sql << mInsertReq[SQL_CALL_QUALITY_EVENT_LOG_ID],
		use(evlog->mReport);

	tr.commit();
}

void DataBaseEventLogWriter::writeEventFromQueue() {
	mMutex.lock();

	shared_ptr<EventLog> evlog = mListLogs.front();
	mListLogs.pop();

	mMutex.unlock();

	EventLog *ev = evlog.get();

	try {
		if (typeid(*ev) == typeid(RegistrationLog)) {
			writeRegistrationLog(static_pointer_cast<RegistrationLog>(evlog));
		} else if (typeid(*ev) == typeid(CallLog)) {
			writeCallLog(static_pointer_cast<CallLog>(evlog));
		} else if (typeid(*ev) == typeid(MessageLog)) {
			writeMessageLog(static_pointer_cast<MessageLog>(evlog));
		} else if (typeid(*ev) == typeid(AuthLog)) {
			writeAuthLog(static_pointer_cast<AuthLog>(evlog));
		} else if (typeid(*ev) == typeid(CallQualityStatisticsLog)) {
			writeCallQualityStatisticsLog(static_pointer_cast<CallQualityStatisticsLog>(evlog));
		}
	} catch (exception const &e) {
		LOGE("DataBaseEventLogWriter: event write error: %s", e.what());
	}
}

void DataBaseEventLogWriter::write(const std::shared_ptr<EventLog> &evlog) {
	mMutex.lock();

	if (mListLogs.size() < mMaxQueueSize) {
		mListLogs.push(evlog);
		mMutex.unlock();

		// Save event in database.
		if (!mThreadPool->Enqueue(bind(&DataBaseEventLogWriter::writeEventFromQueue, this))) {
			LOGE("DataBaseEventLogWriter: unable to enqueue event!");
		}
	} else {
		mMutex.unlock();
		LOGE("DataBaseEventLogWriter: too many events in queue! (%i)", (int)mMaxQueueSize);
	}
}

#endif
