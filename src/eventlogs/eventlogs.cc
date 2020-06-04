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

#include <flexisip/configmanager.hh>
#include "db/db-transaction.hh"
#include <flexisip/eventlogs.hh>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <typeinfo>

#include "utils/string-utils.hh"

using namespace std;

namespace flexisip {

template<typename T, typename... ArgT>
unique_ptr<T> make_unique(ArgT&&... args) {
	return unique_ptr<T>{new T{std::forward<ArgT>(args)...}};
}

EventLog::Init EventLog::evStaticInit;

EventLog::Init::Init() {
	ConfigItemDescriptor items[] = {
		{Boolean, "enabled", "Enable event logs.", "false"},
		{String, "logger", "Define logger for storing logs. It supports \"filesystem\" and \"database\".",
		 "filesystem"},
		{String, "filesystem-directory", "Directory where event logs are written as a filesystem (case when filesystem "
		 "output is choosed).",
		 "/var/log/flexisip"},
		{String, "database-backend", "Choose the type of backend that Soci will use for the connection.\n"
		 "Depending on your Soci package and the modules you installed, the supported databases are:"
		 "`mysql`, `sqlite3` and `postgresql`",
		 "mysql"},
		{String, "database-connection-string", "The configuration parameters of the backend.\n"
		 "The basic format is \"key=value key2=value2\". For a mysql backend, this "
		 "is a valid config: \"db=mydb user=user password='pass' host=myhost.com\".\n"
		 "Please refer to the Soci documentation of your backend, for instance: "
		 "http://soci.sourceforge.net/doc/master/backends/#supported-backends-and-features",
		 "db='mydb' user='myuser' password='mypass' host='myhost.com'"},
		{Integer, "database-max-queue-size",
		 "Amount of queries that will be allowed to be queued before bailing password requests.\n"
		 "This value should be chosen accordingly with 'database-nb-threads-max', so that you have a "
		 "coherent behavior.\n"
		 "This limit is here mainly as a safeguard against out-of-control growth of the queue in the event of a flood "
		 "or big delays in the database backend.",
		 "100"},
		{Integer, "database-nb-threads-max", "Maximum number of threads for writing in database.\n"
		 "If you get a `database is locked` error with sqlite3, you must set this variable to 1.",
		 "10"},

		 // Deprecated parameters
		{String, "dir", "Directory where event logs are written as a filesystem (case when filesystem output is choosed).",
		 "/var/log/flexisip"},
		config_item_end};

	GenericStruct *ev = new GenericStruct(
		"event-logs",
		"Event logs contain per domain and user information about processed registrations, calls and messages.\n"
		"See: https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/Event%20logs%20and%20queries/ for architecture and queries.",
		0
	);
	GenericManager::get()->getRoot()->addChild(ev);
	ev->addChildrenValues(items);
	ev->get<ConfigString>("dir")->setDeprecated({"2020-02-19", "2.0.0", "Replaced by 'filesystem-directory'"});
}

EventLog::EventLog(const sip_t *sip):
	mFrom{sip_from_dup(mHome.home(), sip->sip_from)},
	mTo{sip_to_dup(mHome.home(), sip->sip_to)},
	mUA{sip->sip_user_agent ? sip_user_agent_dup(mHome.home(), sip->sip_user_agent) : nullptr},
	mDate{time(nullptr)},
	mCallId{sip->sip_call_id->i_id} {}

RegistrationLog::RegistrationLog(const sip_t *sip, const sip_contact_t *contacts) : EventLog(sip) {
	mType = (sip->sip_expires && sip->sip_expires->ex_delta == 0)
		? Type::Unregister // REVISIT not 100% exact.
		: Type::Register;

	mContacts = sip_contact_dup(mHome.home(), contacts);
}

void RegistrationLog::write(EventLogWriter &writer) const {
	writer.writeRegistrationLog(*this);
}

void CallLog::write(EventLogWriter &writer) const {
	writer.writeCallLog(*this);
}

void MessageLog::write(EventLogWriter &writer) const {
	writer.writeMessageLog(*this);
}

AuthLog::AuthLog(const sip_t *sip, bool userExists)
:
	EventLog(sip),
	mMethod{sip->sip_request->rq_method_name},
	mUserExists{userExists}
{
	setOrigin(sip->sip_via);
}

void AuthLog::setOrigin(const sip_via_t *via) {
	const char *protocol = strchr(via->v_protocol, '/') + 1;
	const char *port = via->v_rport ? via->v_rport : via->v_port;
	const char *ip = via->v_received ? via->v_received : via->v_host;

	protocol = strchr(protocol, '/') + 1;

	mOrigin = url_format(mHome.home(), "sip:%s", ip);
	if (!mOrigin){
		LOGE("AuthLog: invalid via with host %s", ip);
		mOrigin = url_format(mHome.home(), "sip:invalid.host");
	}
	if (port){
		mOrigin->url_port = su_strdup(mHome.home(), port);
	}
	if (protocol){
		mOrigin->url_params = su_sprintf(mHome.home(), "transport=%s", protocol);
	}
}

void AuthLog::write(EventLogWriter &writer) const {
	writer.writeAuthLog(*this);
}

CallQualityStatisticsLog::CallQualityStatisticsLog(const sip_t *sip)
:
	EventLog(sip),
	mReport{sip->sip_payload && sip->sip_payload->pl_data ? sip->sip_payload->pl_data : nullptr} {}

void CallQualityStatisticsLog::write(EventLogWriter &writer) const {
	writer.writeCallQualityStatisticsLog(*this);
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

static ostream &operator<<(ostream &ostr, const sip_user_agent_t *ua) {
	char tmp[500] = {0};
	sip_user_agent_e(tmp, sizeof(tmp) - 1, (msg_header_t *)ua, 0);
	ostr << tmp;
	return ostr;
}

static ostream &operator<<(ostream &ostr, const url_t *url) {
	char tmp[500] = {0};
	url_e(tmp, sizeof(tmp) - 1, url);
	ostr << tmp;
	return ostr;
}

static ostream &operator<<(ostream &ostr, const sip_from_t *from) {
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

static std::ostream &operator<<(std::ostream &ostr, const PrettyTime &t) {
	char tmp[128] = {0};
	int len;
	ctime_r(&t._t, tmp);
	len = strlen(tmp);
	if (tmp[len - 1] == '\n')
		tmp[len - 1] = '\0'; // because ctime_r adds a '\n'
	ostr << tmp;
	return ostr;
}

static std::ostream &operator<<(std::ostream &ostr, RegistrationLog::Type type) {
	switch (type) {
		case RegistrationLog::Type::Register:
			ostr << "Registered";
			break;
		case RegistrationLog::Type::Unregister:
			ostr << "Unregistered";
			break;
		case RegistrationLog::Type::Expired:
			ostr << "Registration expired";
			break;
	}
	return ostr;
}

static std::ostream &operator<<(std::ostream &ostr, MessageLog::ReportType type) {
	switch (type) {
		case MessageLog::ReportType::ReceivedFromUser:
			ostr << "Received from user";
			break;
		case MessageLog::ReportType::DeliveredToUser:
			ostr << "Delivered to user";
			break;
	}
	return ostr;
}

FilesystemEventLogWriter::FilesystemEventLogWriter(const std::string &rootpath) : mRootPath(rootpath) {
	if (rootpath[0] != '/') {
		LOGE("Path for event log writer must be absolute.");
		return;
	}
	if (!createDirectoryIfNotExist(rootpath.c_str()))
		return;

	mIsReady = true;
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

void FilesystemEventLogWriter::writeRegistrationLog(const RegistrationLog &rlog) {
	const char *label = "registers";
	int fd = openPath(rlog.getFrom()->a_url, label, rlog.getDate());
	if (fd == -1)
		return;

	ostringstream msg;
	msg << PrettyTime(rlog.getDate()) << ": " << rlog.getType() << " " << rlog.getFrom();
	if (rlog.getContacts())
		msg << " (" << rlog.getContacts()->m_url << ") ";
	if (rlog.getUserAgent())
		msg << rlog.getUserAgent();
	msg << endl;

	if (::write(fd, msg.str().c_str(), msg.str().size()) == -1) {
		LOGE("Fail to write registration log: %s", strerror(errno));
	}
	close(fd);
	if (rlog.getStatusCode() >= 300) {
		writeErrorLog(rlog, label, msg.str());
	}
}

void FilesystemEventLogWriter::writeCallLog(const CallLog &calllog) {
	const char *label = "calls";
	int fd1 = openPath(calllog.getFrom()->a_url, label, calllog.getDate());
	int fd2 = openPath(calllog.getTo()->a_url, label, calllog.getDate());

	ostringstream msg;

	msg << PrettyTime(calllog.getDate()) << ": " << calllog.getFrom() << " --> " << calllog.getTo() << " ";
	if (calllog.isCancelled())
		msg << "Cancelled";
	else
		msg << calllog.getStatusCode() << " " << calllog.getReason();
	msg << endl;

	if (fd1 == -1 || ::write(fd1, msg.str().c_str(), msg.str().size()) == -1) {
		LOGE("Fail to write registration log: %s", strerror(errno));
	}
	// Avoid to write logs for users that possibly do not exist.
	// However the error will be reported in the errors directory.
	if (calllog.getStatusCode() != 404) {
		if (fd2 == -1 || ::write(fd2, msg.str().c_str(), msg.str().size()) == -1) {
			LOGE("Fail to write registration log: %s", strerror(errno));
		}
	}
	if (fd1 != -1)
		close(fd1);
	if (fd2 != -1)
		close(fd2);
	if (calllog.getStatusCode() >= 300) {
		writeErrorLog(calllog, label, msg.str());
	}
}

void FilesystemEventLogWriter::writeMessageLog(const MessageLog &mlog) {
	const char *label = "messages";
	ostringstream msg;

	msg << PrettyTime(mlog.getDate()) << ": " << mlog.getReportType() << " id:" << std::hex << mlog.getCallId() << " " <<
		std::dec;
	msg << mlog.getFrom() << " --> " << mlog.getTo();
	if (mlog.getUri())
		msg << " (" << mlog.getUri() << ") ";
	msg << mlog.getStatusCode() << " " << mlog.getReason() << endl;

	if (mlog.getReportType() == MessageLog::ReportType::ReceivedFromUser){
		int fd = openPath(mlog.getFrom()->a_url, label, mlog.getDate());
		if (fd != -1){
			if (::write(fd, msg.str().c_str(), msg.str().size()) == -1) {
				LOGE("Fail to write message log: %s", strerror(errno));
			}
			close(fd);
		}
	}else { //MessageLog::DeliveredToUser
		/*the event is added into the sender's log file and the receiver's log file, for convenience*/
		int fd = openPath(mlog.getFrom()->a_url, label, mlog.getDate());
		if (fd != -1){
			if (::write(fd, msg.str().c_str(), msg.str().size()) == -1) {
				LOGE("Fail to write message log: %s", strerror(errno));
			}
			close(fd);
		}
		// Avoid to write logs for users that possibly do not exist.
		// However the error will be reported in the errors directory.
		if (mlog.getStatusCode() != 404){
			fd = openPath(mlog.getTo()->a_url, label, mlog.getDate());
			if (fd != -1){
				if (::write(fd, msg.str().c_str(), msg.str().size()) == -1) {
					LOGE("Fail to write message log: %s", strerror(errno));
				}
				close(fd);
			}
		}
	}
	if (mlog.getStatusCode() >= 300) {
		writeErrorLog(mlog, label, msg.str());
	}
}

void FilesystemEventLogWriter::writeCallQualityStatisticsLog(const CallQualityStatisticsLog &mlog) {
	const char *label = "statistics_reports";
	int fd = openPath(mlog.getFrom()->a_url, label, mlog.getDate());
	if (fd == -1)
		return;
	ostringstream msg;

	msg << PrettyTime(mlog.getDate()) << " ";
	msg << mlog.getFrom() << " --> " << mlog.getTo() << " ";
	msg << mlog.getStatusCode() << " " << mlog.getReason() << ": ";
	msg << mlog.getReport() << endl;

	if (::write(fd, msg.str().c_str(), msg.str().size()) == -1) {
		LOGE("Fail to write registration log: %s", strerror(errno));
	}

	close(fd);
	if (mlog.getStatusCode() >= 300) {
		writeErrorLog(mlog, label, msg.str());
	}
}

void FilesystemEventLogWriter::writeAuthLog(const AuthLog &alog) {
	const char *label = "auth";
	ostringstream msg;
	msg << PrettyTime(alog.getDate()) << " " << alog.getMethod() << " " << alog.getFrom();
	if (alog.getOrigin())
		msg << " (" << alog.getOrigin() << ") ";
	if (alog.getUserAgent())
		msg << " (" << alog.getUserAgent() << ") ";
	msg << " --> " << alog.getTo() << " ";
	msg << alog.getStatusCode() << " " << alog.getReason() << endl;

	if (alog.userExists()) {
		int fd = openPath(alog.getFrom()->a_url, label, alog.getDate());
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
	const EventLog &log, const char *kind,
	const std::string &logstr
) {
	int fd = openPath(NULL, kind, log.getDate(), log.getStatusCode());
	if (fd == -1)
		return;
	if (::write(fd, logstr.c_str(), logstr.size()) == -1) {
		LOGE("Fail to write error log: %s", strerror(errno));
	}
	close(fd);
}

#if ENABLE_SOCI

namespace {
	constexpr int SqlRegistrationEventLogId = 0;
	constexpr int SqlCallEventLogId = 1;
	constexpr int SqlMessageEventLogId = 2;
	constexpr int SqlAuthEventLogId = 3;
	constexpr int SqlCallQualityEventLogId = 4;
}

std::unique_ptr<DataBaseEventLogWriter::BackendInfo> DataBaseEventLogWriter::BackendInfo::getBackendInfo(const std::string &backendName) {
	if (backendName == "mysql") return make_unique<MysqlInfo>();
	if (backendName == "sqlite3") return make_unique<Sqlite3Info>();
	if (backendName == "postgresql") return make_unique<PostgresqlInfo>();
	throw invalid_argument("invalid Soci backend for event log [" + backendName + "]");
}

static string sipDataToString(const url_t *url) {
	if (!url) {
		return string();
	}

	char tmp[256] = {};
	url_e(tmp, sizeof(tmp) - 1, url);
	return string(tmp);
}

static string sipDataToString(const sip_from_t *from) {
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

static string sipDataToString(const sip_user_agent_t *ua) {
	if (!ua) {
		return string();
	}

	char tmp[256] = {};
	sip_user_agent_e(tmp, sizeof(tmp) - 1, (msg_header_t *)ua, 0);
	return string(tmp);
}

static string sipDataToString(const sip_contact_t *contact) {
	if (!contact) {
		return string();
	}

	return sipDataToString(contact->m_url);
}

// `bool` type is not supported by `soci`.
// Also, for future uses, no sql column is a bool type in this code.
// A Oracle database doesn't support this type. It's better to use
// a `CHAR(1)` instead with a `Y`/`N` value.
static string boolToSqlString(bool value) {
	return value ? "Y" : "N";
}

DataBaseEventLogWriter::BackendInfo::BackendInfo() noexcept:
	mTinyUInt{"TINYINT UNSIGNED"},
	mBigUInt{"BIGINT UNSIGNED"},
	mDateTime{"TIMESTAMP"},
	mInsertPrefix{"INSERT INTO"}
{
	mCreateVersionTableQuery =
		"CREATE TABLE IF NOT EXISTS schema_version (version " + bigUIInt() + ") " + tableOptions();
}

DataBaseEventLogWriter::Sqlite3Info::Sqlite3Info() noexcept : BackendInfo{} {
	mInsertPrefix = "INSERT OR IGNORE INTO";
	mLastIdFunction = "last_insert_rowid()";
	mTableNamesQuery = "SELECT name AS \"TABLE_NAME\" FROM sqlite_master WHERE type = 'table'";
}

DataBaseEventLogWriter::MysqlInfo::MysqlInfo() noexcept : BackendInfo{} {
	mTableOptions = "ENGINE=INNODB DEFAULT CHARSET=utf8";
	mPrimaryKeyIncrementType = "AUTO_INCREMENT";
	mLastIdFunction = "LAST_INSERT_ID()";
	mOnConflictType = "ON DUPLICATE KEY UPDATE type = VALUES(type)";
	mTableNamesQuery = "SHOW TABLES";
}

DataBaseEventLogWriter::PostgresqlInfo::PostgresqlInfo() noexcept : BackendInfo{} {
	mPrimaryKeyIncrementType = "AUTO_INCREMENT";
	mLastIdFunction = "lastval()";
	mOnConflictType = "ON CONFLICT (id) DO UPDATE SET type = EXCLUDED.type";
	mTableNamesQuery = "SELECT table_name AS \"TABLE_NAME\"FROM information_schema.tables WHERE table_schema = 'public'";
}

DataBaseEventLogWriter::DataBaseEventLogWriter(
	const std::string &backendString,
	const std::string &connectionString,
	unsigned int maxQueueSize,
	unsigned int nbThreadsMax
) :
	mMaxQueueSize{maxQueueSize}
{
	try {
		mConnectionPool = make_unique<soci::connection_pool>(nbThreadsMax);
		mThreadPool = make_unique<ThreadPool>(nbThreadsMax, maxQueueSize);

		for (unsigned int i = 0; i < nbThreadsMax; i++) {
			mConnectionPool->at(i).open(backendString, connectionString);
		}

		// Init tables.
		auto backend = BackendInfo::getBackendInfo(backendString);
		{
			unsigned int schemaVersion;
			soci::session session(*mConnectionPool);
			if (!databaseIsEmpty(session, *backend)
				&& (schemaVersion = getSchemaVersion(session, *backend)) < sRequiredSchemaVersion)
			{
				LOGF("Event log database as an invalid schema version. Please backup and clear your current "
					"database and start Flexisip again to generate an up-to-date schema. [currentVersion: %u, "
					"requiredVersion: %u]", schemaVersion, sRequiredSchemaVersion);
			}
			DB_TRANSACTION(&session) {
				initTables(session, *backend);
				tr.commit();
			};
		}

		// Build insert requests.
		const auto &lastIdFunction = backend->lastIdFunction();
		mInsertReq[SqlRegistrationEventLogId] =
			"INSERT INTO event_registration_log VALUES (" + lastIdFunction + ", :typeId, :contacts)";

		mInsertReq[SqlCallEventLogId] =
			"INSERT INTO event_call_log VALUES (" + lastIdFunction + ", :cancelled)";

		mInsertReq[SqlMessageEventLogId] =
			"INSERT INTO event_message_log VALUES (" + lastIdFunction + ", :typeId, :uri)";

		mInsertReq[SqlAuthEventLogId] =
			"INSERT INTO event_auth_log VALUES (" +	lastIdFunction + ", :method, :origin, :userExists)";

		mInsertReq[SqlCallQualityEventLogId] =
			"INSERT INTO event_call_quality_log VALUES (" + lastIdFunction + ", :report)";

		mIsReady = true;
	} catch (exception const &e) {
		LOGE("DataBaseEventLogWriter: could not create logger: %s", e.what());
	}
}

bool DataBaseEventLogWriter::databaseIsEmpty(soci::session &session, const BackendInfo &backend) {
	string tableName{};
	DB_TRANSACTION(&session) {
		session << backend.tableNamesQuery() , soci::into(tableName);
		tr.commit();
	};
	return tableName.empty();
}

unsigned int DataBaseEventLogWriter::getSchemaVersion(soci::session &session, const BackendInfo &backend) {
	auto version = 0u;
	DB_TRANSACTION(&session) {
		session << backend.createVersionTableQuery();
		session << "SELECT version FROM schema_version" , soci::into(version);
		tr.commit();
	};
	return version;
}

void DataBaseEventLogWriter::setSchemaVersion(soci::session &session, const BackendInfo &backend, unsigned int version) {
	session << backend.createVersionTableQuery();
	session << "DELETE FROM schema_version";
	session << "INSERT INTO schema_version VALUE (" + to_string(version) + ")";
}

void DataBaseEventLogWriter::initTables(soci::session &session, const BackendInfo &backend) {
	const auto &tableOptions = backend.tableOptions();
	const auto &tinyUnsignedInt = backend.tinyUIInt();
	const auto &bigUnsignedInt = backend.bigUIInt();
	const auto &timestamp = backend.dateTime();

	// Create schema version table
	setSchemaVersion(session, backend, sRequiredSchemaVersion);

	// Create types (event, registration, message).
	session <<
		"CREATE TABLE IF NOT EXISTS event_type ("
		"  id " + tinyUnsignedInt + " PRIMARY KEY,"
		"  type VARCHAR(255) NOT NULL UNIQUE"
		")" + tableOptions;

	session <<
		"CREATE TABLE IF NOT EXISTS registration_type ("
		"  id " + tinyUnsignedInt + " PRIMARY KEY,"
		"  type VARCHAR(255) NOT NULL UNIQUE"
		")" + tableOptions;

	session <<
		"CREATE TABLE IF NOT EXISTS message_type ("
		"  id " + tinyUnsignedInt + " PRIMARY KEY,"
		"  type VARCHAR(255) NOT NULL UNIQUE"
		")" + tableOptions;

	// Main events table.
	session <<
		"CREATE TABLE IF NOT EXISTS event_log ( id BIGINT UNSIGNED PRIMARY KEY " + backend.primaryKeyIncrementType() + " DESC, "
		"  type_id " + tinyUnsignedInt + " NOT NULL,"
		"  sip_from VARCHAR(255) NOT NULL,"
		"  sip_to VARCHAR(255) NOT NULL,"
		"  user_agent VARCHAR(255) NOT NULL,"
		"  date " + timestamp + " NOT NULL,"
		"  status_code SMALLINT UNSIGNED NOT NULL,"
		"  reason VARCHAR(255) NOT NULL,"
		"  completed CHAR(1) NOT NULL,"
		"  call_id VARCHAR(255) NOT NULL,"
		"  priority VARCHAR(255) NOT NULL,"
		"  FOREIGN KEY (type_id)"
		"    REFERENCES event_type(id)"
		")" + tableOptions;

	// Specialized events table.
	session <<
		"CREATE TABLE IF NOT EXISTS event_registration_log ("
		"  id " + bigUnsignedInt + " PRIMARY KEY DESC,"
		"  type_id " + tinyUnsignedInt + " NOT NULL,"
		"  contacts VARCHAR(255) NOT NULL,"

		"  FOREIGN KEY (id)"
		"    REFERENCES event_log(id)"
		"    ON DELETE CASCADE,"

		"  FOREIGN KEY (type_id)"
		"    REFERENCES registration_type(id)"
		")" + tableOptions;

	session <<
		"CREATE TABLE IF NOT EXISTS event_call_log ("
		"  id " + bigUnsignedInt + " PRIMARY KEY DESC,"
		"  cancelled CHAR(1) NOT NULL,"

		"  FOREIGN KEY (id)"
		"    REFERENCES event_log(id)"
		"    ON DELETE CASCADE"
		")" + tableOptions;

	session <<
		"CREATE TABLE IF NOT EXISTS event_message_log ("
		"  id " + bigUnsignedInt + " PRIMARY KEY DESC,"
		"  type_id " + tinyUnsignedInt + " NOT NULL,"
		"  uri VARCHAR(255) NOT NULL,"

		"  FOREIGN KEY (id)"
		"    REFERENCES event_log(id)"
		"    ON DELETE CASCADE,"

		"  FOREIGN KEY (type_id)"
		"    REFERENCES message_type(id)"
		"    ON DELETE CASCADE"
		")" + tableOptions;

	session <<
		"CREATE TABLE IF NOT EXISTS event_auth_log ("
		"  id " + bigUnsignedInt + " PRIMARY KEY DESC,"
		"  method VARCHAR(255) NOT NULL,"
		"  origin VARCHAR(255) NOT NULL,"
		"  user_exists CHAR(1) NOT NULL,"

		"  FOREIGN KEY (id)"
		"    REFERENCES event_log(id)"
		"    ON DELETE CASCADE"
		")" + tableOptions;

	session <<
		"CREATE TABLE IF NOT EXISTS event_call_quality_statistics_log ("
		"  id " + bigUnsignedInt + " PRIMARY KEY DESC,"
		"  report TEXT NOT NULL,"

		"  FOREIGN KEY (id)"
		"    REFERENCES event_log(id)"
		"    ON DELETE CASCADE"
		")" + tableOptions;

	// Set types values if necessary.
	const auto &insertPrefix = backend.insertPrefix();
	const auto &onConflictType = backend.onConfflictType();

	session << insertPrefix + " event_type (id, type)" +
		"  VALUES"
		"  (0, 'Registration'),"
		"  (1, 'Call'),"
		"  (2, 'Message'),"
		"  (3, 'Auth'),"
		"  (4, 'QualityStatistics')" + onConflictType;

	session << insertPrefix + " registration_type (id, type)" +
		"  VALUES"
		"  (0, 'Register'),"
		"  (1, 'Unregister'),"
		"  (2, 'Expired')" + onConflictType;

	session << insertPrefix + " message_type (id, type)" +
		"  VALUES"
		"  (0, 'Received'),"
		"  (1, 'Delivered')" + onConflictType;
}

void DataBaseEventLogWriter::writeEventLog(soci::session &session, const EventLog &evlog, int typeId) {
	tm date;
	auto from = sipDataToString(evlog.getFrom());
	auto to = sipDataToString(evlog.getTo());
	auto ua = sipDataToString(evlog.getUserAgent());
	auto completed = boolToSqlString(evlog.isCompleted());

	session << "INSERT INTO event_log "
		"(type_id, sip_from, sip_to, user_agent, date, status_code, reason, completed, call_id, priority)"
		"VALUES (:typeId, :sipFrom, :sipTo, :userAgent, :date, :statusCode, :reason, :completed, :callId, :priority)",
		soci::use(typeId), soci::use(from), soci::use(to),
		soci::use(ua), soci::use(*gmtime_r(&evlog.getDate(), &date)), soci::use(evlog.getStatusCode()),
		soci::use(evlog.getReason()), soci::use(completed), soci::use(evlog.getCallId()), soci::use(evlog.getPriority());
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

void DataBaseEventLogWriter::writeRegistrationLog(const RegistrationLog &evlog) {
	soci::session session{*mConnectionPool};
	DB_TRANSACTION(&session) {
		auto contact = sipDataToString(evlog.getContacts());
		writeEventLog(session, evlog, SqlRegistrationEventLogId);
		session << mInsertReq[SqlRegistrationEventLogId], soci::use(int(evlog.getType())), soci::use(contact);
		tr.commit();
	};
}

void DataBaseEventLogWriter::writeCallLog(const CallLog &evlog) {
	soci::session session{*mConnectionPool};
	DB_TRANSACTION(&session) {
		auto cancelled = boolToSqlString(evlog.isCancelled());
		writeEventLog(session, evlog, SqlCallEventLogId);
		session << mInsertReq[SqlCallEventLogId], soci::use(cancelled);
		tr.commit();
	};
}

void DataBaseEventLogWriter::writeMessageLog(const MessageLog &evlog) {
	soci::session session{*mConnectionPool};
	DB_TRANSACTION(&session) {
		auto uri = sipDataToString(evlog.getUri());
		writeEventLog(session, evlog, SqlMessageEventLogId);
		session << mInsertReq[SqlMessageEventLogId], soci::use(int(evlog.getReportType())), soci::use(uri);
		tr.commit();
	};
}

void DataBaseEventLogWriter::writeAuthLog(const AuthLog &evlog) {
	soci::session session{*mConnectionPool};
	DB_TRANSACTION(&session) {
		auto origin = sipDataToString(evlog.getOrigin());
		auto userExists = boolToSqlString(evlog.userExists());
		writeEventLog(session, evlog, SqlAuthEventLogId);
		session << mInsertReq[SqlAuthEventLogId], soci::use(evlog.getMethod()), soci::use(origin), soci::use(userExists);
		tr.commit();
	};
}

void DataBaseEventLogWriter::writeCallQualityStatisticsLog(const CallQualityStatisticsLog &evlog) {
	soci::session session{*mConnectionPool};
	DB_TRANSACTION(&session) {
		writeEventLog(session, evlog, SqlCallQualityEventLogId);
		session << mInsertReq[SqlCallQualityEventLogId], soci::use(evlog.getReport());
		tr.commit();
	};
}

void DataBaseEventLogWriter::writeEventFromQueue() {
	mMutex.lock();
	auto evlog = mListLogs.front();
	mListLogs.pop();
	mMutex.unlock();
	evlog->write(*this);
}

void DataBaseEventLogWriter::write(std::shared_ptr<const EventLog> evlog) {
	mMutex.lock();

	if (mListLogs.size() < mMaxQueueSize) {
		mListLogs.push(move(evlog));
		mMutex.unlock();

		// Save event in database.
		if (!mThreadPool->run(bind(&DataBaseEventLogWriter::writeEventFromQueue, this))) {
			LOGE("DataBaseEventLogWriter: unable to enqueue event!");
		}
	} else {
		mMutex.unlock();
		LOGE("DataBaseEventLogWriter: too many events in queue! (%i)", (int)mMaxQueueSize);
	}
}

} // flexisip namespace

#endif
