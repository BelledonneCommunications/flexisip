/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "db/db-transaction.hh"

#include "eventlogs.hh"
#include "utils/thread/auto-thread-pool.hh"

using namespace std;

namespace flexisip {

namespace {
constexpr int SqlRegistrationEventLogId = 0;
constexpr int SqlCallEventLogId = 1;
constexpr int SqlMessageEventLogId = 2;
constexpr int SqlAuthEventLogId = 3;
constexpr int SqlCallQualityEventLogId = 4;
} // namespace

// redundant declaration (required for C++14 compatibility)
constexpr unsigned int DataBaseEventLogWriter::sRequiredSchemaVersion;

std::unique_ptr<DataBaseEventLogWriter::BackendInfo>
DataBaseEventLogWriter::BackendInfo::getBackendInfo(const std::string& backendName) {
	if (backendName == "mysql") return make_unique<MysqlInfo>();
	if (backendName == "sqlite3") return make_unique<Sqlite3Info>();
	if (backendName == "postgresql") return make_unique<PostgresqlInfo>();
	throw invalid_argument("invalid Soci backend for event log [" + backendName + "]");
}

static string sipDataToString(const url_t* url) {
	if (!url) {
		return string();
	}

	char tmp[256] = {};
	url_e(tmp, sizeof(tmp) - 1, url);
	return string(tmp);
}

static string sipDataToString(const sip_from_t* from) {
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

static string sipDataToString(const sip_user_agent_t* ua) {
	if (!ua) {
		return string();
	}

	char tmp[256] = {};
	sip_user_agent_e(tmp, sizeof(tmp) - 1, (msg_header_t*)ua, 0);
	return string(tmp);
}

static string sipDataToString(const sip_contact_t* contact) {
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

DataBaseEventLogWriter::BackendInfo::BackendInfo() noexcept : mInsertPrefix{"INSERT INTO"} {
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
	mTableNamesQuery =
	    "SELECT table_name AS \"TABLE_NAME\"FROM information_schema.tables WHERE table_schema = 'public'";
}

bool DataBaseEventLogWriter::BackendInfo::databaseIsEmpty(soci::session& session) {
	string tableName{};
	session << mTableNamesQuery, soci::into(tableName);
	return tableName.empty();
}

void DataBaseEventLogWriter::BackendInfo::createSchemaVersionTable(soci::session& session) {
	session << "CREATE TABLE IF NOT EXISTS schema_version (version BIGINT UNSIGNED) " + mTableOptions;
}

unsigned int DataBaseEventLogWriter::BackendInfo::getSchemaVersion(soci::session& session) {
	auto version = 0u;
	createSchemaVersionTable(session);
	session << "SELECT version FROM schema_version", soci::into(version);
	return version;
}

void DataBaseEventLogWriter::BackendInfo::setSchemaVersion(soci::session& session, unsigned int version) {
	createSchemaVersionTable(session);
	session << "DELETE FROM schema_version";
	session << "INSERT INTO schema_version (version) VALUES (" + to_string(version) + ")";
}

void DataBaseEventLogWriter::BackendInfo::initTables(soci::session& session) {
	// Create schema version table
	setSchemaVersion(session, sRequiredSchemaVersion);

	// Create types (event, registration, message).
	session << "CREATE TABLE IF NOT EXISTS event_type ("
	           "  id TINYINT UNSIGNED PRIMARY KEY,"
	           "  type VARCHAR(255) NOT NULL UNIQUE"
	           ")" +
	               mTableOptions;

	session << "CREATE TABLE IF NOT EXISTS registration_type ("
	           "  id TINYINT UNSIGNED PRIMARY KEY,"
	           "  type VARCHAR(255) NOT NULL UNIQUE"
	           ")" +
	               mTableOptions;

	session << "CREATE TABLE IF NOT EXISTS message_type ("
	           "  id TINYINT UNSIGNED PRIMARY KEY,"
	           "  type VARCHAR(255) NOT NULL UNIQUE"
	           ")" +
	               mTableOptions;

	// Main events table.
	session << "CREATE TABLE IF NOT EXISTS event_log ( id BIGINT UNSIGNED PRIMARY KEY " + mPrimaryKeyIncrementType +
	               ", "
	               "  type_id TINYINT UNSIGNED NOT NULL,"
	               "  sip_from VARCHAR(255) NOT NULL,"
	               "  sip_to VARCHAR(255) NOT NULL,"
	               "  user_agent VARCHAR(255) NOT NULL,"
	               "  date TIMESTAMP NOT NULL,"
	               "  status_code SMALLINT UNSIGNED NOT NULL,"
	               "  reason VARCHAR(255) NOT NULL,"
	               "  completed CHAR(1) NOT NULL,"
	               "  call_id VARCHAR(255) NOT NULL,"
	               "  priority VARCHAR(255) NOT NULL,"
	               "  FOREIGN KEY (type_id) REFERENCES event_type(id)"
	               ")" +
	               mTableOptions;

	// Specialized events table.
	session << "CREATE TABLE IF NOT EXISTS event_registration_log ("
	           "  id BIGINT UNSIGNED PRIMARY KEY,"
	           "  type_id TINYINT UNSIGNED NOT NULL,"
	           "  contacts VARCHAR(255) NOT NULL,"

	           "  FOREIGN KEY (id)"
	           "    REFERENCES event_log(id)"
	           "    ON DELETE CASCADE,"

	           "  FOREIGN KEY (type_id)"
	           "    REFERENCES registration_type(id)"
	           ")" +
	               mTableOptions;

	session << "CREATE TABLE IF NOT EXISTS event_call_log ("
	           "  id BIGINT UNSIGNED PRIMARY KEY,"
	           "  cancelled CHAR(1) NOT NULL,"

	           "  FOREIGN KEY (id)"
	           "    REFERENCES event_log(id)"
	           "    ON DELETE CASCADE"
	           ")" +
	               mTableOptions;

	session << "CREATE TABLE IF NOT EXISTS event_message_log ("
	           "  id BIGINT UNSIGNED PRIMARY KEY,"
	           "  type_id TINYINT UNSIGNED NOT NULL,"
	           "  uri VARCHAR(255) NOT NULL,"

	           "  FOREIGN KEY (id)"
	           "    REFERENCES event_log(id)"
	           "    ON DELETE CASCADE,"

	           "  FOREIGN KEY (type_id)"
	           "    REFERENCES message_type(id)"
	           "    ON DELETE CASCADE"
	           ")" +
	               mTableOptions;

	session << "CREATE TABLE IF NOT EXISTS event_auth_log ("
	           "  id BIGINT UNSIGNED PRIMARY KEY,"
	           "  method VARCHAR(255) NOT NULL,"
	           "  origin VARCHAR(255) NOT NULL,"
	           "  user_exists CHAR(1) NOT NULL,"

	           "  FOREIGN KEY (id)"
	           "    REFERENCES event_log(id)"
	           "    ON DELETE CASCADE"
	           ")" +
	               mTableOptions;

	session << "CREATE TABLE IF NOT EXISTS event_call_quality_statistics_log ("
	           "  id BIGINT UNSIGNED PRIMARY KEY,"
	           "  report TEXT NOT NULL,"

	           "  FOREIGN KEY (id)"
	           "    REFERENCES event_log(id)"
	           "    ON DELETE CASCADE"
	           ")" +
	               mTableOptions;

	// Set types values if necessary.
	session << mInsertPrefix + " event_type (id, type)" +
	               "  VALUES"
	               "  (0, 'Registration'),"
	               "  (1, 'Call'),"
	               "  (2, 'Message'),"
	               "  (3, 'Auth'),"
	               "  (4, 'QualityStatistics')" +
	               mOnConflictType;

	session << mInsertPrefix + " registration_type (id, type)" +
	               "  VALUES"
	               "  (0, 'Register'),"
	               "  (1, 'Unregister'),"
	               "  (2, 'Expired')" +
	               mOnConflictType;

	session << mInsertPrefix + " message_type (id, type)" +
	               "  VALUES"
	               "  (0, 'Received'),"
	               "  (1, 'Delivered')" +
	               mOnConflictType;
}

DataBaseEventLogWriter::DataBaseEventLogWriter(const std::string& backendString,
                                               const std::string& connectionString,
                                               unsigned int maxQueueSize,
                                               unsigned int nbThreadsMax)
    : mMaxQueueSize{maxQueueSize} {
	try {
		mConnectionPool = make_unique<soci::connection_pool>(nbThreadsMax);
		mThreadPool = make_unique<AutoThreadPool>(nbThreadsMax, mMaxQueueSize);

		for (unsigned int i = 0; i < nbThreadsMax; i++) {
			mConnectionPool->at(i).open(backendString, connectionString);
		}

		// Init tables.
		auto backend = BackendInfo::getBackendInfo(backendString);
		{
			unsigned int schemaVersion;
			soci::session session(*mConnectionPool);
			if (!backend->databaseIsEmpty(session) &&
			    (schemaVersion = backend->getSchemaVersion(session)) < sRequiredSchemaVersion) {
				LOGF("Event log database as an invalid schema version. Please backup and clear your current "
				     "database and start Flexisip again to generate an up-to-date schema. [currentVersion: %u, "
				     "requiredVersion: %u]",
				     schemaVersion, sRequiredSchemaVersion);
			}
			DB_TRANSACTION(&session) {
				backend->initTables(session);
				tr.commit();
			};
		}

		// Build insert requests.
		const auto& lastIdFunction = backend->lastIdFunction();
		mInsertReq[SqlRegistrationEventLogId] =
		    "INSERT INTO event_registration_log VALUES (" + lastIdFunction + ", :typeId, :contacts)";

		mInsertReq[SqlCallEventLogId] = "INSERT INTO event_call_log VALUES (" + lastIdFunction + ", :cancelled)";

		mInsertReq[SqlMessageEventLogId] =
		    "INSERT INTO event_message_log VALUES (" + lastIdFunction + ", :typeId, :uri)";

		mInsertReq[SqlAuthEventLogId] =
		    "INSERT INTO event_auth_log VALUES (" + lastIdFunction + ", :method, :origin, :userExists)";

		mInsertReq[SqlCallQualityEventLogId] =
		    "INSERT INTO event_call_quality_log VALUES (" + lastIdFunction + ", :report)";

		mIsReady = true;
	} catch (exception const& e) {
		LOGE("DataBaseEventLogWriter: could not create logger: %s", e.what());
	}
}

void DataBaseEventLogWriter::writeEventLog(soci::session& session, const EventLog& evlog, int typeId) {
	tm date;
	auto from = sipDataToString(evlog.getFrom());
	auto to = sipDataToString(evlog.getTo());
	auto ua = sipDataToString(evlog.getUserAgent());
	auto completed = boolToSqlString(evlog.isCompleted());

	session << "INSERT INTO event_log "
	           "(type_id, sip_from, sip_to, user_agent, date, status_code, reason, completed, call_id, priority)"
	           "VALUES (:typeId, :sipFrom, :sipTo, :userAgent, :date, :statusCode, :reason, :completed, :callId, "
	           ":priority)",
	    soci::use(typeId), soci::use(from), soci::use(to), soci::use(ua), soci::use(*gmtime_r(&evlog.getDate(), &date)),
	    soci::use(evlog.getStatusCode()), soci::use(evlog.getReason()), soci::use(completed),
	    soci::use(evlog.getCallId()), soci::use(evlog.getPriority());
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

void DataBaseEventLogWriter::writeRegistrationLog(const RegistrationLog& evlog) {
	soci::session session{*mConnectionPool};
	DB_TRANSACTION(&session) {
		auto contact = sipDataToString(evlog.getContacts());
		writeEventLog(session, evlog, SqlRegistrationEventLogId);
		session << mInsertReq[SqlRegistrationEventLogId], soci::use(int(evlog.getType())), soci::use(contact);
		tr.commit();
	};
}

void DataBaseEventLogWriter::writeCallLog(const CallLog& evlog) {
	soci::session session{*mConnectionPool};
	DB_TRANSACTION(&session) {
		auto cancelled = boolToSqlString(evlog.isCancelled());
		writeEventLog(session, evlog, SqlCallEventLogId);
		session << mInsertReq[SqlCallEventLogId], soci::use(cancelled);
		tr.commit();
	};
}

void DataBaseEventLogWriter::writeMessageLog(const MessageLog& evlog) {
	soci::session session{*mConnectionPool};
	DB_TRANSACTION(&session) {
		auto uri = sipDataToString(evlog.getUri());
		writeEventLog(session, evlog, SqlMessageEventLogId);
		session << mInsertReq[SqlMessageEventLogId], soci::use(int(evlog.getReportType())), soci::use(uri);
		tr.commit();
	};
}

void DataBaseEventLogWriter::writeAuthLog(const AuthLog& evlog) {
	soci::session session{*mConnectionPool};
	DB_TRANSACTION(&session) {
		auto origin = sipDataToString(evlog.getOrigin());
		auto userExists = boolToSqlString(evlog.userExists());
		writeEventLog(session, evlog, SqlAuthEventLogId);
		session << mInsertReq[SqlAuthEventLogId], soci::use(evlog.getMethod()), soci::use(origin),
		    soci::use(userExists);
		tr.commit();
	};
}

void DataBaseEventLogWriter::writeCallQualityStatisticsLog(const CallQualityStatisticsLog& evlog) {
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

} // namespace flexisip
