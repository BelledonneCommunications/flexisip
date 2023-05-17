/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include "event-log-writer.hh"

#include <mutex>
#include <queue>

#include <soci/soci.h>

#include "eventlogs/events/event-log-write-dispatcher.hh"
#include "utils/thread/thread-pool.hh"

namespace flexisip {

class EventLog;

class DataBaseEventLogWriter : public EventLogWriter {
public:
	DataBaseEventLogWriter(const std::string& backendString,
	                       const std::string& connectionString,
	                       unsigned int maxQueueSize,
	                       unsigned int nbThreadsMax);

	void write(const std::shared_ptr<const EventLogWriteDispatcher>&) override;
	bool isReady() const {
		return mIsReady;
	}

private:
	class BackendInfo {
	public:
		BackendInfo() noexcept;
		virtual ~BackendInfo() = default;

		const std::string& tableOptions() const noexcept {
			return mTableOptions;
		}
		const std::string& primaryKeyIncrementType() const noexcept {
			return mPrimaryKeyIncrementType;
		}
		const std::string& insertPrefix() const noexcept {
			return mInsertPrefix;
		}
		const std::string& lastIdFunction() const noexcept {
			return mLastIdFunction;
		}
		const std::string& onConfflictType() const noexcept {
			return mOnConflictType;
		}
		const std::string& tableNamesQuery() const noexcept {
			return mTableNamesQuery;
		}

		bool databaseIsEmpty(soci::session& session);
		void createSchemaVersionTable(soci::session& session);
		unsigned int getSchemaVersion(soci::session& session);
		void setSchemaVersion(soci::session& session, unsigned int version);
		void initTables(soci::session& session);

		static std::unique_ptr<BackendInfo> getBackendInfo(const std::string& backendName);

	protected:
		std::string mTableOptions{};
		std::string mInsertPrefix{};
		std::string mPrimaryKeyIncrementType{};
		std::string mLastIdFunction{};
		std::string mOnConflictType{};
		std::string mTableNamesQuery{};
	};

	class Sqlite3Info : public BackendInfo {
	public:
		Sqlite3Info() noexcept;
	};

	class MysqlInfo : public BackendInfo {
	public:
		MysqlInfo() noexcept;
	};

	class PostgresqlInfo : public BackendInfo {
	public:
		PostgresqlInfo() noexcept;
	};

	static void writeEventLog(soci::session& session, const EventLog&, int typeId);

	void write(const RegistrationLog&) override;
	void write(const CallLog&) override;
	void write(const MessageLog&) override;
	void write(const AuthLog&) override;
	void write(const CallQualityStatisticsLog&) override;

	void writeEventFromQueue();

	bool mIsReady{false};
	std::mutex mMutex{};
	std::queue<std::shared_ptr<const EventLogWriteDispatcher>> mListLogs{};

	std::unique_ptr<soci::connection_pool> mConnectionPool{};
	std::unique_ptr<ThreadPool> mThreadPool{};

	unsigned int mMaxQueueSize{0};

	std::array<std::string, 5> mInsertReq{};

	static constexpr unsigned int sRequiredSchemaVersion = 1;
};

} // namespace flexisip
