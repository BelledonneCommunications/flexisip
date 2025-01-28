/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "event-log-writer.hh"

#include <array>
#include <mutex>
#include <queue>
#include <string>

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

	static constexpr unsigned int sRequiredSchemaVersion = 1;
	static constexpr std::string_view mLogPrefix{"DataBaseEventLogWriter"};

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
};

} // namespace flexisip