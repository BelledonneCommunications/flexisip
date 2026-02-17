/*
     Flexisip, a flexible SIP proxy server with media capabilities.
     Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>

#include <soci/soci.h>

#include "utils/server/mysql/mysql-server.hh"
#include "utils/soci-helper.hh"
#include "utils/tmp-dir.hh"

namespace flexisip::tester {

class DatabaseBackend {
public:
	static constexpr std::string_view kTableName{"test"};

	virtual ~DatabaseBackend() = default;

	virtual void restart() = 0;
	virtual void stop() = 0;
	virtual void clear() = 0;
	virtual std::string_view getName() const = 0;
	virtual std::string getConnectionString() const = 0;
};

class ConnectionPool {
public:
	ConnectionPool(std::string_view dbName, std::string_view connectString, unsigned int poolSize = 1);

	soci::connection_pool& getPool() {
		return mPool;
	}

private:
	soci::connection_pool mPool;
};

template <typename DbBackend>
class DbTestHelper {
public:
	DbTestHelper(const std::shared_ptr<DbBackend>& backend,
	             const std::function<void(soci::session&)>& tableCreationRequest,
	             const unsigned int poolSize = 1)
	    : mDbBackend(backend), mConnectionPool(mDbBackend->getName(), mDbBackend->getConnectionString(), poolSize),
	      mClient(mConnectionPool.getPool()) {
		mClient.execute(tableCreationRequest);
	}

	std::shared_ptr<DbBackend> mDbBackend;
	ConnectionPool mConnectionPool;
	SociHelper mClient;
};

class SqLite3Backend : public DatabaseBackend {
public:
	SqLite3Backend() : mConnectionString(createDbFile().string()) {}

	void restart() override;
	void stop() override;
	void clear() override;

	std::string_view getName() const override {
		return kName;
	}

	std::string getConnectionString() const override {
		return mConnectionString;
	}

private:
	static constexpr std::string_view kName{"sqlite3"};
	static constexpr std::string_view kDirectoryName{"SqLite3Backend"};

	std::filesystem::path createDbFile() const;

	TmpDir mDirectory{kDirectoryName.data()};
	std::string mConnectionString;
};

class MySqlBackend : public DatabaseBackend {
public:
	MySqlBackend();

	void restart() override;
	void stop() override;
	void clear() override;

	bool isStopped() const {
		return !mServer;
	}

	std::string_view getName() const override {
		return kName;
	}

	std::string getConnectionString() const override {
		return mServer->connectionString();
	}

private:
	static constexpr std::string_view kName{"mysql"};

	std::unique_ptr<MysqlServer> mServer{std::make_unique<MysqlServer>()};
};

} // namespace flexisip::tester