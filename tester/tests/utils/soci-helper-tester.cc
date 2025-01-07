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

#include "utils/soci-helper.hh"

#include <filesystem>
#include <fstream>

#include "flexisip/logmanager.hh"

#include "utils/mysql-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

using namespace std;

namespace flexisip::tester {

class DatabaseBackend {
public:
	virtual ~DatabaseBackend() = default;

	virtual void restart() = 0;
	virtual void stop() = 0;
	virtual string_view getName() const = 0;
	virtual string getConnectionString() const = 0;
};

class MySqlDatabaseBackend : public DatabaseBackend {
public:
	MySqlDatabaseBackend() {
		mServer->waitReady();
	}

	void restart() override {
		mServer->restart();
	}

	void stop() override {
		mServer.reset();
	}

	string_view getName() const override {
		return kName;
	}

	string getConnectionString() const override {
		return mServer->connectionString();
	}

private:
	static constexpr string_view kName{"mysql"};
	unique_ptr<MysqlServer> mServer = make_unique<MysqlServer>();
};

class Sqlite3DatabaseBackend : public DatabaseBackend {
public:
	Sqlite3DatabaseBackend() : mDirectory(kDirectoryName.data()), mConnectionString(createDbFile().string()) {
	}

	void restart() override {
		stop();
		mDirectory = TmpDir{kDirectoryName.data()};
		mConnectionString = createDbFile().string();
	}

	void stop() override {
		filesystem::remove_all(mDirectory.path());
	}

	string_view getName() const override {
		return kName;
	}

	string getConnectionString() const override {
		return mConnectionString;
	}

private:
	static constexpr string_view kName{"sqlite3"};
	static constexpr string_view kDirectoryName{"Sqlite3DatabaseBackend"};

	filesystem::path createDbFile() {
		const auto filePath = mDirectory.path() / "database.db";
		ofstream file{filePath};
		file.close();
		BC_HARD_ASSERT(filesystem::exists(filePath));
		return filePath;
	}

	TmpDir mDirectory;
	string mConnectionString;
};

class ConnectionPool {
public:
	ConnectionPool(string_view dbName, string_view connectString, const unsigned int poolSize = 1) : mPool(poolSize) {
		string backendName{dbName}, connectionString{connectString};
		for (unsigned int sessionId = 0; sessionId < poolSize; ++sessionId) {
			mPool.at(sessionId).open(backendName, connectionString);
		}
	}

	soci::connection_pool& getPool() {
		return mPool;
	};

private:
	soci::connection_pool mPool;
};

namespace {

template <typename Database>
class TestHelper {
public:
	explicit TestHelper(const unsigned int poolSize = 1)
	    : mDatabase(), mConnectionPool(mDatabase.getName(), mDatabase.getConnectionString(), poolSize) {
		SociHelper client{mConnectionPool.getPool()};
		client.execute([](soci::session& session) {
			session << "CREATE TABLE test (id int, value varchar(50));";
			session << "INSERT INTO test VALUES (0, 'test');";
		});
	}

	Database mDatabase;
	ConnectionPool mConnectionPool;
};

/**
 * Test successful SQL query execution.
 * @tparam Database type of database backend to use, must be one in: {MySqlDatabaseBackend, Sqlite3DatabaseBackend}
 */
template <class Database>
void successfulExecution() {
	string expectedResult{"test"};
	string currentResult{"unexpected"};

	TestHelper<Database> helper{};
	SociHelper client{helper.mConnectionPool.getPool()};

	client.execute(
	    [&currentResult](soci::session& session) { session << "SELECT value FROM test;", soci::into(currentResult); });

	BC_ASSERT_CPP_EQUAL(currentResult, expectedResult);
}

/**
 * Test that an exception is thrown when there is an error in the SQL query.
 * @tparam Database type of database backend to use, must be one in: {MySqlDatabaseBackend, Sqlite3DatabaseBackend}
 */
template <class Database>
void errorInSqlQuery() {
	string expectedResult{"expected"};
	string currentResult{"expected"};

	TestHelper<Database> helper{};
	SociHelper client{helper.mConnectionPool.getPool()};

	BC_ASSERT_THROWN(client.execute([&currentResult](soci::session& session) {
		session << "SELECT unknown FROM test;", soci::into(currentResult);
	}),
	                 DatabaseException)

	BC_ASSERT_CPP_EQUAL(currentResult, expectedResult);
}

namespace mysql {

/**
 * Test that an exception is thrown when the database becomes unavailable during execution.
 */
void databaseBecomesUnavailableDuringExecution() {
	string expectedResult{"expected"};
	string currentResult{"expected"};

	TestHelper<MySqlDatabaseBackend> helper{};
	SociHelper client{helper.mConnectionPool.getPool()};

	helper.mDatabase.stop();
	BC_ASSERT_THROWN(client.execute([&currentResult](soci::session& session) {
		session << "SELECT value FROM test;", soci::into(currentResult);
	}),
	                 DatabaseException)

	BC_ASSERT_CPP_EQUAL(currentResult, expectedResult);
}

/**
 * Test successful SQL query execution on "retryable" error.
 */
void retryableError() {
	bool restarted = false;
	string expectedResult{"test"};
	string currentResult{"unexpected"};

	TestHelper<MySqlDatabaseBackend> helper{};
	SociHelper client{helper.mConnectionPool.getPool()};

	client.execute([&database = helper.mDatabase, &currentResult, &restarted](soci::session& session) {
		if (!restarted) {
			database.restart();
			restarted = true;
		}
		session << "SELECT value FROM test;", soci::into(currentResult);
	});

	BC_ASSERT_CPP_EQUAL(currentResult, expectedResult);
}

} // namespace mysql

TestSuite _("SociHelper",
            {
                CLASSY_TEST(successfulExecution<MySqlDatabaseBackend>),
                CLASSY_TEST(successfulExecution<Sqlite3DatabaseBackend>),
                CLASSY_TEST(errorInSqlQuery<MySqlDatabaseBackend>),
                CLASSY_TEST(errorInSqlQuery<Sqlite3DatabaseBackend>),
                CLASSY_TEST(mysql::databaseBecomesUnavailableDuringExecution),
                CLASSY_TEST(mysql::retryableError),
            });

} // namespace
} // namespace flexisip::tester