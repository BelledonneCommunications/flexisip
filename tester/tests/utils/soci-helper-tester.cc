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
#include "utils/server/mysql/mysql-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

using namespace std;

namespace flexisip::tester {

namespace {

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
	}

private:
	soci::connection_pool mPool;
};

class DatabaseBackend {
public:
	virtual ~DatabaseBackend() = default;

	virtual void restart() = 0;
	virtual void stop() = 0;
	virtual void clear() = 0;
	virtual string_view getName() const = 0;
	virtual string getConnectionString() const = 0;
};

template <typename DbBackend>
class TestHelper {
public:
	explicit TestHelper(const shared_ptr<DbBackend>& backend, const unsigned int poolSize = 1)
	    : mDbBackend(backend), mConnectionPool(mDbBackend->getName(), mDbBackend->getConnectionString(), poolSize) {
		SociHelper client{mConnectionPool.getPool()};
		client.execute([](soci::session& session) {
			session << "CREATE TABLE " << kTableName << " (id int, value varchar(50));";
			session << "INSERT INTO test VALUES (0, 'test');";
		});
	}

	static constexpr auto* kTableName{"test"};

	shared_ptr<DbBackend> mDbBackend;
	ConnectionPool mConnectionPool;
};

/**
 * Test successful SQL query execution.
 * @tparam DbBackend the type of database backend to use
 */
template <class DbBackend>
void successfulExecution(const shared_ptr<DbBackend>& backend) {
	string expectedResult{"test"};
	string currentResult{"unexpected"};

	TestHelper helper{backend};
	SociHelper client{helper.mConnectionPool.getPool()};

	client.execute(
	    [&currentResult](soci::session& session) { session << "SELECT value FROM test;", soci::into(currentResult); });

	BC_ASSERT_CPP_EQUAL(currentResult, expectedResult);
}

/**
 * Test that an exception is thrown when there is an error in the SQL query.
 * @tparam DbBackend the type of database backend to use
 */
template <class DbBackend>
void error(const shared_ptr<DbBackend>& backend) {
	string expectedResult{"expected"};
	string currentResult{"expected"};

	TestHelper helper{backend};
	SociHelper client{helper.mConnectionPool.getPool()};

	BC_ASSERT_THROWN(client.execute([&currentResult](soci::session& session) {
		session << "SELECT unknown FROM test;", soci::into(currentResult);
	}),
	                 DatabaseException)

	BC_ASSERT_CPP_EQUAL(currentResult, expectedResult);
}

namespace sqlite3 {

class Sqlite3DatabaseBackend : public DatabaseBackend {
public:
	Sqlite3DatabaseBackend() : mConnectionString(createDbFile().string()) {
	}

	void restart() override {
		stop();
		mDirectory = TmpDir{kDirectoryName.data()};
		mConnectionString = createDbFile().string();
	}

	void stop() override {
		filesystem::remove_all(mDirectory.path());
	}

	void clear() override {
		restart();
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

	filesystem::path createDbFile() const {
		const auto filePath = mDirectory.path() / "database.db";
		ofstream file{filePath};
		file.close();
		if (!filesystem::exists(filePath))
			throw runtime_error{"failed to create sqlite3 database file ("s + filePath.string() + ")"};
		return filePath;
	}

	TmpDir mDirectory{kDirectoryName.data()};
	string mConnectionString;
};

shared_ptr<Sqlite3DatabaseBackend> sBackend{};

void successfulQueryExecution() {
	successfulExecution(sBackend);
}

void errorInSqlQuery() {
	error(sBackend);
}

TestSuite _{
    "SociHelper::sqlite3",
    {
        CLASSY_TEST(successfulQueryExecution),
        CLASSY_TEST(errorInSqlQuery),
    },
    Hooks{}
        .beforeSuite([] {
	        sBackend = make_shared<Sqlite3DatabaseBackend>();
	        return 0;
        })
        .beforeEach([] { sBackend->clear(); })
        .afterSuite([] {
	        sBackend.reset();
	        return 0;
        }),
};

} // namespace sqlite3

namespace mysql {

class MySqlDatabaseBackend : public DatabaseBackend {
public:
	MySqlDatabaseBackend() {
		mServer->waitReady();
	}

	void restart() override {
		if (isStopped()) {
			mServer = make_unique<MysqlServer>();
			mServer->waitReady();
		} else {
			mServer->restart();
		}
	}

	void stop() override {
		mServer.reset();
	}

	void clear() override {
		mServer->clear();
	}

	bool isStopped() const {
		return !mServer;
	}

	string_view getName() const override {
		return kName;
	}

	string getConnectionString() const override {
		return mServer->connectionString();
	}

private:
	static constexpr string_view kName{"mysql"};

	unique_ptr<MysqlServer> mServer{make_unique<MysqlServer>()};
};

// Shared instance of mysql process across all tests in the suite.
shared_ptr<MySqlDatabaseBackend> backend{};

void successfulQueryExecution() {
	successfulExecution(backend);
}

void errorInSqlQuery() {
	error(backend);
}

/**
 * Test that an exception is thrown when the database becomes unavailable during execution.
 */
void databaseBecomesUnavailableDuringExecution() {
	string expectedResult{"expected"};
	string currentResult{"expected"};

	TestHelper helper{backend};
	SociHelper client{helper.mConnectionPool.getPool()};

	helper.mDbBackend->stop();
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
	try {
		bool restarted = false;
		string expectedResult{"test"};
		string currentResult{"unexpected"};

		TestHelper helper{backend};
		SociHelper client{helper.mConnectionPool.getPool()};

		client.execute([&currentResult, &restarted](soci::session& session) {
			if (!restarted) {
				backend->restart(); // Trigger a "retryable" error.
				restarted = true;
			}
			session << "SELECT value FROM test;", soci::into(currentResult);
		});

		BC_ASSERT_CPP_EQUAL(currentResult, expectedResult);
	} catch (runtime_error&) {
		BC_HARD_FAIL("Database could not be started");
	}
}

TestSuite _{
    "SociHelper::mysql",
    {
        CLASSY_TEST(successfulQueryExecution),
        CLASSY_TEST(errorInSqlQuery),
        CLASSY_TEST(databaseBecomesUnavailableDuringExecution),
        CLASSY_TEST(retryableError),
    },
    Hooks{}
        .beforeSuite([] {
	        backend = make_shared<MySqlDatabaseBackend>();
	        return 0;
        })
        .beforeEach([] {
	        if (backend->isStopped()) backend->restart();
	        backend->clear();
        })
        .afterSuite([] {
	        backend.reset();
	        return 0;
        }),
};

} // namespace mysql

} // namespace
} // namespace flexisip::tester