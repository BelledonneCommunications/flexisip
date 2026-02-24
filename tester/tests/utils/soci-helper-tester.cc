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

#include "utils/soci-helper.hh"

#include <filesystem>
#include <fstream>

#include "flexisip/logmanager.hh"
#include "utils/server/mysql/mysql-server.hh"
#include "utils/soci/soci-tester-utils.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip::tester {

namespace {

const auto tableCreationRequest = [](soci::session& session) {
	session << "CREATE TABLE " << DatabaseBackend::kTableName << " (id int, value varchar(50));";
	session << "INSERT INTO " << DatabaseBackend::kTableName << " VALUES (0, 'test');";
};

/**
 * Test successful SQL query execution.
 * @tparam DbBackend the type of database backend to use
 */
template <class DbBackend>
void successfulExecution(const shared_ptr<DbBackend>& backend) {
	string expectedResult{"test"};
	string currentResult{"unexpected"};

	DbTestHelper<DbBackend> helper{backend, tableCreationRequest};
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

	DbTestHelper<DbBackend> helper{backend, tableCreationRequest};
	SociHelper client{helper.mConnectionPool.getPool()};

	BC_ASSERT_THROWN(client.execute([&currentResult](soci::session& session) {
		session << "SELECT unknown FROM test;", soci::into(currentResult);
	}),
	                 DatabaseException)

	BC_ASSERT_CPP_EQUAL(currentResult, expectedResult);
}

namespace sqlite3 {

shared_ptr<SqLite3Backend> sBackend{};

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
	        sBackend = make_shared<SqLite3Backend>();
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

// Shared instance of mysql process across all tests in the suite.
shared_ptr<MySqlBackend> sBackend{};

void successfulQueryExecution() {
	successfulExecution(sBackend);
}

void errorInSqlQuery() {
	error(sBackend);
}

/**
 * Test that an exception is thrown when the database becomes unavailable during execution.
 */
void databaseBecomesUnavailableDuringExecution() {
	string expectedResult{"expected"};
	string currentResult{"expected"};

	DbTestHelper helper{sBackend, tableCreationRequest};
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

		DbTestHelper helper{sBackend, tableCreationRequest};
		SociHelper client{helper.mConnectionPool.getPool()};

		client.execute([&currentResult, &restarted](soci::session& session) {
			if (!restarted) {
				sBackend->restart(); // Trigger a "retryable" error.
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
	        sBackend = make_shared<MySqlBackend>();
	        return 0;
        })
        .beforeEach([] {
	        if (sBackend->isStopped()) sBackend->restart();
	        sBackend->clear();
        })
        .afterSuite([] {
	        sBackend.reset();
	        return 0;
        }),
};

} // namespace mysql

} // namespace
} // namespace flexisip::tester