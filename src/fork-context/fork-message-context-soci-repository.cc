/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/fork-context/fork-message-context-soci-repository.hh"

using namespace flexisip;
using namespace std;
using namespace soci;

std::string ForkMessageContextSociRepository::sBackendString{};
std::string ForkMessageContextSociRepository::sConnectionString{};
unsigned int ForkMessageContextSociRepository::sNbThreadsMax = 1;
std::unique_ptr<ForkMessageContextSociRepository> ForkMessageContextSociRepository::singleton{};

const std::unique_ptr<ForkMessageContextSociRepository>& ForkMessageContextSociRepository::getInstance() {
	if (singleton) {
		return singleton;
	}

	singleton = std::unique_ptr<ForkMessageContextSociRepository>(
	    new ForkMessageContextSociRepository(sBackendString, sConnectionString, sNbThreadsMax));

	return singleton;
}

ForkMessageContextSociRepository::ForkMessageContextSociRepository(const string& backendString,
                                                                   const string& connectionString,
                                                                   unsigned int nbThreadsMax)
    : mConnectionPool{nbThreadsMax} {

	try {
		for (size_t i = 0; i != nbThreadsMax; ++i) {
			session& sql = mConnectionPool.at(i);
			sql.open(backendString, connectionString);
		}

		session sql(mConnectionPool);
		// Database creation, modify existing request only in case of emergency.
		// Only add request so the database can be created/updated from any version.
		sql << R"sql(CREATE TABLE IF NOT EXISTS fork_message_context (
		uuid BINARY(16) PRIMARY KEY,
		current_priority FLOAT NOT NULL,
		delivered_count INT NOT NULL,
		is_finished TINYINT NOT NULL,
		is_message TINYINT NOT NULL,
		expiration_date TIMESTAMP NOT NULL,
		request BLOB NOT NULL))sql";

		sql << R"sql(CREATE TABLE IF NOT EXISTS branch_info (
		fork_uuid BINARY(16) NOT NULL,
		contact_uid VARCHAR(255) NOT NULL,
		request BLOB NOT NULL,
		last_response BLOB,
		priority FLOAT NOT NULL,
		is_push_sent TINYINT NOT NULL,
		PRIMARY KEY (fork_uuid, contact_uid),
		FOREIGN KEY (fork_uuid) REFERENCES fork_message_context(uuid) ON DELETE CASCADE))sql";

		sql << R"sql(CREATE TABLE IF NOT EXISTS fork_key (
		fork_uuid BINARY(16),
		key_value VARCHAR(255),
		PRIMARY KEY (fork_uuid, key_value),
		FOREIGN KEY (fork_uuid) REFERENCES fork_message_context(uuid) ON DELETE CASCADE))sql";

		// See https://mariadb.com/kb/en/guiduuid-performance/ for more info about those two functions
		// We use "DROP FUNCTION IF EXISTS" because "CREATE OR REPLACE FUNCTION" isn't available in MariaDB 5.5 (centos
		// 7)
		sql << R"sql(DROP FUNCTION IF EXISTS UuidToBin;)sql";
		sql << R"sql(CREATE FUNCTION UuidToBin(_uuid BINARY(36))
			RETURNS BINARY(16)
			LANGUAGE SQL  DETERMINISTIC  CONTAINS SQL  SQL SECURITY INVOKER
		RETURN
			UNHEX(CONCAT(
				SUBSTR(_uuid, 15, 4),
				SUBSTR(_uuid, 10, 4),
				SUBSTR(_uuid,  1, 8),
				SUBSTR(_uuid, 20, 4),
				SUBSTR(_uuid, 25) ));)sql";

		sql << R"sql(DROP FUNCTION IF EXISTS UuidFromBin;)sql";
		sql << R"sql(CREATE FUNCTION UuidFromBin(_bin BINARY(16))
			RETURNS BINARY(36)
			LANGUAGE SQL  DETERMINISTIC  CONTAINS SQL  SQL SECURITY INVOKER
		RETURN
			LCASE(CONCAT_WS('-',
				HEX(SUBSTR(_bin,  5, 4)),
				HEX(SUBSTR(_bin,  3, 2)),
				HEX(SUBSTR(_bin,  1, 2)),
				HEX(SUBSTR(_bin,  9, 2)),
				HEX(SUBSTR(_bin, 11))));)sql";
	} catch (const runtime_error& e) {
		LOGF("ForkMessageContextSociRepository - A problem occurred during database creation. Fix it or disable "
		     "save-fork-late-message-in-db before restart. \nException : %s",
		     e.what());
	}
}

ForkMessageContextDb ForkMessageContextSociRepository::findForkMessageByUuid(const string& uuid) {
	session sql(mConnectionPool);
	ForkMessageContextDb dbFork{};

	// fork_message_context
	sql << "select current_priority, delivered_count, is_finished, is_message, expiration_date, request from "
	       "fork_message_context where uuid = UuidToBin(:v)",
	    use(uuid), into(dbFork);

	// fork_key
	findAndPushBackKeys(uuid, dbFork, sql);
	// branch_info
	findAndPushBackBranches(uuid, dbFork, sql);

	return dbFork;
}

string
ForkMessageContextSociRepository::saveForkMessageContext(const shared_ptr<ForkMessageContext>& forkMessageContext) {
	auto dbFork = forkMessageContext->getDbObject();
	session sql(mConnectionPool);
	string insertedUuid{};

	sql << "SET @uuid=UUID()";
	sql << "insert into fork_message_context(uuid, current_priority, delivered_count, is_finished, is_message, "
	       "expiration_date, request) values(UuidToBin(@uuid), :current_priority, :delivered_count, :is_finished "
	       ",:is_message, :expiration_date, :request);",
	    use(dbFork);
	sql << "SET @uuid = IF(ROW_COUNT(), @uuid, null)";
	sql << "SELECT @uuid", into(insertedUuid);

	for (const auto& key : dbFork.dbKeys) {
		sql << "insert into fork_key(fork_uuid, key_value) values(UuidToBin(:fork_uuid), :key_value)",
		    use(insertedUuid, "fork_uuid"), use(key, "key_value");
	}

	for (const auto& dbBranch : dbFork.dbBranches) {
		sql << "insert into branch_info(fork_uuid, contact_uid, request, last_response, priority, is_push_sent) values "
		       "(UuidToBin(:fork_uuid), :contact_uid, :request, :last_response, :priority, :is_push_sent)",
		    use(insertedUuid, "fork_uuid"), use(dbBranch);
	}

	return insertedUuid;
}

void ForkMessageContextSociRepository::updateForkMessageContext(
    const std::shared_ptr<ForkMessageContext>& forkMessageContext, const std::string& uuid) {
	auto dbFork = forkMessageContext->getDbObject();
	session sql(mConnectionPool);

	sql << "update fork_message_context set current_priority = :current_priority, delivered_count = :delivered_count, "
	       "is_finished = :is_finished, is_message = :is_message, expiration_date = :expiration_date, request = "
	       ":request where uuid = UuidToBin(:uuid)",
	    use(dbFork), use(uuid, "uuid");

	// Keys in table fork_key are not updated because they always remain the same.

	for (const auto& dbBranch : dbFork.dbBranches) {
		// Delete all branch before this could be considered because of test's cases scenario,
		// but in real life no branch is never removed (only replaced).
		sql << "insert into branch_info(fork_uuid, contact_uid, request, last_response, priority, is_push_sent) values "
		       "(UuidToBin(:fork_uuid), :contact_uid, :request, :last_response, :priority, :is_push_sent)"
		       "ON DUPLICATE KEY UPDATE contact_uid=:contact_uid, request=:request, last_response=:last_response, "
		       "priority=:priority, is_push_sent=:is_push_sent",
		    use(uuid, "fork_uuid"), use(dbBranch);
	}
}

std::vector<ForkMessageContextDb> ForkMessageContextSociRepository::findAllForkMessage() {
	session sql(mConnectionPool);
	vector<ForkMessageContextDb> allForkMessages;
	ForkMessageContextDb currentFork{};
	int isFinishedIntValue;
	int isMessageIntValue;

	soci::statement forkSt =
	    (sql.prepare << "select UuidFromBin(uuid), current_priority, delivered_count, is_finished, is_message, "
	                    "expiration_date, request from fork_message_context",
	     into(currentFork.uuid), into(currentFork.currentPriority), into(currentFork.deliveredCount),
	     into(isFinishedIntValue), into(isMessageIntValue), into(currentFork.expirationDate),
	     into(currentFork.request));
	forkSt.execute();
	while (forkSt.fetch()) {
		currentFork.isFinished = isFinishedIntValue;
		currentFork.isMessage = isMessageIntValue;
		findAndPushBackKeys(currentFork.uuid, currentFork, sql);
		findAndPushBackBranches(currentFork.uuid, currentFork, sql);
		allForkMessages.push_back(currentFork);
	}

	return allForkMessages;
}

void ForkMessageContextSociRepository::findAndPushBackKeys(const string& uuid,
                                                           ForkMessageContextDb& dbFork,
                                                           session& sql) const {
	string dbKey;
	dbFork.dbKeys.clear();

	statement st =
	    (sql.prepare << "select key_value from fork_key where fork_uuid = UuidToBin(:v)", use(uuid), into(dbKey));
	st.execute();
	while (st.fetch()) {
		dbFork.dbKeys.push_back(dbKey);
	}
}

void ForkMessageContextSociRepository::findAndPushBackBranches(const std::string& uuid,
                                                               ForkMessageContextDb& dbFork,
                                                               soci::session& sql) const { // branch_info
	BranchInfoDb dbBranch;
	dbFork.dbBranches.clear();

	statement st = (sql.prepare << "select contact_uid, request, last_response, priority, is_push_sent from "
	                               "branch_info where fork_uuid = UuidToBin(:v)",
	                use(uuid), into(dbBranch));
	st.execute();
	while (st.fetch()) {
		dbFork.dbBranches.push_back(dbBranch);
	}
}

void ForkMessageContextSociRepository::deleteByUuid(const string& uuid) {
	session sql(mConnectionPool);

	sql << "delete from fork_message_context where uuid=UuidToBin(:v)", use(uuid);
}

#ifdef ENABLE_UNIT_TESTS
void ForkMessageContextSociRepository::deleteAll() {
	session sql(mConnectionPool);

	sql << "delete from fork_message_context";
}
#endif