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

	for (size_t i = 0; i != nbThreadsMax; ++i) {
		session& sql = mConnectionPool.at(i);
		sql.open(backendString, connectionString);
	}

	session sql(mConnectionPool);
	// Database creation, modified directly existing request only in case of emergency.
	// Only add request so the database can be created/updated from any version.
	sql << R"sql(CREATE TABLE IF NOT EXISTS fork_message_context (
	uuid BINARY(16) PRIMARY KEY,
	current_priority FLOAT NOT NULL,
	delivered_count INT NOT NULL,
	is_finished TINYINT NOT NULL,
	is_message TINYINT NOT NULL,
	expiration_date TIMESTAMP NOT NULL))sql";

	sql << R"sql(CREATE TABLE IF NOT EXISTS branch_info (
	fork_uuid BINARY(16) NOT NULL,
	contact_uid VARCHAR(255) NOT NULL,
	request BLOB NOT NULL,
	last_response BLOB,
	priority FLOAT NOT NULL,
	is_push_sent TINYINT NOT NULL,
	PRIMARY KEY (fork_uuid, contact_uid),
	FOREIGN KEY (fork_uuid) REFERENCES fork_message_context(uuid)))sql";

	sql << R"sql(CREATE TABLE IF NOT EXISTS fork_key (
	fork_uuid BINARY(16),
	key_value VARCHAR(255),
	PRIMARY KEY (fork_uuid, key_value),
	FOREIGN KEY (fork_uuid) REFERENCES fork_message_context(uuid)))sql";

	// See https://mariadb.com/kb/en/guiduuid-performance/ for more info about those two functions
	sql << R"sql(CREATE OR REPLACE FUNCTION UuidToBin(_uuid BINARY(36))
		RETURNS BINARY(16)
		LANGUAGE SQL  DETERMINISTIC  CONTAINS SQL  SQL SECURITY INVOKER
	RETURN
		UNHEX(CONCAT(
			SUBSTR(_uuid, 15, 4),
			SUBSTR(_uuid, 10, 4),
			SUBSTR(_uuid,  1, 8),
			SUBSTR(_uuid, 20, 4),
			SUBSTR(_uuid, 25) ));)sql";

	sql << R"sql(CREATE OR REPLACE FUNCTION UuidFromBin(_bin BINARY(16))
		RETURNS BINARY(36)
		LANGUAGE SQL  DETERMINISTIC  CONTAINS SQL  SQL SECURITY INVOKER
	RETURN
		LCASE(CONCAT_WS('-',
			HEX(SUBSTR(_bin,  5, 4)),
			HEX(SUBSTR(_bin,  3, 2)),
			HEX(SUBSTR(_bin,  1, 2)),
			HEX(SUBSTR(_bin,  9, 2)),
			HEX(SUBSTR(_bin, 11))));)sql";
}

ForkMessageContextDb ForkMessageContextSociRepository::findForkMessageByUuid(const string& uuid) {
	session sql(mConnectionPool);
	ForkMessageContextDb dbFork{};

	// fork_message_context
	sql << "select current_priority, delivered_count, is_finished, is_message, expiration_date from "
	       "fork_message_context where uuid = UuidToBin(:v)",
	    use(uuid), into(dbFork);

	// fork_key
	indicator ind;
	string dbKey;
	try {
		soci::statement st = (sql.prepare << "select key_value from fork_key where fork_uuid = UuidToBin(:v)",
		                      use(uuid), into(dbKey, ind));
		st.execute();
		while (st.fetch()) {
			switch (ind) {
				case soci::i_ok: {
					dbFork.dbKeys.push_back(dbKey);
					break;
				}
				default: {
					SLOGW << "Error retrieving data from fork_key table";
				}
			}
		}
	} catch (const exception& e) {
		SLOGW << "Error retrieving data from fork_key table" << e.what();
	}

	// branch_info
	BranchInfoDb dbBranch{};
	try {
		soci::statement st = (sql.prepare << "select * from branch_info where fork_uuid = UuidToBin(:v)", use(uuid),
		                      into(dbBranch, ind));
		st.execute();
		while (st.fetch()) {
			switch (ind) {
				case soci::i_ok: {
					dbFork.dbBranches.push_back(dbBranch);
					break;
				}
				default: {
					SLOGW << "Error retrieving data from branch_info table";
				}
			}
		}
	} catch (const exception& e) {
		SLOGW << "Error retrieving data from branch_info table" << e.what();
	}

	// TODO Sql error management

	return dbFork;
}

string
ForkMessageContextSociRepository::saveForkMessageContext(const shared_ptr<ForkMessageContext>& forkMessageContext) {
	auto dbFork = forkMessageContext->getDbObject();
	session sql(mConnectionPool);
	string insertedUuid{};

	sql << "SET @uuid=UUID()";
	sql << "insert into fork_message_context(uuid, current_priority, delivered_count, is_finished, is_message, "
	       "expiration_date) values(UuidToBin(@uuid), :current_priority, :delivered_count, :is_finished ,:is_message, "
	       ":expiration_date);",
	    use(dbFork);
	sql << "SET @uuid = IF(ROW_COUNT(), @uuid, null)";
	sql << "SELECT @uuid", into(insertedUuid);

	for (const auto& key : forkMessageContext->getKeys()) {
		sql << "insert into fork_key(fork_uuid, key_value) values(UuidToBin(:fork_uuid), :key_value)",
		    use(insertedUuid, "fork_uuid"), use(key, "key_value");
	}

	for (const auto& waitingBranch : forkMessageContext->getWaintingBranches()) {
		auto dbInfo = waitingBranch->getDbInfo();
		sql << "insert into branch_info(fork_uuid, contact_uid, request, last_response, priority, is_push_sent) values "
		       "(UuidToBin(:fork_uuid), :contact_uid, :request, :last_response, :priority, :is_push_sent)",
		    use(insertedUuid, "fork_uuid"), use(dbInfo);
	}

	// TODO Sql error management

	return insertedUuid;
}

void ForkMessageContextSociRepository::updateForkMessageContext(
    const std::shared_ptr<ForkMessageContext>& forkMessageContext, const std::string& uuid) {
	auto dbFork = forkMessageContext->getDbObject();
	session sql(mConnectionPool);

	sql << "update fork_message_context set current_priority = :current_priority, delivered_count = :delivered_count, "
	       "is_finished = "
	       ":is_finished, is_message = :is_message, expiration_date = :expiration_date where uuid = UuidToBin(:uuid)",
	    use(dbFork), use(uuid, "uuid");

	// Keys in table fork_key are not updated because they always remain the same.

	// TODO update branch
}
