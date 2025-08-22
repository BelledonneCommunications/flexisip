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

#include <string>

#include "soci/connection-pool.h"

#include "fork-message-context.hh"

namespace flexisip {

/**
 * Responsible for creating the database to save MESSAGE requests waiting for delivery (ForkMessageContextDb instances).
 * This tool also provides methods for performing CRUD operations on this database.
 */
class ForkMessageContextSociRepository {
public:
	ForkMessageContextSociRepository(const std::string& backendString,
	                                 const std::string& connectionString,
	                                 unsigned int poolSize);
	~ForkMessageContextSociRepository();

	ForkMessageContextSociRepository(ForkMessageContextSociRepository& other) = delete;
	void operator=(const ForkMessageContextSociRepository&) = delete;

	/**
	 * @brief Fetch all ForkMessageContextDb instances from the database.
	 *
	 * @note load minimal information to create ForkMessageContextDbProxy instances with IN_DATABASE state
	 */
	std::vector<ForkMessageContextDb> findAllForkMessage();
	/**
	 * @param uuid unique ForkMessageContextDb identifier
	 * @return the ForkMessageContextDb instance associated with the provided uuid in the database
	 */
	ForkMessageContextDb findForkMessageByUuid(const std::string& uuid);
	/**
	 * Save data of the provided ForkMessageContextDb into the database.
	 *
	 * @param dbFork instance to save into the database
	 * @return the uuid associated with the saved instance
	 */
	std::string saveForkMessageContext(const ForkMessageContextDb& dbFork);
	/**
	 * Update the content of a ForkMessageContextDb saved into the database.
	 *
	 * @param dbFork new data to insert into the database for the provided uuid
	 * @param uuid unique identifier target by this update
	 */
	void updateForkMessageContext(const ForkMessageContextDb& dbFork, const std::string& uuid);
	/**
	 * Remove a ForkMessageContextDb from the database associated with the provided uuid.
	 * @param uuid unique ForkMessageContextDb identifier to remove from the database
	 */
	void deleteByUuid(const std::string& uuid);

#ifdef ENABLE_UNIT_TESTS
	void deleteAll();
#endif

private:
	static void findAndPushBackKeys(const std::string& uuid, ForkMessageContextDb& dbFork, soci::session& sql);
	static void findAndPushBackBranches(const std::string& uuid, ForkMessageContextDb& dbFork, soci::session& sql);

	soci::connection_pool mConnectionPool;
	std::vector<std::string> mUuidsToDelete;
	std::mutex mMutex;
	std::string mLogPrefix;
};

} // namespace flexisip