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

#include "fork-message-context.hh"
#include "soci/connection-pool.h"
#include "soci/sqlite3/soci-sqlite3.h"

namespace flexisip {

/**
 * @brief Gather all access to the database that stores ForkMessageContext instances.
 */
class ForkMessageContextSociRepository {
public:
	void operator=(const ForkMessageContextSociRepository&) = delete;
	ForkMessageContextSociRepository(ForkMessageContextSociRepository& other) = delete;

	static const std::unique_ptr<ForkMessageContextSociRepository>& getInstance();

	static void prepareConfiguration(const std::string& backendString,
	                                 const std::string& connectionString,
	                                 unsigned int nbThreadsMax);

	ForkMessageContextDb findForkMessageByUuid(const std::string& uuid);

	/**
	 * @brief Fetch all ForkMessageContextDb instances from the database.
	 *
	 * @note load minimal information to create ForkMessageContextDbProxy instances with IN_DATABASE state
	 * @warning the list must be ordered by expiration date
	 */
	std::vector<ForkMessageContextDb> findAllForkMessage();

	std::string saveForkMessageContext(const ForkMessageContextDb& dbFork);

	void updateForkMessageContext(const ForkMessageContextDb& dbFork, const std::string& uuid);

	void deleteByUuid(const std::string& uuid);

#ifdef ENABLE_UNIT_TESTS
	void deleteAll();
#endif

private:
	ForkMessageContextSociRepository(const std::string& backendString,
	                                 const std::string& connectionString,
	                                 unsigned int nbThreadsMax);

	static void findAndPushBackKeys(const std::string& uuid, ForkMessageContextDb& dbFork, soci::session& sql);
	static void findAndPushBackBranches(const std::string& uuid, ForkMessageContextDb& dbFork, soci::session& sql);

	static std::string sBackendString;
	static std::string sConnectionString;
	static unsigned int sNbThreadsMax;
	static std::unique_ptr<ForkMessageContextSociRepository> singleton;

	soci::connection_pool mConnectionPool;
	std::vector<std::string> mUuidsToDelete;
	std::mutex mMutex;
	std::string mLogPrefix;
};

} // namespace flexisip