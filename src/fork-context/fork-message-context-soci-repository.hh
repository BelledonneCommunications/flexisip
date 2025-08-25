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

#include <soci/connection-pool.h>

#include "fork-message-context.hh"

namespace flexisip {

/**
 * Singleton class used to gather all access to the database for ForkMessageContext instances.
 * Creating the singleton creates the connection to the database and creates/updates the schema if it doesn't already
 * exist.
 *
 * This class should not be cloneable or assignable.
 */
class ForkMessageContextSociRepository {
public:
	ForkMessageContextSociRepository(ForkMessageContextSociRepository& other) = delete;
	void operator=(const ForkMessageContextSociRepository&) = delete;

	~ForkMessageContextSociRepository();

	static const std::shared_ptr<ForkMessageContextSociRepository>& getInstance();

	static void prepareConfiguration(const std::string& backendString,
	                                 const std::string& connectionString,
	                                 unsigned int nbThreadsMax);

	ForkMessageContextDb findForkMessageByUuid(const std::string& uuid);

	/**
	 * Load minimal information about all ForkMessageContext instances to re-create proxy objects in "database state".
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

	soci::connection_pool mConnectionPool;
	std::vector<std::string> mUuidsToDelete{};
	std::mutex mMutex{};

	static std::string sBackendString;
	static std::string sConnectionString;
	static unsigned int sNbThreadsMax;
	static std::shared_ptr<ForkMessageContextSociRepository> singleton;
};

} // namespace flexisip