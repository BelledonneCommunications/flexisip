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

#pragma once

#include <string>

#include <soci/connection-pool.h>
#include <soci/mysql/soci-mysql.h>
#include <soci/session.h>
#include <soci/sqlite3/soci-sqlite3.h>

#include "flexisip/fork-context/fork-message-context.hh"

namespace flexisip {

class ForkMessageContextSociRepository {
public:
	/**
	 * ForkMessageContextSociRepository should not be cloneable.
	 */
	ForkMessageContextSociRepository(ForkMessageContextSociRepository& other) = delete;
	/**
	 * ForkMessageContextSociRepository should not be assignable.
	 */
	void operator=(const ForkMessageContextSociRepository&) = delete;

	static const std::unique_ptr<ForkMessageContextSociRepository>& getInstance();

	static void prepareConfiguration(const std::string& backendString,
	                                 const std::string& connectionString,
	                                 unsigned int nbThreadsMax) {
		sBackendString = backendString;
		sConnectionString = connectionString;
		sNbThreadsMax = nbThreadsMax;
	}

	ForkMessageContextDb findForkMessageByUuid(const std::string& uuid);

	std::vector<ForkMessageContextDb> findAllForkMessage();

	std::string saveForkMessageContext(const std::shared_ptr<ForkMessageContext>& forkMessageContext);

	void updateForkMessageContext(const std::shared_ptr<ForkMessageContext>& forkMessageContext,
	                              const std::string& uuid);

	void deleteByUuid(const std::string& uuid);

#ifdef ENABLE_UNIT_TESTS
	void deleteAll();
#endif

private:
	ForkMessageContextSociRepository(const std::string& backendString,
	                                 const std::string& connectionString,
	                                 unsigned int nbThreadsMax);

	void findAndPushBackKeys(const std::string& uuid, ForkMessageContextDb& dbFork, soci::session& sql) const;
	void findAndPushBackBranches(const std::string& uuid, ForkMessageContextDb& dbFork, soci::session& sql) const;

	soci::connection_pool mConnectionPool;

	static std::string sBackendString;
	static std::string sConnectionString;
	static unsigned int sNbThreadsMax;
	static std::unique_ptr<ForkMessageContextSociRepository> singleton;
};

} // namespace flexisip