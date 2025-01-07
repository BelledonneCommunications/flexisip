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

#include <chrono>

#include "soci/mysql/soci-mysql.h"
#include "soci/soci.h"

#include "flexisip/logmanager.hh"

#include "exceptions/database-exception.hh"

namespace flexisip {

/**
 * Tool to execute SQL queries in a reliable way, i.e. it will automatically reconnect the session if it has been
 * disconnected. Indeed, inactive connections are dropped by mariadb/mysqld after some time, so this happens quite
 * frequently on a system where there are few users.
 */
class SociHelper {
public:
	/**
	 * Instantiate from a connection pool.
	 */
	explicit SociHelper(soci::connection_pool& pool) : mPool(pool){};

	/**
	 * Safely execute an SQL query.
	 * Try to execute the query again (see SociHelper::kMaxTrials) if one of the following sql error occurs:
	 *   - code=4031: "The client was disconnected by the server because of inactivity"
	 *   - code=2014: "Commands out of sync; you can't run this command now"
	 *   - code=2006: "MySQL server has gone away"
	 *
	 * @param requestLambda code to execute the query
	 * @throw flexisip::DatabaseException in case of error during execution (session acquisition or query execution)
	 */
	void execute(const std::function<void(soci::session&)>& requestLambda);

private:
	static constexpr int kMaxTrials = 1;

	/**
	 * Try to close then reconnect the given session.
	 *
	 * @param session session to reconnect
	 * @throw flexisip::DatabaseException if an error occurred during close or reconnect operation
	 */
	void reconnectSession(soci::session& session);

	const std::string mLogPrefix = "SociHelper";
	soci::connection_pool& mPool;
};

} // namespace flexisip