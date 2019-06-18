/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2019  Belledonne Communications SARL, All rights reserved.

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

#include "soci/soci.h"
#include "soci/mysql/soci-mysql.h"

#include "flexisip/logmanager.hh"

#include <chrono>

namespace flexisip{

/*
 * This is a helper class to execute soci queries in a reliable way, ie
 * it will take care automatically to reconnect the session if it has been disconnected.
 * Indeed, inactive connections are dropped by mariadb/mysqld after some time, so this case
 * happens quite frequently on a system where there are few users.
 */
class SociHelper{
public:
	class DatabaseException : public std::runtime_error {
	public:
		DatabaseException() : std::runtime_error("Database failure") {}
	};

	// Initialize the SociHelper by giving the connection pool.
	SociHelper(soci::connection_pool &pool) : mPool(pool){};
	
	// Execute the database query safely. The code to execute the query shall be provided in the lambda argument.
	void execute(const std::function<void (soci::session &)> &requestLambda);

private:
	void reconnectSession(soci::session &session);
	unsigned long durationMs(std::chrono::steady_clock::time_point start, std::chrono::steady_clock::time_point stop){
		return (unsigned long) std::chrono::duration_cast<std::chrono::milliseconds>((stop) - (start)).count();
	}
	soci::connection_pool &mPool;
};

} //end of namespace

