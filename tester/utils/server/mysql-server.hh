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

#include <future>

#include "soci/connection-pool.h"
#include "soci/session.h"

#include "utils/posix-process.hh"
#include "utils/tmp-dir.hh"

namespace flexisip::tester {

/**
 * Spawns a local MySQL server daemon process and shuts it down on destruction.
 * The spawned server does not listen on the network and therefore cannot conflict with any other running instance. (Or
 * other instances of this class.)
 */
class MysqlServer {
public:
	MysqlServer();
	~MysqlServer();

	/**
	 * Blocks the current thread until the daemon reports it is ready to receive connections.
	 * Returns immediately if the daemon is already ready.
	 *
	 * @note can be called any number of times
	 */
	void waitReady() const;

	void restart();

	/**
	 * Drop all databases except 'mysql', 'information_schema' and 'performance_schema'.
	 */
	void clear();

	/**
	 * @return SOCI connection string to use to connect to this instance
	 */
	std::string connectionString() const;

private:
	constexpr static char kSocketFile[] = "/mysql.sock";
	constexpr static char kDbName[] = "default_test_database";

	void startDaemon();
	void makeDaemonReady();
	void stop();

	TmpDir mDatadir; // Mysql mandatory data directory, cleaned up if the tester didn't crash
	process::Process mDaemon;
	mutable std::future<void> mReady;
	soci::connection_pool mConnectionPool{1};
	std::optional<soci::session> mSession{std::nullopt};
};

} // namespace flexisip::tester