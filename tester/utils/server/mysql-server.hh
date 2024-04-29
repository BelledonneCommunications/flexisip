/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <future>

#include "utils/tmp-dir.hh"
#include "utils/posix-process.hh"

namespace flexisip {
namespace tester {

/**
 * Spawns a local MySQL server daemon process and shuts it down on destruction.
 * The spawned server does not listen on the network and therefore cannot conflict with any other running instance. (Or
 * other instances of this class.)
 */
class MysqlServer {
public:
	MysqlServer();
	~MysqlServer();

	// Blocks the current thread until the daemon reports it's ready for connections. Returns immediately if the daemon
	// is already ready. Can be called any number of times.
	void waitReady() const;

	// The SOCI connection string to use to connect to this instance.
	std::string connectionString() const;

private:
	constexpr static char kSocketFile[] = "/mysql.sock";
	constexpr static char kDbName[] = "flexisip_messages";
	TmpDir mDatadir; // Mysql mandatory data directory. Cleaned up if the tester didn't crash
	process::Process mDaemon;
	mutable std::future<void> mReady;
};

} // namespace tester
} // namespace flexisip
