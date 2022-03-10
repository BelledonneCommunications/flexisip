/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include <cstdint>
#include <string>

#include "flexisip-tester-config.hh"

namespace flexisip {
namespace tester {

/**
 * Helper class to easily spawn a fresh redis-server process.
 * After construction, the server process can be spawned by calling start()
 * and stopped and destroyed by calling terminate().
 * The terminate() method is automatically if the process hasn't been terminated yet while
 * the RedisServer is being destroyed.
 */
class RedisServer {
public:
	RedisServer() = default;
	~RedisServer() {
		if (isStarted()) terminate();
	}

	// Disable object copy
	RedisServer(const RedisServer&) = delete;
	RedisServer& operator=(const RedisServer&) = delete;

	/**
	 * Spawn a redis-server process listening on a random port and wait for starting completion.
	 * If the server couldn't be started — probably because the listening port is already used — it will be
	 * started again two more times by using other randomly generated listen port.
	 * A runtime_error exception will be raised if the redis server have failed to start 3 times.
	 * @return The listen port of the spawned Redis server.
	 */
	std::uint16_t start();
	/**
	 * Send SIGTERM to the handled redis-server and wait for termination. If the server process isn't terminate
	 * after 2 seconds, then SIGKILL is send.
	 * The behavior is undefined if start() hasn't been called before.
	 */
	void terminate();
	/**
	 * Send SIGKILL to the handled redis-server. The behavior is undefined
	 * if start() hasn't been called before.
	 */
	void kill();
	/**
	 * Check whether a redis-server process has been spawned.
	 * @return true if the RedisServer actually handles a redis-server processus.
	 */
	bool isStarted() const noexcept {
		return mPid > 0;
	}

private:
	// Private methods
	bool spawn(std::uint16_t listenPort);

	// Private static methods
	static std::uint16_t getRandomPort() noexcept;
	static bool waitForTermination(pid_t pid, bool noHang = false);
	template <typename Duration> static bool waitForTermination(pid_t pid, Duration timeout);

	// Private attributes
	std::string mServerPath{REDIS_SERVER_EXEC};
	int mPid{-1};
};

} // namespace tester
} // namespace flexisip
