/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include <cstdint>
#include <string>

#include "flexisip-tester-config.hh"
#include "utils/posix-process.hh"

namespace flexisip {
namespace tester {

/**
 * Helper class to easily spawn a fresh redis-server process.
 * The server process is spawned at construction and stopped at destruction.
 */
class RedisServer {
public:
	RedisServer();
	~RedisServer();

	/**
	 * Return the port Redis is listening on. Will block if Redis is not ready to accept connections until it finally
	 * is.. If the server couldn't be started — probably because the listening port is already used — it will be started
	 * again two more times by using other randomly generated listen ports. A runtime_error exception will be raised if
	 * the redis server has failed to start 3 times.
	 * @return The listen port of the spawned Redis server.
	 */
	std::uint16_t port();

private:
	static std::uint16_t genPort() noexcept;
	static process::Process spawn(std::uint16_t);

	std::uint16_t mPort;
	process::Process mDaemon;
	bool mReadyForConnections = false;
};

} // namespace tester
} // namespace flexisip
