/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "utils/posix-process.hh"
#include "utils/tmp-dir.hh"

namespace flexisip::tester {

/**
 * Helper class to easily spawn a fresh squid process.
 * The server process is spawned at construction and stopped at destruction.
 */
class SquidServer {
public:
	struct Params {
		std::optional<std::uint16_t> port;
	};

	explicit SquidServer(Params&& = {});
	~SquidServer();

	/**
	 * Will block if Squid is not ready to accept connections until it finally is...
	 * If the server couldn't be started — probably because the listening port is already used — it will be started
	 * again two more times by using other randomly generated listen ports. A runtime_error exception will be raised if
	 * the squid server has failed to start 3 times.
	 * @return The listen port of the spawned Squid server.
	 */
	std::uint16_t port();

	/**
	 * (Synchronously) stops then starts the server again on the same port.
	 */
	void restart();

private:
	static constexpr std::string_view mLogPrefix{"SquidServer"};

	static std::uint16_t genPort() noexcept;
	static process::Process spawn(const Params&, const TmpDir& configDir);

	/**
	 * Send a KILL signal and wait for termination.
	 */
	void stop();

	bool mReadyForConnections = false;
	Params mParams;
	TmpDir mConfigDir;
	process::Process mDaemon;
};

} // namespace flexisip::tester
