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

#include <chrono>
#include <csignal>
#include <cstdint>
#include <iostream>
#include <system_error>
#include <thread>

#include <sys/wait.h>

#include "flexisip/logmanager.hh"

#include "redis-server.hh"

using namespace std;
using namespace std::chrono;

namespace flexisip {
namespace tester {

std::uint16_t RedisServer::start() {
	constexpr auto ntries = 3;
	for (auto i = 0; i < ntries; ++i) {
		auto listenPort = getRandomPort();
		if (spawn(listenPort)) return listenPort;
	}
	ostringstream err{};
	err << "'redis-server' failed to start " << ntries << " times. Aborting";
	throw runtime_error{err.str()};
}

void RedisServer::terminate() {
	::kill(mPid, SIGTERM);
	if (waitForTermination(mPid, 2s)) {
		SLOGD << "'redis-server' terminated";
		mPid = -1;
	} else {
		SLOGD << "'redis-server' terminate timeout";
		kill();
	}
}

void RedisServer::kill() {
	::kill(mPid, SIGKILL);
	waitForTermination(mPid);
	SLOGD << "'redis-server' killed";
	mPid = -1;
}

bool RedisServer::spawn(std::uint16_t listenPort) {
	SLOGD << "Starting 'redis-server' on port " << listenPort;

	// Create a child processus by forking and execute 'redis-server'
	mPid = fork();
	if (mPid < 0) {
		throw system_error{errno, generic_category(), "fork()"};
	}
	if (mPid == 0) {
		execl(mServerPath.c_str(), mServerPath.c_str(), "--port",
		      to_string(listenPort).c_str(), /* specify listen port */
		      "--save", "",                  /* disable snapshoting */
		      nullptr);
		throw system_error{errno, generic_category(), "execl()"};
	}

	SLOGD << "Executing 'redis-server' in process " << mPid;

	// Wait one secound to be sure that Redis is ready
	this_thread::sleep_for(1s);

	// Check whether 'redis-server' has aborted while starting
	if (waitForTermination(mPid, true)) {
		SLOGE << "'redis-server' has unexpectedly been terminated on starting";
		return false;
	}

	// 'redis-server' is assumed as successfully started if it hasn't been terminated at this point.
	SLOGD << "'redis-server' successfully started";
	return true;
}

std::uint16_t RedisServer::getRandomPort() noexcept {
	std::srand(std::time(nullptr));
	return rand() % (numeric_limits<uint16_t>::max() - 1024) + 1024;
}

bool RedisServer::waitForTermination(pid_t pid, bool noHang) {
	auto wpid = waitpid(pid, nullptr, noHang ? WNOHANG : 0);
	if (wpid < 0 && errno != EAGAIN) {
		throw system_error{errno, generic_category(), "waitpid()"};
	}
	return wpid > 0;
}

template <typename Duration> bool RedisServer::waitForTermination(pid_t pid, Duration timeout) {
	auto now = steady_clock::now();
	const auto endTime = now + timeout;
	for (; now < endTime; now = steady_clock::now()) {
		if (waitForTermination(pid, true)) return true;
		this_thread::sleep_for(10ms);
	}
	return false;
}

} // namespace tester
} // namespace flexisip
