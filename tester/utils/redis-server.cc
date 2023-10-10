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
#include <exception>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <type_traits>
#include <variant>

#include <sys/wait.h>

#include "flexisip/logmanager.hh"

#include "redis-server.hh"
#include "tester.hh"
#include "utils/pipe.hh"
#include "utils/posix-process.hh"
#include "utils/variant-utils.hh"

using namespace std;
using namespace std::chrono;

namespace flexisip {
namespace tester {

uint16_t RedisServer::genPort() noexcept {
	static auto engine = tester::randomEngine();
	static std::uniform_int_distribution<uint16_t> dist(1024, numeric_limits<uint16_t>::max());

	return dist(engine);
}

process::Process RedisServer::spawn(uint16_t port) {
	return process::Process([port] {
		::execl(REDIS_SERVER_EXEC, REDIS_SERVER_EXEC,
		        // specify listen port
		        "--port", to_string(port).c_str(),
		        // disable snapshoting
		        "--save", "",
		        //
		        nullptr);
	});
}

RedisServer::RedisServer(std::uint16_t port) : mPort(port), mDaemon(spawn(mPort)) {
}

void RedisServer::stop() {
	if (auto* running = get_if<process::Running>(&mDaemon.state())) {
		if (auto err = running->signal(SIGTERM)) {
			SLOGE << "Failed to send term signal to redis process: " << *err;
		}
	}
	std::move(mDaemon).wait();
}

RedisServer::~RedisServer() {
	stop();
}

void RedisServer::restart() {
	stop();
	mReadyForConnections = false;
	mDaemon = spawn(mPort);
}

uint16_t RedisServer::port() {
	if (mReadyForConnections) {
		EXPECT_VARIANT(process::Running&).in(mDaemon.state());
		return mPort;
	}

	constexpr auto ntries = 3;
	const auto restart = [this]() {
		mPort = genPort();
		mDaemon = spawn(mPort);
	};
	for (auto i = 0; i < ntries; ++i) {
		auto& state = mDaemon.state();
		auto* running = get_if<process::Running>(&state);
		if (!running) {
			SLOGW << "Restarting Redis daemon found in unexpected state: " << StreamableVariant(std::move(state));
			restart();
			continue;
		}
		auto& standardOut = EXPECT_VARIANT(pipe::ReadOnly&).in(running->mStdout);
		string fullLog{};
		string previousChunk{};
		while (true) {
			auto chunk = [&standardOut, &fullLog] {
				try {
					return EXPECT_VARIANT(string).in(standardOut.read(0xFF));
				} catch (const exception& exc) {
					ostringstream msg{};
					msg << "Something went wrong reading Redis stdout: " << exc.what()
					    << ". Read so far ('|' indicates chunk boundaries): " << fullLog;
					throw runtime_error{msg.str()};
				}
			}();
			auto concatenated = previousChunk + chunk;
			if (concatenated.find("Failed listening on port") != string::npos) {
				SLOGW << "Redis: " << chunk;
				// Redis should exit on its own at this point, no need to kill it.
				restart();
				break;
			}
			if (concatenated.find("eady to accept connections") != string::npos) {
				SLOGI << "Redis: " << chunk;
				mReadyForConnections = true;
				return mPort;
			}
			fullLog += "|" + chunk;
			previousChunk = std::move(chunk);
		}
	}

	ostringstream err{};
	err << "'redis-server' failed to start " << ntries << " times. Aborting";
	throw runtime_error{err.str()};
}

} // namespace tester
} // namespace flexisip
