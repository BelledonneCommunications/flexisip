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

#include "flexisip-tester-config.hh"
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

process::Process RedisServer::spawn(const RedisServer::Params& params) {
	const auto& port = to_string(*params.port);
	auto argv = vector<const char*>{
	    REDIS_SERVER_EXEC,
	    // specify listen port
	    "--port", port.c_str(),
	    // disable snapshotting (persistence) to avoid polluting the test env with useless files, and avoid disk writes.
	    "--save", "",
	    // save 5s on replica sync (affects the master node)
	    "--repl-diskless-sync-delay", "0",
	    // avoid creating files on the replica
	    // TODO: uncomment when we drop support for redis <6.0 (rocky8)
	    //"--repl-diskless-load", "on-empty-db",
	    //
	};
	const auto& addSingleValueArg = [&argv](const auto& name, const auto& value) {
		if (!value.empty()) {
			argv.emplace_back(name);
			argv.emplace_back(value.data());
		}
	};
	addSingleValueArg("--requirepass", params.requirepass);
	addSingleValueArg("--masterauth", params.masterauth);
	if (!params.replicaof.host.empty()) {
		argv.emplace_back("--replicaof");
		argv.emplace_back(params.replicaof.host.data());
		argv.emplace_back(params.replicaof.port.data());
	}
	argv.emplace_back(nullptr);

	return process::Process([&argv] {
		::execv(REDIS_SERVER_EXEC,
		        // "argv[] [...] [is] completely constant"
		        // https://pubs.opengroup.org/onlinepubs/9699919799/functions/exec.html#tag_16_111_08
		        const_cast<char* const*>(argv.data()));
	});
}

RedisServer::RedisServer(RedisServer::Params&& params)
    : mParams{
          .port = params.port ? *params.port : genPort(),
          .requirepass = std::move(params.requirepass),
          .replicaof = std::move(params.replicaof),
          .masterauth = std::move(params.masterauth),
      },
      mDaemon(spawn(mParams)) {
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
	mDaemon = spawn(mParams);
}

uint16_t RedisServer::port() {
	if (mReadyForConnections) {
		EXPECT_VARIANT(process::Running&).in(mDaemon.state());
		return *mParams.port;
	}

	constexpr auto ntries = 3;
	for (auto i = 0; i < ntries; ++i) {
		string fullLog{};
		string previousChunk{};
		constexpr auto timeout = 1min;
		const auto deadline = chrono::system_clock::now() + timeout;
		do {
			auto& state = mDaemon.state();
			auto* running = get_if<process::Running>(&state);
			if (!running) {
				SLOGW << "Restarting Redis daemon found in unexpected state: " << StreamableVariant(std::move(state));
				break;
			}
			auto& standardOut = EXPECT_VARIANT(pipe::ReadOnly&).in(running->mStdout);
			const auto& chunk = [&standardOut, &fullLog] {
				try {
					return EXPECT_VARIANT(string).in(standardOut.read(0xFF));
				} catch (const exception& exc) {
					ostringstream msg{};
					msg << "Something went wrong reading Redis stdout: " << exc.what()
					    << ". Read so far ('|' indicates chunk boundaries): " << fullLog;
					throw runtime_error{msg.str()};
				}
			}();
			const auto& concatenated = previousChunk + chunk;
			if (concatenated.find("Failed listening on port") != string::npos) {
				SLOGW << "Redis: " << chunk;
				// Redis should exit on its own at this point, no need to kill it.
				break;
			}
			// This log message has been unchanged since Redis 4.0.0 and at least up to 7.2.5
			if (concatenated.find("Ready to accept connections") != string::npos) {
				SLOGI << "Redis: " << chunk;
				mReadyForConnections = true;
				return *mParams.port;
			}
			fullLog += "|" + chunk;
			previousChunk = std::move(chunk);
		} while (chrono::system_clock::now() < deadline);
		mParams.port = genPort();
		mDaemon = spawn(mParams);
	}

	ostringstream err{};
	err << "'redis-server' failed to start " << ntries << " times. Aborting";
	throw runtime_error{err.str()};
}

RedisServer RedisServer::createReplica() {
	return RedisServer({
	    .requirepass = mParams.requirepass,
	    .replicaof = {.host = "127.0.0.1", .port = to_string(port())},
	    .masterauth = mParams.requirepass,
	});
}

} // namespace tester
} // namespace flexisip
