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

#include "mysql-server.hh"

#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <variant>

#include "soci/connection-pool.h"
#include "soci/rowset.h"
#include "soci/session.h"

#include "flexisip-tester-config.hh"
#include "flexisip/logmanager.hh"
#include "utils/pipe.hh"
#include "utils/posix-process.hh"
#include "utils/rand.hh"
#include "utils/string-utils.hh"
#include "utils/sys-err.hh"
#include "utils/variant-utils.hh"

using namespace std;
using namespace std::string_literals;

namespace flexisip::tester {

static constexpr string_view kGetAllDatabasesDropQuery{
    "SELECT GROUP_CONCAT(CONCAT('DROP DATABASE ', schema_name, ';') SEPARATOR ' ') "
    "FROM information_schema.schemata "
    "WHERE schema_name "
    "NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys');",
};

MysqlServer::MysqlServer()
    : mConfigurer{DbServerConfigurer::getConfigurer(*this)}, mDatadir(".mysql.db.d"),
      mDaemon([this]() { startDaemon(true); }), mReady(async(launch::async, [this]() { makeDaemonReady(); })) {
}

MysqlServer::~MysqlServer() {
	stop();
}

void MysqlServer::waitReady() const {
	if (!mReady.valid()) return; // Already waited
	mReady.get();                // Propagates exceptions
}

void MysqlServer::restart() {
	stop();
	mDaemon = process::Process{[this]() { startDaemon(); }};
	mReady = async(launch::async, [this]() { makeDaemonReady(); });
	waitReady();
}

void MysqlServer::clear() {
	waitReady();
	resetDatabase();
}

string MysqlServer::connectionString() const {
	return "unix_socket='" + mDatadir.path().string() + kSocketFile + "' db='" + kDbName + "'";
}

void MysqlServer::startDaemon(bool initialize) {
	const auto datadirArg = "--datadir=" + mDatadir.path().string();

	if (initialize) {
		auto setup = mConfigurer->initialSetup(datadirArg);

		visit(
		    [](auto&& state) {
			    using T = decay_t<decltype(state)>;
			    if constexpr (is_same_v<T, process::ExitedNormally>) {
				    if (state.mExitCode != 0) {
					    cerr << "Mysql datadir install failed";
					    if (auto* out = get_if<pipe::ReadOnly>(&state.mStdout))
						    cerr << StreamableVariant(out->readUntilDataReceptionOrTimeout(0xFFFF));
					    if (auto* err = get_if<pipe::ReadOnly>(&state.mStderr))
						    cerr << StreamableVariant(err->readUntilDataReceptionOrTimeout(0xFFFF));
					    ::exit(state.mExitCode);
				    }
			    } else {
				    cerr << "Mysql setup process finished in unexpected state";
				    ::exit(EXIT_FAILURE);
			    }
		    },
		    std::move(setup).wait());
	}

	std::vector<string> args = {
	    MYSQL_SERVER_EXEC,     "--no-defaults", "--skip-networking",
	    "--skip-grant-tables", datadirArg,      "--socket=" + mDatadir.path().string() + kSocketFile,
	};
	const auto extraArgs = mConfigurer->getExecArgs();
	args.insert(args.end(), extraArgs.begin(), extraArgs.end());

	std::vector<char*> cArgs;
	for (auto& arg : args) {
		cArgs.push_back(arg.data());
	}
	cArgs.push_back(nullptr);

	::execv(MYSQL_SERVER_EXEC, cArgs.data());
}

void MysqlServer::makeDaemonReady() {
	string fullLog{};
	string previousChunk{};
	std::uint16_t iterations{0};
	while (true) {
		auto& state = mDaemon.state();
		auto* running = get_if<process::Running>(&state);
		if (!running) {
			if (auto* exited = get_if<process::ExitedNormally>(&state)) {
				if (auto* standardError = get_if<pipe::ReadOnly>(&exited->mStderr)) {
					auto maybeChunk = standardError->readUntilDataReceptionOrTimeout(0xFFFF);
					if (auto* chunk = get_if<string>(&maybeChunk)) fullLog += *chunk;
				}
			}
			throw runtime_error("Mysql server unexpectedly quit:\n" + fullLog);
		}

		auto* standardError = get_if<pipe::ReadOnly>(&running->mStderr);
		if (!standardError) {
			throw runtime_error("Mysql daemon stderr wired incorrectly");
		}

		auto chunk =
		    Match(standardError->readUntilDataReceptionOrTimeout(0xFF, 10s))
		        .against([](string&& chunk) { return std::move(chunk); },
		                 [&fullLog](const SysErr& err) -> string {
			                 throw system_error{err.number(), generic_category(),
			                                    "Error reading from mysql daemon stderr. read: \n" + fullLog};
		                 },
		                 [&fullLog, &standardError, &daemon = mDaemon, &iterations](const TimeOut& timeout) -> string {
			                 std::ostringstream msg{};
			                 msg << "Timed out reading from mysql daemon stderr (" << *standardError << ") after "
			                     << iterations << " iterations, and " << timeout.duration.count() << "µs.";
			                 if (iterations < 5) {
				                 SLOGD << msg.str() << " Retrying...";
				                 return "";
			                 }
			                 msg << " read: \n" << fullLog << "\nprocess: " << std::move(daemon);
			                 throw runtime_error(msg.str());
		                 });
		auto concatenated = previousChunk + chunk;
		if (concatenated.find("ready for connections") != string::npos) {
			mConfigurer->onReady();
			SLOGD << chunk;
			return;
		}
		fullLog += "|" + chunk;
		previousChunk = std::move(chunk);
		++iterations;
	}
}

void MysqlServer::stop() {
	if (auto* running = get_if<process::Running>(&mDaemon.state())) {
		if (auto err = running->signal(SIGQUIT)) {
			SLOGE << "Failed to send quit signal to mysql process: " << *err;
		}
	}
	std::move(mDaemon).wait();
	mSession.reset();
	mConnectionPool.at(0).close();
}

void MysqlServer::createDatabaseIfNotExists() {
	if (!mSession.has_value()) {
		// Do not use connectionString() as the database might not have been created yet.
		mConnectionPool.at(0).open("mysql", "unix_socket='" + mDatadir.path().string() + kSocketFile + "'");
		mSession.emplace(mConnectionPool);
	}
	*mSession << "CREATE DATABASE IF NOT EXISTS " << kDbName << ";";
}

void MysqlServer::resetDatabase() {
	if (!mSession.has_value()) {
		// Do not use connectionString() as the database might not have been created yet.
		mConnectionPool.at(0).open("mysql", "unix_socket='" + mDatadir.path().string() + kSocketFile + "'");
		mSession.emplace(mConnectionPool);
	}
	auto& session = *mSession;
	string dropDatabasesQuery{};
	session << kGetAllDatabasesDropQuery, soci::into(dropDatabasesQuery);
	session << dropDatabasesQuery;
	createDatabaseIfNotExists();
}

} // namespace flexisip::tester