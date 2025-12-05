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

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <variant>

#include <unistd.h>

#include "flexisip/logmanager.hh"

#include "flexisip-tester-config.hh"
#include "utils/pipe.hh"
#include "utils/posix-process.hh"
#include "utils/sys-err.hh"
#include "utils/variant-utils.hh"

#include "mysql-server.hh"

using namespace std;
using namespace std::string_literals;

namespace flexisip::tester {

MysqlServer::MysqlServer()
    : mDatadir(".mysql.db.d"), mDaemon([this]() { startDaemon(); }),
      mReady(async(launch::async, [this]() { makeDaemonReady(); })) {
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

string MysqlServer::connectionString() const {
	return "unix_socket='" + mDatadir.path().string() + kSocketFile + "' db='" + kDbName + "'";
}

void MysqlServer::startDaemon() {
	auto datadirArg = "--datadir=" + mDatadir.path().string();
	process::Process setup([&datadirArg] {
		::execl(MYSQL_SERVER_EXEC, MYSQL_SERVER_EXEC,
		        // Some distros pack default install configurations (like default user), ignore that
		        "--no-defaults",
		        // Bypass mysql_install_db to speedup database setup
		        "--bootstrap",
		        // Skip InnoDB startup
		        "--innodb=OFF", "--default-storage-engine=MEMORY",
		        //
		        datadirArg.c_str(), nullptr);
	});

	{
		auto setupStdin = visit(
		    [](auto& state) -> pipe::WriteOnly {
			    if constexpr (is_same_v<decay_t<decltype(state)>, process::Running>) {
				    return visit(
				        [](auto&& pipe) -> pipe::WriteOnly {
					        if constexpr (is_same_v<decay_t<decltype(pipe)>, pipe::WriteOnly>) {
						        return std::move(pipe);
					        } else {
						        cerr << "Stdin pipe to mysql setup process in unexpected state: " << pipe << endl;
						        ::exit(EXIT_FAILURE);
						        throw runtime_error{"unreachable"};
					        }
				        },
				        exchange(state.mStdin, pipe::Closed()));
			    }

			    cerr << "Mysql setup process unexpectedly quit";
			    ::exit(EXIT_FAILURE);
			    throw runtime_error{"unreachable"};
		    },
		    setup.state());

		ostringstream sql{};
		sql << "CREATE DATABASE IF NOT EXISTS mysql;\n";
		sql << "USE mysql;\n";
		sql << ifstream(MYSQL_SYSTEM_TABLES_SETUP).rdbuf();
		sql << "CREATE DATABASE IF NOT EXISTS " << kDbName << ";\n";
		if (auto err = setupStdin.write(sql.str())) {
			cerr << "Failed to write to mysql setup process stdin: " << *err << endl;
			::exit(EXIT_FAILURE);
		}
	} // closing stdin

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

	::execl(MYSQL_SERVER_EXEC, MYSQL_SERVER_EXEC, "--no-defaults",
	        // Avoid port opening conflicts altogether. Everything will go through the unix socket
	        "--skip-networking",
	        // Do not check privileges (insecure). Required for old versions of mysql that do not support
	        // --auth-root-authentication-method=socket (CentOS 7, Debian 11, Ubuntu 18.04)
	        "--skip-grant-tables",
	        //
	        datadirArg.c_str(), ("--socket=" + mDatadir.path().string() + kSocketFile).c_str(), nullptr);
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
		    Match(standardError->readUntilDataReceptionOrTimeout(0xFF, 5s))
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
}

} // namespace flexisip::tester