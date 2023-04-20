/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

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

namespace flexisip {
namespace tester {

MysqlServer::MysqlServer()
    : mDatadir(".mysql.db.d"), mDaemon([&datadir = mDatadir] {
	      auto datadirArg = "--datadir=" + datadir.path().string();
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
						              return move(pipe);
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
					          cerr << print_variant(out->read(0xFFFF));
				          if (auto* err = get_if<pipe::ReadOnly>(&state.mStderr))
					          cerr << print_variant(err->read(0xFFFF));
				          ::exit(state.mExitCode);
			          }
		          } else {
			          cerr << "Mysql setup process finished in unexpected state";
			          ::exit(EXIT_FAILURE);
		          }
	          },
	          move(setup).wait());

	      ::execl(MYSQL_SERVER_EXEC, MYSQL_SERVER_EXEC, "--no-defaults",
	              // Avoid port opening conflicts altogether. Everything will go through the unix socket
	              "--skip-networking",
	              // Do not check privileges (insecure). Required for old versions of mysql that do not support
	              // --auth-root-authentication-method=socket (CentOS 7, Debian 11, Ubuntu 18.04)
	              "--skip-grant-tables",
	              //
	              datadirArg.c_str(), ("--socket=" + datadir.path().string() + kSocketFile).c_str(), nullptr);
      }),
      mReady(async(launch::async, [&daemon = mDaemon] {
	      string fullLog{};
	      while (true) {
		      auto& state = daemon.state();
		      auto* running = get_if<process::Running>(&state);
		      if (!running) {
			      if (auto* exited = get_if<process::ExitedNormally>(&state)) {
				      if (auto* standardError = get_if<pipe::ReadOnly>(&exited->mStderr)) {
					      auto maybeChunk = standardError->read(0xFFFF);
					      if (auto* chunk = get_if<string>(&maybeChunk)) fullLog += *chunk;
				      }
			      }
			      throw runtime_error("Mysql server unexpectedly quit:\n" + fullLog);
		      }

		      auto* standardError = get_if<pipe::ReadOnly>(&running->mStderr);
		      if (!standardError) {
			      throw runtime_error("Mysql daemon stderr wired incorrectly");
		      }

		      auto chunk = visit(
		          [&fullLog](auto&& result) -> string {
			          using T = decay_t<decltype(result)>;
			          if constexpr (is_same_v<T, string>) return move(result);
			          else if constexpr (is_same_v<T, SysErr>)
				          throw system_error{result.number(), generic_category(),
				                             "Error reading from mysql daemon stderr. read: \n" + fullLog};
			          else
				          throw runtime_error("Timed out reading from mysql daemon stderr after " +
				                              to_string(result.duration.count()) + "us. read: \n" + fullLog);
		          },
		          standardError->read(0xFF));
		      if (chunk.find("ready for connections") != string::npos) {
			      SLOGD << chunk;
			      return;
		      }
		      fullLog += chunk;
	      }
      })) {
}

MysqlServer::~MysqlServer() {
	if (auto* running = get_if<process::Running>(&mDaemon.state())) {
		if (auto err = running->signal(SIGQUIT)) {
			SLOGE << "Failed to send quit signal to mysql process: " << *err;
		}
	}
	move(mDaemon).wait();
}

void MysqlServer::waitReady() {
	if (!mReady.valid()) return; // Already waited
	mReady.get();                // Propagates exceptions
}

string MysqlServer::connectionString() {
	return "unix_socket='" + mDatadir.path().string() + kSocketFile + "' db='" + kDbName + "'";
}

} // namespace tester
} // namespace flexisip
