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

#include "squid-server.hh"

#include <chrono>
#include <csignal>
#include <exception>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <variant>

#include "flexisip/logmanager.hh"

#include "flexisip-tester-config.hh"
#include "random.hh"
#include "utils/pipe.hh"
#include "utils/posix-process.hh"
#include "utils/string-formatter.hh"
#include "utils/variant-utils.hh"

using namespace std;
using namespace std::chrono;

namespace flexisip::tester {
uint16_t SquidServer::genPort() noexcept {
	static auto rand = tester::random::random();
	return rand.integer<uint16_t>(1024, numeric_limits<uint16_t>::max()).generate();
}

process::Process SquidServer::spawn(const SquidServer::Params& params, const TmpDir& configDir) {
	const auto& port = to_string(*params.port);
	const auto& squidConfigFile = configDir.path() / "squid.conf";
	const StringFormatter squidConfigFmt{
	    R"squid(
		http_port #port#
		auth_param basic program #basic_ncsa_auth# #path#/squid_passwd
		auth_param basic realm "Squid Proxy"
		auth_param basic credentialsttl 2 hours
		auth_param basic casesensitive on
		acl authenticated proxy_auth REQUIRED
		acl SSL_ports port 443
		acl CONNECT method CONNECT
		http_access allow authenticated
		http_access allow CONNECT SSL_ports
		http_access deny all
		pid_filename none
		access_log none
    )squid",
	    '#',
	    '#',
	};
	ofstream{squidConfigFile} << squidConfigFmt.format({
	    {"port", port},
	    {"basic_ncsa_auth", BASIC_NCSA_AUTH_EXEC},
	    {"path", configDir.path()},
	});
	const auto& squidPasswdFile = configDir.path() / "squid_passwd";
	ofstream{squidPasswdFile} << "bc:$apr1$uT9Ww5mM$38.x6t3FaeZdcQvA25Y4k0";
	const auto& squidConfigFilepath = squidConfigFile.string();

	auto argv = vector<const char*>{
	    SQUID_EXEC,
	    // specify config file
	    "-f",
	    squidConfigFilepath.c_str(),
	    // run in foreground
	    "-N",
	};
	argv.emplace_back(nullptr);

	return process::Process([&argv] {
		::execv(SQUID_EXEC,
		        // "argv[] [...] [is] completely constant"
		        // https://pubs.opengroup.org/onlinepubs/9699919799/functions/exec.html#tag_16_111_08
		        const_cast<char* const*>(argv.data()));
	});
}

SquidServer::SquidServer(SquidServer::Params&& params)
    : mParams{.port = params.port ? *params.port : genPort()}, mConfigDir{"squid-"},
      mDaemon(spawn(mParams, mConfigDir)) {}

void SquidServer::stop() {
	if (auto* running = get_if<process::Running>(&mDaemon.state())) {
		if (auto err = running->signal(SIGKILL)) {
			LOGE << "Failed to send KILL signal to squid process: " << *err;
		}
	}
	std::move(mDaemon).wait();
}

SquidServer::~SquidServer() {
	stop();
}

void SquidServer::restart() {
	stop();
	mReadyForConnections = false;
	mDaemon = spawn(mParams, mConfigDir);
}

uint16_t SquidServer::port() {
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
				LOGW << "Restarting Squid daemon found in unexpected state: " << StreamableVariant(std::move(state));
				break;
			}
			auto& standardErr = EXPECT_VARIANT(pipe::ReadOnly&).in(running->mStderr);
			const auto& chunk = [&standardErr, &fullLog] {
				try {
					return EXPECT_VARIANT(string).in(standardErr.readUntilDataReceptionOrTimeout(0xFF));
				} catch (const exception& exc) {
					ostringstream msg{};
					msg << "Something went wrong reading Squid stdout: " << exc.what()
					    << ". Read so far ('|' indicates chunk boundaries): " << fullLog;
					throw runtime_error{msg.str()};
				}
			}();
			const auto& concatenated = previousChunk + chunk;
			if (concatenated.find("Address already in use") != string::npos) {
				LOGW << chunk;
				// Squid should exit on its own at this point, no need to kill it.
				break;
			}
			if (concatenated.find("Accepting HTTP Socket connections") != string::npos) {
				LOGI << chunk;
				mReadyForConnections = true;
				return *mParams.port;
			}
			fullLog += "|" + chunk;
			previousChunk = chunk;
		} while (chrono::system_clock::now() < deadline);
		mParams.port = genPort();
		mDaemon = spawn(mParams, mConfigDir);
	}

	ostringstream err{};
	err << "'squid-server' failed to start " << ntries << " times. Aborting";
	throw runtime_error{err.str()};
}

} // namespace flexisip::tester
