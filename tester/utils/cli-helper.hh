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

#include <cerrno>
#include <future>
#include <string>
#include <sys/un.h>
#include <sysexits.h>

#include "asserts.hh"
#include "flexisip-tester-config.hh"
#include "test-patterns/test.hh"

using namespace std;

namespace flexisip::tester {

constexpr auto kCliFilePath = FLEXISIP_TESTER_DATA_SRCDIR "/../scripts/flexisip_cli.py";

/**
 * Execute and test a command with cli.
 */
class CliHelper {
public:
	CliHelper() = default;
	~CliHelper() = default;

	static string callScript(const string& command, int expected_status, BcAssert<>& asserter) {
		const auto& pid = to_string(getpid());
		return callScriptForPid(command, expected_status, asserter, pid);
	}

	static string
	callScriptForPid(const string& command, int expected_status, BcAssert<>& asserter, const string& pid) {
		const auto& pyScript = kCliFilePath + " -p "s + pid + " --server proxy ";

		auto fut = async(launch::async, [command = pyScript + command, expected_status] {
			auto* handle = popen(command.c_str(), "r");
			BC_HARD_ASSERT(handle != nullptr);

			string output(0xFFFF, '\0');
			const auto& nread = fread(&output.front(), sizeof(decltype(output)::value_type), output.size(), handle);
			if (ferror(handle)) {
				BC_HARD_FAIL(("Error "s + strerror(errno) + " reading from subprocess' stdout").c_str());
			}

			auto exitStatus = pclose(handle);
			if (exitStatus < 0) {
				BC_HARD_FAIL(("Error "s + strerror(errno) + " closing process").c_str());
			}

			if (WIFEXITED(exitStatus)) exitStatus = WEXITSTATUS(exitStatus);
			output.resize(nread);
			if (exitStatus != expected_status) {
				BC_HARD_FAIL(("Expected command to return " + to_string(expected_status) + " but found " +
				              to_string(exitStatus) + ".\nCommand: " + command + "\nOutput: " + output)
				                 .c_str());
			}

			return output;
		});

		asserter.iterateUpTo(
		            33, [&fut] { return LOOP_ASSERTION(fut.wait_for(0s) == future_status::ready); }, 7s)
		    .hard_assert_passed();

		return fut.get();
	}
};

} // namespace flexisip::tester
