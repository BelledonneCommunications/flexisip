/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include <signal.h> // For macOs
#include <sys/wait.h>

#include <flexisip/logmanager.hh>

#include "main/flexisip.hh"
#include "tester.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/variant-utils.hh"

using namespace std;

namespace flexisip::tester {

/**
 * Test the main function of flexisip server
 *
 * Start a flexisip server with all service types activated then check that all service are properly initialized.
 * Stop the server and check that the program exit cleanly.
 *
 */
void callAndStopMain() {
#ifdef ENABLE_CONFERENCE
	auto confFilePath = bcTesterRes("config/flexisip-main-all-services.conf");
#else
	auto confFilePath = bcTesterRes("config/flexisip-main-no-conference.conf");
#endif
	vector<const char*> args{
	    "flexisip",
	    "-c",
	    confFilePath.c_str(),
	};

	auto pipeReady = EXPECT_VARIANT(pipe::Ready).in(pipe::open());
	// Child process: Execute main and exit
	auto childPid = ::fork();
	if (childPid == 0) {
		// Child process: Execute main and exit

		// Protect with try/catch to ensure the process is ended with "_exit"
		// if not, it could destruct objects of the parent process.
		int returnValue = EXIT_FAILURE;
		try {
			returnValue = _main(args.size(), args.data(), ::move(pipeReady));
		} catch (const exception& e) {
			SLOGE << "Unexpected exception while running main: " << e.what();
		}

		::_exit(returnValue);
	}

	// Main process:
	// Check that flexisip started, stop it and check that it exited cleanly
	auto res = pipe::ReadOnly(::move(pipeReady)).readUntilDataReceptionOrTimeout(sizeof("ok"), 5s);
	if (holds_alternative<TimeOut>(res)) {
		// Flexisip not started or failed, kill it to be sure that no process is left running
		::kill(childPid, SIGKILL);
	}
	BC_ASSERT_CPP_EQUAL(EXPECT_VARIANT(string).in(res), "ok");

	// Short wait to ensure that main loop starts
	this_thread::sleep_for(0.5s);
	// Stop flexisip execution
	BC_HARD_ASSERT_CPP_EQUAL(::kill(childPid, SIGINT), 0);

	constexpr auto step = 100ms;

	int status;
	// Ensure clean exit from flexisip
	for (auto _ = 0ms; _ < 2s; _ += step) {
		auto pid = ::waitpid(childPid, &status, WNOHANG);
		if (pid > 0 && WIFEXITED(status)) {
			break;
		}
		this_thread::sleep_for(step);
	}

	BC_ASSERT_TRUE(WIFEXITED(status));
	if (!WIFEXITED(status)) {
		// Force the child to exit to avoid any leftover process
		::kill(childPid, SIGKILL);
	}
	BC_ASSERT_CPP_EQUAL(WEXITSTATUS(status), 0);
}

namespace {
TestSuite _("mainTester",
            {
                CLASSY_TEST(callAndStopMain),
            });
} // namespace
} // namespace flexisip::tester
