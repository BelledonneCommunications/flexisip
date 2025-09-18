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

#include <chrono>
#include <csignal>

#include "bctoolbox/tester.h"

#include "flexisip/signal-handling/sofia-driven-signal-handler.hh"
#include "flexisip/sofia-wrapper/su-root.hh"
#include "utils/test-suite.hh"

using namespace std::chrono_literals;

namespace flexisip {
namespace signal_handling {
namespace tester {

void test_sofia_driven_signal_handler() {
	sofiasip::SuRoot root{};
	SofiaDrivenSignalHandler shadowed(root.getCPtr(), std::vector<SigNum>{SIGCHLD}, []([[maybe_unused]] auto _signal) {
		BC_FAIL("Shadowed handler should never be called");
	});
	auto pid = getpid();

	{
#ifdef SIGRTMIN
		auto test0 = SIGRTMIN + 0;
		auto test1 = SIGRTMIN + 1;
		auto test2 = SIGRTMIN + 2;
		auto test3 = SIGRTMIN + 3;
		auto test4 = SIGRTMIN + 4;
#else
		auto test0 = SIGUSR1 + 0;
		auto test1 = SIGUSR1 + 1;
		auto test2 = SIGUSR1 + 2;
		auto test3 = SIGUSR1 + 3;
		auto test4 = SIGUSR1 + 4;
#endif
		SigNum received1;
		SofiaDrivenSignalHandler handler1(root.getCPtr(), std::vector<SigNum>{SIGCHLD, test0, test1, test2},
		                                  [&received1](auto signal) { received1 = signal; });
		SigNum received2;
		SofiaDrivenSignalHandler handler2(root.getCPtr(), std::vector<SigNum>{test2, test3, test4},
		                                  [&received2](auto signal) { received2 = signal; });

		kill(pid, SIGCHLD);
		root.step(1ms);
		BC_ASSERT_EQUAL(received1, SIGCHLD, SigNum, "%i");

		kill(pid, test0);
		kill(pid, test1);
		root.step(1ms);
		BC_ASSERT_EQUAL(received1, test0, SigNum, "%i");
		root.step(1ms);
		BC_ASSERT_EQUAL(received1, test1, SigNum, "%i");

		kill(pid, test4);
		kill(pid, test2);
		kill(pid, test3);
		root.step(1ms);
		BC_ASSERT_EQUAL(received2, test4, SigNum, "%i");
		root.step(1ms);
		BC_ASSERT_EQUAL(received2, test2, SigNum, "%i");
		BC_ASSERT_EQUAL(received1, test1, SigNum, "%i"); // unchanged
		root.step(1ms);
		BC_ASSERT_EQUAL(received2, test3, SigNum, "%i");
	}

	// A shadowed handler is permanently unregistered, even if the shadowing handler is destructed
	// SIGCHLD is ignored by default (no risk to kill ourself)
	kill(pid, SIGCHLD);
}

auto _ = [] {
	static test_t tests[] = {
	    TEST_NO_TAG_AUTO_NAMED(test_sofia_driven_signal_handler),
	};
	static test_suite_t suite{"SofiaDrivenSignalHandler",       NULL, NULL, NULL, NULL,
	                          sizeof(tests) / sizeof(tests[0]), tests};
	bc_tester_add_suite(&suite);
	return nullptr;
}();

} // namespace tester
} // namespace signal_handling
} // namespace flexisip
