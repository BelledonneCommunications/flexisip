/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <chrono>

#include "bctoolbox/tester.h"

#include "flexisip/signal-handling/sofia-driven-signal-handler.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

#include "tester.hh"

using namespace std::chrono_literals;

namespace flexisip {
namespace signal_handling {
namespace tester {

void test_sofia_driven_signal_handler() {
	sofiasip::SuRoot root{};
	SofiaDrivenSignalHandler shadowed(root.getCPtr(), std::vector<SigNum>{SIGCHLD},
	                                  [](auto _signal) { BC_FAIL("Shadowed handler should never be called"); });
	auto pid = getpid();

	{
		auto test0 = SIGRTMIN + 0;
		auto test1 = SIGRTMIN + 1;
		auto test2 = SIGRTMIN + 2;
		auto test3 = SIGRTMIN + 3;
		auto test4 = SIGRTMIN + 4;
		SigNum received1;
		SofiaDrivenSignalHandler handler1(root.getCPtr(), std::vector<SigNum>{SIGCHLD, test0, test1, test2},
		                                 [&received1](auto signal) {
			                                 received1 = signal;
		                                 });
		SigNum received2;
		SofiaDrivenSignalHandler handler2(root.getCPtr(), std::vector<SigNum>{test2, test3, test4},
		                                 [&received2](auto signal) {
			                                 received2 = signal;
		                                 });

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
