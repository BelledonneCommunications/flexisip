/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <cstdlib>
#include <iostream>
#include <sstream>
#include <variant>

#include <type_traits>
#include <unistd.h>

#include "bctoolbox/tester.h"
#include "flexisip-tester-config.hh"
#include "utils/pipe.hh"
#include "utils/sys-err.hh"
#include "utils/test-suite.hh"
#include "utils/variant-utils.hh"

#include "utils/posix-process.hh"

using namespace std;

namespace flexisip {
namespace tester {

void smoke_test() {
	BC_ASSERT_TRUE(std::holds_alternative<process::ExitedNormally>(process::Process([] {}).wait()));
}

void test_echo_stdin_to_stdout() {
	process::Process test([] {
		if (::execl(CAT_EXEC, CAT_EXEC, nullptr) < 0) {
			cout << "*angry hissing* " << SysErr() << "\n";
			::exit(EXIT_FAILURE);
		}
	});

	auto* running = get_if<process::Running>(&test.state());
	BC_ASSERT_PTR_NOT_NULL(running);
	auto* in = get_if<pipe::WriteOnly>(&running->mStdin);
	BC_ASSERT_PTR_NOT_NULL(in);
	auto expected = "sudo make me a sandwich.";
	BC_ASSERT_FALSE(in->write(expected));
	running->mStdin = pipe::Closed();
	cerr << test << endl;

	auto finished = std::move(test).wait();
	auto* exitedNormally = get_if<process::ExitedNormally>(&finished);
	BC_ASSERT_PTR_NOT_NULL(exitedNormally);
	auto* out = get_if<pipe::ReadOnly>(&exitedNormally->mStdout);
	BC_ASSERT_PTR_NOT_NULL(out);
	auto maybeRead = out->read(0xFF);
	auto* read = get_if<string>(&maybeRead);
	BC_ASSERT_PTR_NOT_NULL(read);
	BC_ASSERT_STRING_EQUAL(read->c_str(), expected);
	if (read->empty()) {
		if (auto* pipe = get_if<pipe::ReadOnly>(&exitedNormally->mStderr)) {
			ostringstream err{};
			err << "stderr: " << StreamableVariant(pipe->read(0xFFF));
			bc_assert(__FILE__, __LINE__, false, err.str().c_str());
		}
	}
}

namespace {
TestSuite _("PosixProcess",
            {
                TEST_NO_TAG_AUTO_NAMED(smoke_test),
                TEST_NO_TAG_AUTO_NAMED(test_echo_stdin_to_stdout),
            });
} // namespace
} // namespace tester
} // namespace flexisip
