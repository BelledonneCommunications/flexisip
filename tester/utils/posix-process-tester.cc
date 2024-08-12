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
	auto maybeRead = out->readUntilDataReceptionOrTimeout(0xFF);
	auto* read = get_if<string>(&maybeRead);
	BC_ASSERT_PTR_NOT_NULL(read);
	BC_ASSERT_STRING_EQUAL(read->c_str(), expected);
	if (read->empty()) {
		if (auto* pipe = get_if<pipe::ReadOnly>(&exitedNormally->mStderr)) {
			ostringstream err{};
			err << "stderr: " << StreamableVariant(pipe->readUntilDataReceptionOrTimeout(0xFFF));
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
