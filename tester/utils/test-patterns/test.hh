/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <sstream>
#include <stdexcept>
#include <thread>
#include <type_traits>

#include <bctoolbox/tester.h>

namespace flexisip {
namespace tester {

class TestAssertFailedException : public std::exception {};

inline void bc_hard_assert(const char* file, int line, int predicate, const char* format) {
	bc_assert(file, line, predicate, format);
	if (!predicate) throw TestAssertFailedException{};
}

#define BC_HARD_ASSERT_TRUE(value) bc_hard_assert(__FILE__, __LINE__, (value), "BC_HARD_ASSERT_TRUE(" #value ")")
#define BC_HARD_ASSERT_FALSE(value) bc_hard_assert(__FILE__, __LINE__, !(value), "BC_HARD_ASSERT_FALSE(" #value ")")
#define BC_HARD_FAIL(msg) bc_hard_assert(__FILE__, __LINE__, 0, msg)

// Interface for all the classes which are to be executed as unit test.
// The test is executed by calling () operator.
class Test {
public:
	virtual ~Test() = default;

	// May throw TestAssetFailedException
	virtual void operator()() = 0;

protected:
	template <typename Duration>
	bool waitFor(const std::function<bool()>& breakCondition, Duration timeout) {
		using namespace std::chrono;
		for (auto now = steady_clock::now(), end = now + timeout; now < end; now = steady_clock::now()) {
			if (breakCondition()) return true;
			// Steps must not exceed 10ms in order the break condition be evaluated several times.
			auto stepTimeout = std::min(duration_cast<milliseconds>(end - now), 10ms);
			std::this_thread::sleep_for(stepTimeout);
		}
		return false;
	}
};

/**
 * This function allows BCUnit to easily call a Test-derived class.
 * The template instantiation fits the restrictions to be placed
 * in a BCUnit test suites array.
 * @param TestT The Test-derived class to execute.
 */
template <typename TestT>
void run() noexcept {
	try {
		TestT test{};
		test();
	} catch (const TestAssertFailedException&) {
	} catch (const std::runtime_error& e) {
		std::ostringstream msg{};
		msg << "runtime_error exception: " << e.what();
		bc_assert(__FILE__, __LINE__, 0, msg.str().c_str());
	}
};

} // namespace tester
} // namespace flexisip
