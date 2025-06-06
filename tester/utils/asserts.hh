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

#pragma once

#include <chrono>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include <cstdint>

#include "bctoolbox/tester.h"
#include "linphone++/linphone.hh"
#include "utils/test-patterns/test.hh"

namespace flexisip::tester {

struct AssertionResult {
	const char* const file;
	const int line;
	std::string reason;

	// Asserts that the assertion passed. Logs the error otherwise.
	bool assert_passed() const {
		return bc_assert(file, line, operator bool(), reason.c_str());
	}

	void hard_assert_passed() const {
		bc_hard_assert(file, line, operator bool(), reason.c_str());
	}

	operator bool() const { // Assertion is true if and only if there is no failure reason
		return reason.empty();
	}

	AssertionResult(const char* const file, const int line, const char* const reason)
	    : file(file), line(line), reason(reason == nullptr ? "" : reason) {
	}

	AssertionResult(const bool b) // Convert from bool for seemless integration with existing code
	    : file(__FILE__), line(__LINE__),
	      reason(b ? "" : "Context Missing. Please rewrite your test to use AssertionResult instead of bool.") {
	}
};

#define ASSERTION_FAILED(reason) AssertionResult(__FILE__, __LINE__, "ASSERTION_FAILED(" reason ")")
#define ASSERTION_PASSED() AssertionResult(__FILE__, __LINE__, nullptr)
#define ASSERTION_CONTINUE() AssertionResult(false)

#define FAIL_IF(assertion)                                                                                             \
	if (assertion) return AssertionResult(__FILE__, __LINE__, "FAIL_IF(" #assertion ")")

#define LOOP_ASSERTION(assertion)                                                                                      \
	AssertionResult(__FILE__, __LINE__, (assertion) ? nullptr : "LOOP_ASSERTION(" #assertion ")")

#define ASSERT_PASSED(assertionResult)                                                                                 \
	bc_assert(__FILE__, __LINE__, assertionResult.assert_passed(), "ASSERT_PASSED(" #assertionResult ")")

constexpr auto kDefaultSleepInterval = std::chrono::nanoseconds(std::chrono::milliseconds(10));
constexpr auto kNoSleep = std::chrono::nanoseconds(0);

template <const std::chrono::nanoseconds& sleepBetweenIterations = kDefaultSleepInterval>
class BcAssert {
public:
	BcAssert() = default;
	BcAssert(const std::initializer_list<std::function<void()>>& mIterateFuncs) : mIterateFuncs(mIterateFuncs) {
	}
	void addCustomIterate(const std::function<void()>& iterate) {
		mIterateFuncs.push_back(iterate);
	}
	template <typename Func>
	[[nodiscard]] AssertionResult waitUntil(const std::chrono::duration<double> timeout, Func&& condition) const {
		const auto timeLimit = std::chrono::steady_clock::now() + timeout;

		return loopAssert([&timeLimit] { return timeLimit < std::chrono::steady_clock::now(); },
		                  std::forward<Func>(condition));
	}

	template <typename Func>
	[[nodiscard]] AssertionResult wait(Func condition) {
		return waitUntil(std::chrono::seconds(2), condition);
	}

	template <typename Func>
	[[nodiscard]] AssertionResult iterateUpTo(const uint32_t iterations,
	                                          Func condition,
	                                          std::chrono::milliseconds minTime = std::chrono::milliseconds{1}) {
		auto remaining = iterations + 1;
		auto beforePlusMinTime = std::chrono::system_clock::now() + minTime;
		return loopAssert(
		    [&remaining, beforePlusMinTime] {
			    if (remaining != 0) --remaining;
			    return remaining == 0 && beforePlusMinTime < std::chrono::system_clock::now();
		    },
		    std::forward<Func>(condition));
	}

	template <typename AssertFunc, typename StopFunc>
	[[nodiscard]] AssertionResult loopAssert(StopFunc stopCondition, AssertFunc assertion) const {
		const auto before = std::chrono::system_clock::now();
		for (uint32_t iterations = 0;; ++iterations) {
			iterateAllOnce();

			AssertionResult result = assertion();
			if (result) return result;

			if (stopCondition()) {
				result.reason += "\n -> Still failing after " + std::to_string(iterations) + " iterations and " +
				                 std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
				                                    std::chrono::system_clock::now() - before)
				                                    .count()) +
				                 "ms";
				return result;
			}

			if constexpr (0 < sleepBetweenIterations.count()) {
				std::this_thread::sleep_for(sleepBetweenIterations);
			}
		}
	}

	/**
	 * Iterate for at least "iterations" number of iterations and at least "minTime" milliseconds.
	 * Then test the provided condition and return the result.
	 */
	template <typename Func>
	[[nodiscard]] AssertionResult
	forceIterateThenAssert(const uint32_t minIterations, std::chrono::milliseconds minTime, Func condition) {
		const auto before = std::chrono::system_clock::now();
		uint32_t iterations = 0;
		for (; (iterations < minIterations) || (before + minTime > std::chrono::system_clock::now()); ++iterations) {
			iterateAllOnce();
		}

		AssertionResult result = condition();
		if (!result) {
			result.reason += "\n -> Failed after " + std::to_string(iterations) + " iterations and " +
			                 std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
			                                    std::chrono::system_clock::now() - before)
			                                    .count()) +
			                 "ms";
		}
		return result;
	}

	void iterateAllOnce() const {
		for (const auto& iterate : mIterateFuncs) {
			iterate();
		}
	}

private:
	std::vector<std::function<void()>> mIterateFuncs;
};

} // namespace flexisip::tester