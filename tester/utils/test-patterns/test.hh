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

#include <functional>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <type_traits>

#include <bctoolbox/tester.h>

namespace flexisip {
namespace tester {

class TestAssertFailedException : public std::exception {
public:
	const char* what() const noexcept override {
		return "Test assertion failed";
	}
};

/**
 * Base function for BC_HARD_ASSERT_* macro.
 * These macros throw an TestAssertFailedException in addition of marking the test as failed when
 * predicate is false.
 */
inline void bc_hard_assert(const char* file, int line, int predicate, const char* format) {
	bc_assert(file, line, predicate, format);
	if (!predicate) throw TestAssertFailedException{};
}

/**
 * Basic hard assert: mark the test as failed if the given expression is false.
 */
#define BC_HARD_ASSERT(expression) bc_hard_assert(__FILE__, __LINE__, (expression), "BC_HARD_ASSERT(" #expression ")")
/**
 * Same as BC_HARD_ASSERT().
 */
#define BC_HARD_ASSERT_TRUE(expression)                                                                                \
	bc_hard_assert(__FILE__, __LINE__, (expression), "BC_HARD_ASSERT_TRUE(" #expression ")")
/**
 * Mark the test as failed if the given expression is true.
 */
#define BC_HARD_ASSERT_FALSE(expression)                                                                               \
	bc_hard_assert(__FILE__, __LINE__, !(expression), "BC_HARD_ASSERT_FALSE(" #expression ")")
/**
 * Mark the test as failed if the given expression is null.
 */
#define BC_HARD_ASSERT_NOT_NULL(expression)                                                                            \
	bc_hard_assert(__FILE__, __LINE__, (expression != nullptr), "BC_HARD_ASSERT_NOT_NULL(" #expression ")")
/**
 * Make the test fails systematically with a custom message.
 */
#define BC_HARD_FAIL(msg) bc_hard_assert(__FILE__, __LINE__, 0, msg)

/**
 * Base macro for BC_ASSERT_CPP_EQUAL() and BC_HARD_ASSERT_CPP_EQUAL().
 */
#define BC_ASSERT_CPP_EQUAL_BASE(assertFunction, value, expected)                                                      \
	do {                                                                                                               \
		std::ostringstream os{};                                                                                       \
		os << "BC_ASSERT_CPP_EQUAL(" #value ", " #expected "), value: \"" << (value) << "\", expected: \""             \
		   << (expected) << "\"";                                                                                      \
		assertFunction(__FILE__, __LINE__, value == expected, os.str().c_str());                                       \
	} while (0)
/**
 * Assert the equality of two expressions whatever their types. The '==' and '<<' operators must be declared for
 * the type of the two operands.
 */
#define BC_ASSERT_CPP_EQUAL(value, expected) BC_ASSERT_CPP_EQUAL_BASE(bc_assert, value, expected)
/**
 * Same as BC_ASSERT_CPP_EQUAL() but send an exception in addition of marking the test as failed.
 */
#define BC_HARD_ASSERT_CPP_EQUAL(value, expected) BC_ASSERT_CPP_EQUAL_BASE(bc_hard_assert, value, expected)
/**
 * Assert the equality of two enums by casting them to int.
 */
#define BC_ASSERT_ENUM_EQUAL(value, expected) BC_ASSERT_CPP_EQUAL(int(value), int(expected))

/**
 * Base macro for BC_ASSERT_CPP_NOT_EQUAL() and BC_HARD_ASSERT_CPP_NOT_EQUAL().
 */
#define BC_ASSERT_CPP_NOT_EQUAL_BASE(assertFunction, value, expected)                                                  \
	do {                                                                                                               \
		std::ostringstream os{};                                                                                       \
		os << "BC_ASSERT_CPP_NOT_EQUAL(" #value ", " #expected "), value: " << (value)                                 \
		   << ", expected: " << (expected);                                                                            \
		assertFunction(__FILE__, __LINE__, value != expected, os.str().c_str());                                       \
	} while (0)
/**
 * Same as BC_ASSERT_CPP_EQUAL() but test that the two expressions aren't equal.
 */
#define BC_ASSERT_CPP_NOT_EQUAL(value, expected) BC_ASSERT_CPP_NOT_EQUAL_BASE(bc_assert, value, expected)
/**
 * Same as BC_ASSERT_CPP_NOT_EQUAL() but send an exception in addition of marking the test as failed.
 */
#define BC_HARD_ASSERT_CPP_NOT_EQUAL(value, expected) BC_ASSERT_CPP_NOT_EQUAL_BASE(bc_hard_assert, value, expected)

/*
 * Check that expression has thrown an exception and that exception type is as expected.
 */
#define BC_ASSERT_THROWN(expression, expectedType)                                                                     \
	{                                                                                                                  \
		bool exceptionWasThrown = false;                                                                               \
		try {                                                                                                          \
			expression;                                                                                                \
		} catch (const expectedType& exception) {                                                                      \
			exceptionWasThrown = true;                                                                                 \
			if (typeid(exception) == typeid(expectedType)) {                                                           \
				BC_PASS("");                                                                                           \
			} else {                                                                                                   \
				bc_assert(__FILE__, __LINE__, 0,                                                                       \
				          ("thrown exception has wrong type, " + std::string(typeid(exception).name()) +               \
				           " != " + std::string(typeid(expectedType).name()))                                          \
				              .c_str());                                                                               \
			}                                                                                                          \
		} catch (...) {                                                                                                \
			exceptionWasThrown = true;                                                                                 \
			bc_assert(                                                                                                 \
			    __FILE__, __LINE__, 0,                                                                                 \
			    ("thrown exception has wrong type, " + std::string(typeid(expectedType).name()) + " was expected")     \
			        .c_str());                                                                                         \
		}                                                                                                              \
		if (!exceptionWasThrown) {                                                                                     \
			bc_assert(                                                                                                 \
			    __FILE__, __LINE__, 0,                                                                                 \
			    ("expected " + std::string(typeid(expectedType).name()) + " but no exception was thrown").c_str());    \
		}                                                                                                              \
	}

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
 * Wraps the test function in a try {} catch {} to enable BC_HARD_ASSERTs and graceful exception handling
 * @param TestFunction The plain test function to wrap
 */
template <void TestFunction()>
static void run() noexcept {
	try {
		TestFunction();
	} catch (const TestAssertFailedException&) {
	} catch (const std::exception& e) {
		std::ostringstream msg{};
		msg << "unexpected exception: " << e.what();
		bc_assert(__FILE__, __LINE__, 0, msg.str().c_str());
	}
};

template <typename TestT>
static void instanciateAndCall() {
	TestT test{};
	test();
}

/**
 * This function allows BCUnit to easily call a Test-derived class.
 * The template instantiation fits the restrictions to be placed
 * in a BCUnit test suites array.
 * @param TestT The Test-derived class to execute.
 */
template <typename TestT>
static void run() noexcept {
	run<instanciateAndCall<TestT>>();
};

#define CLASSY_TEST(test_class) TEST_NO_TAG(#test_class, run<test_class>)

} // namespace tester
} // namespace flexisip
