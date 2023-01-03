/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <utility>
#include <vector>

#include "bctoolbox/tester.h"

namespace flexisip {
namespace tester {

// Setup and teardown hooks to be called before tests
class Hooks {
	friend class TestSuite;

public:
	Hooks& beforeSuite(pre_post_function_t f) {
		mBeforeAll = f;
		return *this;
	}
	Hooks& afterSuite(pre_post_function_t f) {
		mAfterAll = f;
		return *this;
	}
	Hooks& beforeEach(test_function_t f) {
		mBeforeEach = f;
		return *this;
	}
	Hooks& afterEach(test_function_t f) {
		mAfterEach = f;
		return *this;
	}

private:
	pre_post_function_t mBeforeAll = nullptr;
	pre_post_function_t mAfterAll = nullptr;
	test_function_t mBeforeEach = nullptr;
	test_function_t mAfterEach = nullptr;
};

/**
 * Instances of this class automatically register to BCUnit on construction and MUST have static lifetimes.
 * I.e. This class is intended to be instanced as a static variable in each test-file to streamline the registration of
 * tests.
 */
class TestSuite {
public:
	TestSuite(const char* name, std::vector<test_t>&& tests, const Hooks& hooks = {})
	    : mTests(std::move(tests)), mSuite{
	                                    name,               // Suite name
	                                    hooks.mBeforeAll,   // Before suite
	                                    hooks.mAfterAll,    // After suite
	                                    hooks.mBeforeEach,  // Before each test
	                                    hooks.mAfterEach,   // After each test
	                                    int(mTests.size()), // test array length
	                                    mTests.data()       // test array
	                                } {
		bc_tester_add_suite(&mSuite);
	}

	/**
	 * Add this suffix to disable the test suite. Tests can be compiled, but the suite will not be added to BCUnit, and
	 * never be run
	 */
	class Disabled {
	public:
		Disabled(const char* name, std::vector<test_t>&& tests, const Hooks& hooks = {}) {
		}
	};

private:
	std::vector<test_t> mTests;
	test_suite_t mSuite;
};

} // namespace tester
} // namespace flexisip
