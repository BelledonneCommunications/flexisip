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

#pragma once

#include <utility>
#include <vector>

#include "bctoolbox/tester.h"

namespace flexisip::tester {

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
	                                    .name = name,
	                                    .before_all = hooks.mBeforeAll,
	                                    .after_all = hooks.mAfterAll,
	                                    .before_each = hooks.mBeforeEach,
	                                    .after_each = hooks.mAfterEach,
	                                    .nb_tests = int(mTests.size()),
	                                    .tests = mTests.data(),
	                                } {
		bc_tester_add_suite(&mSuite);
	}

	const char* getName() const {
		return mSuite.name;
	}

	/**
	 * Add this suffix to disable the test suite. Tests can be compiled, but the suite will not be added to BCUnit, and
	 * never be run
	 */
	class Disabled {
	public:
		Disabled(const char*, std::vector<test_t>&&, const Hooks& = {}) {
		}
	};

private:
	std::vector<test_t> mTests;
	test_suite_t mSuite;
};

} // namespace flexisip::tester
